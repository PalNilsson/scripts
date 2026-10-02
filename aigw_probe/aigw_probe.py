#!/usr/bin/env python3
"""Smoke-test a CERN-hosted, LiteLLM-proxied OpenAI-compatible model.

The script runs up to four independent checks against the proxy so that a
failure localises itself instead of surfacing as a single opaque HTTP error:

1. ``models``    -- list the models the API key can see (catches wrong base
   URL and wrong key before any token is spent).
2. ``key``       -- report the key's team and granted models via ``/key/info``,
   which distinguishes an unscoped key from a wrong model alias.
3. ``chat``      -- a single non-streaming chat completion, printing both the
   visible answer and any separate reasoning channel.
4. ``stream``    -- the same prompt with ``stream=True`` to verify incremental
   delivery through the proxy.
5. ``tools``     -- a two-turn function-calling round trip, verifying that the
   model emits a ``tool_call`` and can consume the tool result.
6. ``context``   -- probes the usable context window with oversized filler,
   since a deployment's advertised limit can disagree with what the upstream
   server accepts.
7. ``embed``     -- requests embeddings and reports vector dimensionality.
   Excluded from ``all``, because embedding models reject chat requests and
   chat models reject embedding requests; run it explicitly against an
   embedding model.

``--model`` accepts a comma-separated list, in which case every model-specific
check runs once per candidate under identical settings, and the summary is
keyed by model. This is the intended way to choose between candidates.

Notes:
    The ``api_base`` shown in a LiteLLM model's *LiteLLM Params* block is the
    upstream inference server, not the endpoint a virtual key may call. The
    endpoint to call is the LiteLLM proxy itself -- the host serving the admin
    UI -- suffixed with ``/v1``, which for the CERN AI gateway is
    ``https://aigw.cern.ch/v1`` and is the built-in default.

    A LiteLLM virtual key carries its own team scoping server-side, so the team
    ID is deliberately not sent in the request body.

Example:
    ::

        export CERN_LLM_API_KEY='sk-...'
        export CERN_LLM_MODEL='<model ID>'

        python aigw_probe.py --check models
        python aigw_probe.py --check chat --reasoning-effort low
        python aigw_probe.py --check all

Requires:
    ``python -m pip install openai``. The ``key`` check additionally needs
    ``httpx``, normally present as an ``openai`` dependency; without it that
    one check is skipped and the rest still run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, replace
from typing import Any, Final, Sequence

try:
    import openai
    from openai import OpenAI
except ImportError as _error:  # pragma: no cover - environment guard
    sys.exit(
        f"Cannot import required module '{_error.name}' "
        f"(while importing 'openai').\n"
        f"  interpreter: {sys.executable}\n"
        f"  install it into THAT interpreter with:\n"
        f"      {sys.executable} -m pip install openai\n"
        f"  A bare 'pip install' may target a different environment."
    )

try:
    import httpx
except ImportError:  # pragma: no cover - optional dependency
    try:
        # openai 3.x ships 'httpx2' (with 'httpcore2') rather than 'httpx'.
        import httpx2 as httpx  # type: ignore[no-redef]
    except ImportError:
        httpx = None  # type: ignore[assignment]
        """Only the 'key' check needs an HTTP client beyond the openai SDK;
        every other check degrades without one, so a missing install must not
        block inference testing."""

DEFAULT_BASE_URL: Final[str] = "https://aigw.cern.ch/v1"

NO_DEFAULT_MODELS: Final[str] = "no-default-models"
"""Sentinel LiteLLM returns in place of a model list for a key with no
default model access. Its presence means authentication succeeded but the
key was granted nothing directly; team-granted models may still resolve at
request time, so it is a warning rather than a failure."""

DEFAULT_PROMPT: Final[str] = (
    "In one sentence, what is the ATLAS experiment at CERN?"
)

TOOL_PROMPT: Final[str] = (
    "What is the status of PanDA job 1234567? Use the available tool."
)

JOB_STATUS_TOOL: Final[dict[str, Any]] = {
    "type": "function",
    "function": {
        "name": "get_panda_job_status",
        "description": "Look up the current status of a PanDA job by its ID.",
        "parameters": {
            "type": "object",
            "properties": {
                "panda_id": {
                    "type": "integer",
                    "description": "The numeric PanDA job identifier.",
                },
            },
            "required": ["panda_id"],
        },
    },
}


@dataclass
class CheckResult:
    """Outcome of a single check.

    Attributes:
        ok: Whether the check succeeded.
        metrics: Measurements to merge into the per-model summary. Keys are
            drawn from :data:`SUMMARY_ROWS`; unknown keys are carried but not
            displayed.
    """

    ok: bool
    metrics: dict[str, Any] = field(default_factory=dict)


SUMMARY_ROWS: Final[tuple[tuple[str, str], ...]] = (
    ("prompt_tokens", "Prompt tokens"),
    ("completion_tokens", "Completion tokens"),
    ("total_tokens", "Total tokens"),
    ("latency_s", "Latency (s)"),
    ("latency_spread", "Latency min/max"),
    ("ttft_s", "Stream TTFT (s)"),
    ("chunks", "Stream chunks"),
    ("reasoning_tokens", "Reasoning chars"),
    ("tool_call", "Tool call"),
    ("context_limit", "Context limit"),
    ("embed_dim", "Embedding dim"),
)
"""Ordered (metric key, display label) pairs for the performance summary."""


@dataclass(frozen=True)
class Settings:
    """Resolved configuration for a single test run.

    Attributes:
        api_key: Virtual API key issued by the LiteLLM proxy.
        base_url: Proxy base URL, including the ``/v1`` suffix.
        model: Public model name as registered on the proxy.
        prompt: User prompt sent by the chat and stream checks.
        max_tokens: Upper bound on generated tokens per request.
        temperature: Sampling temperature.
        reasoning_effort: Optional reasoning budget hint, or ``None`` to omit.
        timeout: Per-request timeout in seconds.
        filler_tokens: Approximate prompt size used by the ``context`` probe.
    """

    api_key: str
    base_url: str
    model: str
    prompt: str
    max_tokens: int
    temperature: float
    reasoning_effort: str | None
    timeout: float
    filler_tokens: int = 40_000
    repeat: int = 1

    @property
    def models(self) -> tuple[str, ...]:
        """Split the configured model field into individual aliases.

        Accepting a comma-separated list lets a single run compare candidate
        models under identical prompts and settings.

        Returns:
            One or more model aliases, in the order given.
        """
        return tuple(
            name.strip() for name in self.model.split(",") if name.strip()
        )

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "Settings":
        """Build settings from parsed CLI arguments and the environment.

        Command-line values take precedence over environment variables.

        Args:
            args: Namespace produced by :func:`build_parser`.

        Returns:
            A fully populated :class:`Settings` instance.

        Raises:
            SystemExit: If a required value is missing from both sources.
        """
        api_key = args.api_key or os.environ.get("CERN_LLM_API_KEY", "")
        base_url = (
            args.base_url
            or os.environ.get("CERN_LLM_BASE_URL")
            or DEFAULT_BASE_URL
        )
        model = args.model or os.environ.get("CERN_LLM_MODEL", "")

        missing = [
            name
            for name, value in (
                ("--api-key / CERN_LLM_API_KEY", api_key),
                ("--model / CERN_LLM_MODEL", model),
            )
            if not value
        ]
        if missing:
            sys.exit("Missing required configuration: " + ", ".join(missing))

        return cls(
            api_key=api_key,
            base_url=base_url.rstrip("/"),
            model=model,
            prompt=args.prompt,
            max_tokens=args.max_tokens,
            temperature=args.temperature,
            reasoning_effort=args.reasoning_effort,
            timeout=args.timeout,
            filler_tokens=args.filler_tokens,
            repeat=args.repeat,
        )


def build_client(settings: Settings) -> OpenAI:
    """Construct an OpenAI-compatible client aimed at the proxy.

    Args:
        settings: Resolved run configuration.

    Returns:
        A configured :class:`openai.OpenAI` client.
    """
    return OpenAI(
        api_key=settings.api_key,
        base_url=settings.base_url,
        timeout=settings.timeout,
        max_retries=0,
    )


def extra_body(settings: Settings) -> dict[str, Any]:
    """Build provider-specific request fields not typed by the SDK.

    ``reasoning_effort`` is passed through the raw body so the script works
    with SDK versions that do not yet expose it as a named parameter.

    Args:
        settings: Resolved run configuration.

    Returns:
        A mapping suitable for the ``extra_body`` request argument.
    """
    body: dict[str, Any] = {}
    if settings.reasoning_effort:
        body["reasoning_effort"] = settings.reasoning_effort
    return body


def reasoning_of(message: Any) -> str | None:
    """Extract the separate reasoning channel from a response message.

    Proxies that do not merge reasoning into ``choices`` return it in a
    non-standard field, so it is read defensively.

    Args:
        message: A chat completion message object.

    Returns:
        The reasoning text, or ``None`` if the model returned none.
    """
    for field in ("reasoning_content", "reasoning"):
        value = getattr(message, field, None)
        if isinstance(value, str) and value.strip():
            return value
    return None


def proxy_root(settings: Settings) -> str:
    """Return the proxy root, with any ``/v1`` API prefix stripped.

    Administrative endpoints such as ``/key/info`` are mounted at the root,
    not beneath the OpenAI-compatible ``/v1`` prefix.

    Args:
        settings: Resolved run configuration.

    Returns:
        The proxy root URL without a trailing slash.
    """
    root = settings.base_url
    for suffix in ("/openai/v1", "/v1"):
        if root.endswith(suffix):
            return root[: -len(suffix)]
    return root


def fetch_json(settings: Settings, path: str) -> Any:
    """GET a JSON document from a proxy administrative endpoint.

    Args:
        settings: Resolved run configuration.
        path: Root-relative path, for example ``/key/info``.

    Returns:
        The decoded JSON body.

    Raises:
        httpx.HTTPStatusError: If the endpoint returns a non-2xx status.
    """
    response = httpx.get(
        f"{proxy_root(settings)}{path}",
        headers={"Authorization": f"Bearer {settings.api_key}"},
        timeout=settings.timeout,
    )
    response.raise_for_status()
    return response.json()


def check_models(client: OpenAI, settings: Settings) -> CheckResult:
    """List the models this key can see and flag the target's visibility.

    The check passes whenever the endpoint answers, because a successful
    listing already proves the base URL and key are good. A missing target
    model is reported as a warning: some proxy versions omit team-granted
    models here even though a chat request against them succeeds.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        ``True`` if the listing endpoint responded.
    """
    print("== models ==")
    names = sorted(model.id for model in client.models.list().data)
    if not names:
        print("  empty model list")
        return CheckResult(ok=True)

    for name in names:
        marker = " <-- target" if name == settings.model else ""
        print(f"  {name}{marker}")

    if names == [NO_DEFAULT_MODELS]:
        print(
            f"\n  WARNING: '{NO_DEFAULT_MODELS}' is a sentinel, not a model. "
            "Auth works, but this key has no directly granted models. "
            "Team-granted models may still work -- run --check chat to find "
            "out, and confirm the key belongs to the model's team.\n"
            "  This listing cannot enumerate candidate models: read the "
            "Models table in the proxy UI instead."
        )
    elif settings.model not in names:
        print(
            f"\n  WARNING: '{settings.model}' is not in this listing. Check "
            "the Public Model Name column in the UI -- the request takes that "
            "alias, not the model UUID or the cost-map key."
        )
    return CheckResult(ok=True)


def check_key(client: OpenAI, settings: Settings) -> CheckResult:
    """Report the calling key's team and granted models, if exposed.

    Queries the proxy's ``/key/info`` endpoint, which some deployments
    restrict to administrative keys. A rejection is reported without failing
    the run, since it says nothing about whether inference works.

    Args:
        client: Configured API client. Unused; kept for a uniform signature.
        settings: Resolved run configuration.

    Returns:
        ``True`` unless the endpoint returned an unexpected error.
    """
    del client
    print("== key ==")
    if httpx is None:
        print(
            "  skipped: neither 'httpx' nor 'httpx2' is importable "
            f"({sys.executable} -m pip install httpx)"
        )
        return CheckResult(ok=True)
    try:
        payload = fetch_json(settings, "/key/info")
    except httpx.HTTPStatusError as error:
        code = error.response.status_code
        if code in (401, 403, 404):
            print(
                f"  /key/info unavailable (HTTP {code}) -- usually restricted "
                "to admin keys. Read the key's team and models from the UI "
                "instead."
            )
            return CheckResult(ok=True)
        print(f"  HTTP {code}: {error.response.text[:300]}")
        return CheckResult(ok=False)

    info = payload.get("info", payload) if isinstance(payload, dict) else {}
    for field in ("key_alias", "team_id", "models", "spend", "max_budget"):
        if field in info:
            print(f"  {field}: {info[field]!r}")

    team_id = info.get("team_id")
    if not team_id:
        print(
            "\n  WARNING: this key has no team_id. A model with "
            "direct_access=false is reachable only through a key scoped to "
            "one of its access_via_team_ids."
        )
    return CheckResult(ok=True)


def parse_context_limit(message: str) -> tuple[int | None, int | None]:
    """Extract the context limit and prompt size from an overflow error.

    vLLM emits two different wordings depending on where the check fires, and
    both have been observed through this gateway:

    - ``This model's maximum context length is 16384 tokens ... your prompt
      contains at least 16321 input tokens``
    - ``Input length (48236) exceeds model's maximum context length (32768)``

    Args:
        message: The error message text.

    Returns:
        A ``(limit, prompt_tokens)`` pair, either element ``None`` if absent.
    """
    limit: int | None = None
    sent: int | None = None

    match = re.search(r"maximum context length is (\d+) tokens", message)
    if match:
        limit = int(match.group(1))
        inner = re.search(r"at least (\d+) input tokens", message)
        sent = int(inner.group(1)) if inner else None
        return limit, sent

    match = re.search(
        r"Input length \((\d+)\) exceeds model's maximum context length "
        r"\((\d+)\)",
        message,
    )
    if match:
        return int(match.group(2)), int(match.group(1))
    return None, None


def check_embed(client: OpenAI, settings: Settings) -> CheckResult:
    """Probe an embedding model and report its vector dimensionality.

    Dimensionality decides whether a hosted embedder could replace a local
    one without re-ingesting a vector store: differing dimensions make
    existing vectors unusable, so this is the first thing to measure.

    Not included in ``--check all``, since embedding models reject chat
    requests and chat models reject embedding requests.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        ``True`` if vectors came back.
    """
    print("== embed ==")
    # E5-family models are trained with asymmetric prefixes; sending them
    # unprefixed measurably degrades retrieval quality.
    inputs = [
        "query: pilot error 1099 lost heartbeat",
        "passage: The pilot failed to report within the heartbeat window.",
    ]

    started = time.monotonic()
    response = client.embeddings.create(model=settings.model, input=inputs)
    elapsed = time.monotonic() - started

    vectors = [item.embedding for item in response.data]
    if not vectors:
        print("  no vectors returned")
        return CheckResult(ok=False)

    dim = len(vectors[0])
    print(f"  vectors={len(vectors)} dim={dim} elapsed={elapsed:.2f}s")
    if response.usage is not None:
        print(f"  prompt_tokens={response.usage.prompt_tokens}")
    print(
        "  NOTE: a vector store built at a different dimensionality cannot "
        "be reused -- switching embedders means a full re-ingest."
    )
    print(
        "  NOTE: E5-family models expect 'query: ' / 'passage: ' prefixes; "
        "this probe sends them. Match that at ingest and query time."
    )
    return CheckResult(
        ok=True,
        metrics={"embed_dim": dim, "latency_s": round(elapsed, 2)},
    )


def check_context(client: OpenAI, settings: Settings) -> CheckResult:
    """Probe the usable context window with an oversized prompt.

    A model's advertised ``max_tokens`` in the proxy's model info is usually
    the deployment's context window, not a per-request output cap, and it can
    disagree with what the upstream server actually accepts. This sends
    deliberately large filler and reports the boundary the server reports back.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        ``True`` if the probe produced a usable answer or an informative limit.
    """
    print("== context ==")
    unit = "lorem ipsum dolor sit amet "
    # This filler tokenizes at roughly 5.4 chars/token (measured against the
    # gateway). Budget 6.5 chars/token so the probe overshoots the target
    # rather than silently testing a smaller window than requested.
    repeats = max(1, int(settings.filler_tokens * 6.5) // len(unit))
    filler = unit * repeats
    prompt = (
        "The following is filler text. Ignore it entirely and reply with "
        f"exactly the word OK.\n\n{filler}\n\nReply with exactly: OK"
    )
    print(f"  probing with ~{settings.filler_tokens} tokens of filler")

    try:
        response = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=64,
            temperature=0.0,
        )
    except openai.APIStatusError as error:
        limit, sent = parse_context_limit(str(error.message))
        if limit is None:
            print(f"  rejected: {error.message}")
            return CheckResult(ok=True)

        print(f"  REJECTED -- real context limit: {limit} tokens")
        if sent is not None:
            print(f"  (prompt was {sent} tokens)")
        print(
            "  NOTE: LiteLLM reports context overflow as HTTP "
            f"{error.status_code}, not 400. Detect it from the message, "
            "not the status code."
        )
        return CheckResult(ok=True, metrics={"context_limit": limit})

    usage = response.usage
    accepted = usage.prompt_tokens if usage is not None else None
    if accepted is not None:
        print(f"  ACCEPTED prompt_tokens={accepted}")
    print(f"  finish_reason={response.choices[0].finish_reason}")
    print(
        "  NOTE: this proves the window is at least this large, nothing more. "
        "Raise --filler-tokens until it is rejected to find the real limit."
    )
    return CheckResult(ok=True)


def check_chat(client: OpenAI, settings: Settings) -> CheckResult:
    """Issue chat completions and record token counts and latency.

    Repeats the request ``settings.repeat`` times. A single latency sample is
    too noisy to compare models with, so the mean is reported along with the
    observed spread.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        The outcome, with token and latency metrics.
    """
    print("== chat ==")
    latencies: list[float] = []
    choice = None
    usage = None

    for attempt in range(settings.repeat):
        started = time.monotonic()
        response = client.chat.completions.create(
            model=settings.model,
            messages=[{"role": "user", "content": settings.prompt}],
            max_tokens=settings.max_tokens,
            temperature=settings.temperature,
            extra_body=extra_body(settings),
        )
        latencies.append(time.monotonic() - started)
        choice = response.choices[0]
        usage = response.usage
        if settings.repeat > 1:
            print(f"  run {attempt + 1}/{settings.repeat}: "
                  f"{latencies[-1]:.2f}s")

    assert choice is not None
    reasoning = reasoning_of(choice.message)
    content = (choice.message.content or "").strip()

    if reasoning:
        print(f"  [reasoning] {reasoning.strip()[:500]}")
    print(f"  [content]   {content}")

    mean = sum(latencies) / len(latencies)
    print(f"  finish_reason={choice.finish_reason} mean_latency={mean:.2f}s")

    metrics: dict[str, Any] = {
        "latency_s": round(mean, 2),
        "reasoning_tokens": len(reasoning) if reasoning else 0,
    }
    if len(latencies) > 1:
        metrics["latency_spread"] = (
            f"{min(latencies):.2f}/{max(latencies):.2f}"
        )
    if usage is not None:
        print(
            f"  tokens: prompt={usage.prompt_tokens} "
            f"completion={usage.completion_tokens} "
            f"total={usage.total_tokens}"
        )
        metrics.update(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
        )

    if choice.finish_reason == "length" and not content:
        print(
            "  WARNING: truncated with EMPTY content -- the whole token "
            "budget went to reasoning. Raise --max-tokens."
        )
    return CheckResult(ok=bool(content), metrics=metrics)


def check_stream(client: OpenAI, settings: Settings) -> CheckResult:
    """Issue a streaming chat completion and print deltas as they arrive.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        ``True`` if at least one content delta was received.
    """
    print("== stream ==")
    chunks = 0
    started = time.monotonic()
    first_token_at: float | None = None

    print("  ", end="", flush=True)
    with client.chat.completions.create(
        model=settings.model,
        messages=[{"role": "user", "content": settings.prompt}],
        max_tokens=settings.max_tokens,
        temperature=settings.temperature,
        stream=True,
        extra_body=extra_body(settings),
    ) as stream:
        for event in stream:
            if not event.choices:
                continue
            piece = event.choices[0].delta.content
            if piece:
                if first_token_at is None:
                    first_token_at = time.monotonic() - started
                chunks += 1
                print(piece, end="", flush=True)
    print()

    ttft = f"{first_token_at:.2f}s" if first_token_at is not None else "n/a"
    print(f"  content chunks={chunks} time_to_first_token={ttft}")

    metrics: dict[str, Any] = {"chunks": chunks}
    if first_token_at is not None:
        metrics["ttft_s"] = round(first_token_at, 2)
    return CheckResult(ok=chunks > 0, metrics=metrics)


def check_tools(client: OpenAI, settings: Settings) -> CheckResult:
    """Run a two-turn function-calling round trip.

    The first turn should produce a ``tool_call``; a synthetic tool result is
    then fed back so the model can produce a final natural-language answer.

    Args:
        client: Configured API client.
        settings: Resolved run configuration.

    Returns:
        ``True`` if the model emitted a tool call and consumed its result.
    """
    print("== tools ==")
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": TOOL_PROMPT},
    ]

    first = client.chat.completions.create(
        model=settings.model,
        messages=messages,
        tools=[JOB_STATUS_TOOL],
        tool_choice="auto",
        max_tokens=settings.max_tokens,
        temperature=settings.temperature,
        extra_body=extra_body(settings),
    )
    message = first.choices[0].message
    tool_calls = message.tool_calls or []
    if not tool_calls:
        print("  model returned no tool_calls")
        print(f"  [content] {(message.content or '').strip()}")
        return CheckResult(ok=False)

    call = tool_calls[0]
    print(f"  tool_call: {call.function.name}({call.function.arguments})")

    messages.append(message.model_dump(exclude_none=True))
    messages.append(
        {
            "role": "tool",
            "tool_call_id": call.id,
            "content": json.dumps({"status": "finished", "attempt": 2}),
        }
    )

    second = client.chat.completions.create(
        model=settings.model,
        messages=messages,
        tools=[JOB_STATUS_TOOL],
        max_tokens=settings.max_tokens,
        temperature=settings.temperature,
        extra_body=extra_body(settings),
    )
    final = (second.choices[0].message.content or "").strip()
    print(f"  [final]    {final}")
    return CheckResult(
        ok=bool(final),
        metrics={"tool_call": "ok" if final else "no final answer"},
    )


def print_performance_summary(
    measured: dict[str, dict[str, Any]],
    models: Sequence[str],
) -> None:
    """Render a side-by-side table of per-model measurements.

    Only rows with at least one value are shown, so a run limited to a single
    check produces a compact table rather than a mostly empty one.

    Args:
        measured: Metrics keyed by model, then by metric name.
        models: Models in the order they should appear as columns.
    """
    present = [m for m in models if measured.get(m)]
    if not present:
        return

    rows = [
        (label, key)
        for key, label in SUMMARY_ROWS
        if any(key in measured.get(model, {}) for model in present)
    ]
    if not rows:
        return

    label_width = max(len(label) for label, _ in rows)
    col_width = max(max(len(m) for m in present), 12)

    print("== performance ==")
    header = " " * label_width + "  " + "  ".join(
        m.rjust(col_width) for m in present
    )
    print(f"  {header}")
    print("  " + "-" * len(header))
    for label, key in rows:
        cells = []
        for model in present:
            value = measured.get(model, {}).get(key)
            cells.append(("-" if value is None else str(value)).rjust(col_width))
        print(f"  {label.ljust(label_width)}  " + "  ".join(cells))
    print(
        "\n  Token counts are for one identical prompt; latency is a mean "
        "over --repeat runs."
    )


def describe_error(error: Exception) -> str:
    """Render an API error with a hint about its most likely cause.

    Args:
        error: The exception raised by the client.

    Returns:
        A human-readable diagnostic string.
    """
    if isinstance(error, openai.APIStatusError):
        hints = {
            400: "often an unrecognised model alias -- use the Public Model "
            "Name from the UI, not the model UUID or the cost-map key",
            401: "key rejected -- wrong or expired virtual key",
            403: "key lacks permission for this model or team",
            404: "endpoint not found -- is the base URL the proxy, not the "
            "upstream api_base, and does it end in /v1?",
            429: "rate limited or budget exhausted",
            504: "the GATEWAY's upstream timeout fired, not the client's -- "
            "raising --timeout cannot help. The backend is down, or cold and "
            "slower than the proxy will wait. Needs an admin.",
        }
        hint = hints.get(error.status_code, "")
        suffix = f" ({hint})" if hint else ""
        return f"HTTP {error.status_code}{suffix}: {error.message}"
    if isinstance(error, openai.APITimeoutError):
        return (
            "no response before the timeout. The proxy accepted the model "
            "name (an unknown alias is rejected immediately with 400), so the "
            "upstream is slow or down. A large model that scales to zero when "
            "idle can take minutes to load on its first request -- retry with "
            "--timeout 900. If it still times out, the backend is probably "
            "not deployed."
        )
    if isinstance(error, openai.APIConnectionError):
        return (
            f"connection failed: {error}. Check the host is reachable "
            "(CERN network or VPN) and that the URL scheme is correct."
        )
    return f"{type(error).__name__}: {error}"


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser.

    Returns:
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        description="Smoke-test a CERN LiteLLM-proxied OpenAI-compatible model.",
    )
    parser.add_argument("--api-key", help="Overrides CERN_LLM_API_KEY.")
    parser.add_argument(
        "--base-url",
        help=(
            "Proxy base URL ending in /v1. Overrides CERN_LLM_BASE_URL "
            f"(default: {DEFAULT_BASE_URL})."
        ),
    )
    parser.add_argument(
        "--model",
        help=(
            "Model alias, or a comma-separated list to compare candidates "
            "under identical settings. Overrides CERN_LLM_MODEL."
        ),
    )
    parser.add_argument(
        "--check",
        default="models",
        choices=(
            "models",
            "key",
            "chat",
            "stream",
            "tools",
            "context",
            "embed",
            "all",
        ),
        help="Which check to run (default: models).",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="Prompt used by the chat and stream checks.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=512,
        help=(
            "Maximum generated tokens. Keep this well below the model's "
            "context window; a reasoning model can spend the whole budget "
            "thinking and return empty content."
        ),
    )
    parser.add_argument(
        "--temperature", type=float, default=0.0, help="Sampling temperature."
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=("low", "medium", "high"),
        help="Reasoning budget hint; omitted entirely if unset.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help=(
            "Repeat the 'chat' check this many times and report mean latency. "
            "A single sample is too noisy to compare models with."
        ),
    )
    parser.add_argument(
        "--filler-tokens",
        type=int,
        default=40_000,
        help=(
            "Approximate prompt size for the 'context' check. Raise it until "
            "the model rejects the request to find the real window."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-request timeout in seconds.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected checks.

    Args:
        argv: Argument vector, or ``None`` to read from ``sys.argv``.

    Returns:
        ``0`` if every selected check passed, otherwise ``1``.
    """
    args = build_parser().parse_args(argv)
    settings = Settings.from_args(args)
    client = build_client(settings)

    models = settings.models
    print(f"base_url={settings.base_url}")
    print(f"models={', '.join(models)}\n")

    # Cheapest first: a cold or dead model is then detected by 'chat' and
    # skipped before the expensive context probe is ever attempted.
    selected = (
        ("models", "key", "chat", "stream", "tools", "context")
        if args.check == "all"
        else (args.check,)
    )
    runners = {
        "models": check_models,
        "key": check_key,
        "chat": check_chat,
        "stream": check_stream,
        "tools": check_tools,
        "context": check_context,
        "embed": check_embed,
    }
    # These query the key or the proxy, not a model, so running them once per
    # candidate model would repeat identical output.
    model_agnostic = {"models", "key"}

    results: dict[str, bool] = {}
    # A model whose backend is down or cold costs a full timeout on every
    # remaining check, so it is dropped after the first transport failure.
    unreachable: set[str] = set()
    interrupts = 0
    aborted = False
    measured: dict[str, dict[str, Any]] = {}

    for name in selected:
        targets = (
            (models[0],) if name in model_agnostic else models
        )
        is_agnostic = name in model_agnostic
        for target in targets:
            label = name if is_agnostic else f"{name}[{target}]"
            if not is_agnostic and target in unreachable:
                print(f"-- {target}\n== {name} ==")
                print("  skipped: model unreachable on an earlier check\n")
                results[label] = False
                continue

            run_settings = replace(settings, model=target)
            if len(targets) > 1:
                print(f"-- {target}")
            try:
                outcome = runners[name](client, run_settings)
                results[label] = outcome.ok
                if outcome.metrics:
                    measured.setdefault(target, {}).update(outcome.metrics)
            except KeyboardInterrupt:
                interrupts += 1
                results[label] = False
                print("\n  interrupted")
                if not is_agnostic:
                    unreachable.add(target)
                if interrupts >= 2:
                    print("  second interrupt -- aborting run\n")
                    aborted = True
                    break
                print("  skipping this check; Ctrl-C again to abort the run")
            except Exception as error:  # noqa: BLE001 - diagnostic entry point
                print(f"  FAILED: {describe_error(error)}")
                results[label] = False
                if not is_agnostic and isinstance(
                    error, openai.APIConnectionError
                ):
                    unreachable.add(target)
            print()
        if aborted:
            break

    print_performance_summary(measured, models)
    print()

    print("== summary ==")
    for label, ok in results.items():
        print(f"  {label}: {'ok' if ok else 'FAILED'}")
    if aborted:
        return 130
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
