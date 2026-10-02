# aigw_probe.py

A dependency-light smoke-test harness for the CERN AI gateway
(`https://aigw.cern.ch`), a LiteLLM proxy exposing OpenAI-compatible models.

It answers three questions that are otherwise awkward to separate: *is my key
working*, *is this model reachable*, and *which of these models should I
use*. Each check is independent, so a failure localises itself instead of
surfacing as one opaque HTTP error.

## Install

```bash
python -m pip install openai
```

Use `python -m pip`, not bare `pip` — it guarantees you install into the same
interpreter that will run the script. Mismatched environments are the most
common setup failure.

Python 3.10+. Tested on 3.12 and 3.14.

The `key` check additionally wants an HTTP client (`httpx` or `httpx2`); it
skips itself if neither is importable. Every other check needs only `openai`.

## Configure

| Variable | Required | Default |
| --- | --- | --- |
| `CERN_LLM_API_KEY` | yes | — |
| `CERN_LLM_MODEL` | yes | — |
| `CERN_LLM_BASE_URL` | no | `https://aigw.cern.ch/v1` |

```bash
export CERN_LLM_API_KEY='sk-...'
export CERN_LLM_MODEL='gpt-oss-20b'
```

Each is overridable with `--api-key`, `--model`, `--base-url`.

Get the API key and the model alias from the proxy UI at
<https://aigw.cern.ch/ui/>. **The alias is the "Public Model Name" column** —
not the model UUID, and not the `key` field from the model-info JSON.

## Use

```bash
# Is my key working at all? Cheapest check, costs no tokens.
python aigw_probe.py --check models

# Does this model actually answer?
python aigw_probe.py --check chat

# Everything, comparing two models side by side.
python aigw_probe.py --check all --repeat 5 \
    --model gpt-oss-20b,hf-qwen3-32b-awq

# Embedding models (excluded from --check all).
python aigw_probe.py --check embed --model e5-large-v2

# Find a model's true context window.
python aigw_probe.py --check context --model gpt-oss-20b --filler-tokens 40000
```

### Checks

| Check | What it establishes |
| --- | --- |
| `models` | Base URL and key are valid. Lists what the key can see. |
| `key` | The key's team and granted models, via `/key/info`. |
| `chat` | One or more completions; token counts, latency, reasoning channel. |
| `stream` | Incremental delivery works; time-to-first-token. |
| `tools` | Two-turn function calling: model emits a `tool_call` and consumes the result. |
| `context` | The real usable context window, by overflowing it deliberately. |
| `embed` | Embedding dimensionality and latency. |
| `all` | Everything except `embed`. |

`embed` is excluded from `all` because embedding models reject chat requests
and chat models reject embedding requests.

### Comparing models

Pass a comma-separated list to `--model`. Model-specific checks then run once
per candidate under identical settings, and the run ends with a table:

```
== performance ==
                          gpt-oss-20b  hf-qwen3-32b-awq
  -----------------------------------------------------
  Prompt tokens                    80                26
  Completion tokens               201                59
  Total tokens                    281                85
  Latency (s)                    1.93              1.17
  Stream TTFT (s)                0.78              0.08
  Reasoning chars                 512                 0
  Tool call                        ok                ok
  Context limit                 32768             16384
```

Use `--repeat 5` or more for latency. Single samples vary by tens of percent
on the same model and prompt.

`models` and `key` query the proxy rather than a model, so they run once
regardless. A model that fails at the transport level is dropped from its
remaining checks, so an unreachable backend costs one timeout rather than one
per check. Ctrl-C skips the current check; a second Ctrl-C aborts the run.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | every selected check passed |
| 1 | at least one failed |
| 130 | aborted with Ctrl-C |

## Interpreting failures

**`no-default-models` in the model list** is a LiteLLM sentinel, not a model
and not an error. It means the key has no *directly* granted models. Models
granted through a team can still work — `/v1/models` under-reports them. So
this listing cannot enumerate candidates; read the UI's Models table instead.

**HTTP 400** usually means an unrecognised model alias. Check the Public Model
Name column.

**HTTP 401 / 403** on a chat request means the key is not scoped to the
model's team. On `/key/info` specifically, 403 just means the endpoint is
admin-only and says nothing about whether inference works.

**HTTP 500** may be a context overflow rather than a server fault: LiteLLM
wraps `ContextWindowExceededError` in a 500. The message names the true limit.
Two vLLM wordings exist and the script parses both:

- `This model's maximum context length is 16384 tokens ... at least 16321 input tokens`
- `Input length (48236) exceeds model's maximum context length (32768)`

**HTTP 504** is the *gateway's* upstream timeout, not the client's. Raising
`--timeout` cannot help: nginx gives up first. The backend is down, or cold
and slower than the proxy will wait. Needs an admin.

**A client-side timeout** (rather than a 400) means the proxy accepted the
model name and routed it — an unknown alias is rejected immediately without
contacting any upstream. So the alias is probably right and the backend is
the problem.

## Things worth knowing about these models

Snapshot from October 2026; re-measure rather than trusting this.

- **The advertised `max_tokens` is the context window**, not a per-request
  output cap. It sits alongside `max_input_tokens: null` in the model info.
  `--max-tokens` in this script is a generation cap — a different quantity.
- **Reasoning arrives on a separate channel.** Where
  `merge_reasoning_content_in_choices` is false, chain-of-thought lands in
  `message.reasoning_content`, not `message.content`. Code that logs whole
  message objects will write chain-of-thought into its logs.
- **A reasoning model can return empty content with no error.** Under a tight
  `--max-tokens` it spends the entire budget thinking and returns
  `finish_reason="length"` with an empty string. The `chat` check warns about
  this explicitly.
- **Reasoning behaviour is per-model config.** `gpt-oss-20b` emits a reasoning
  channel; `hf-qwen3-32b-awq` does not. Don't generalise from one model.
- **E5-family embedding models expect `query: ` / `passage: ` prefixes** and
  degrade measurably without them. The `embed` check sends them.
- **Embedding dimensionality decides re-ingest cost.** `e5-large-v2` returns
  1024-dim vectors; a store built at a different dimensionality cannot be
  reused.
- **`openai` 3.x depends on `httpx2`/`httpcore2`, not `httpx`.** An
  `import httpx` next to it can fail even though an HTTP client is installed.
- **The `api_base` in a model's LiteLLM params is the upstream inference
  server**, not the endpoint your virtual key may call. Call the proxy.

## What this does not test

The `tools` check uses one tool, one required integer parameter, one round
trip, and a prompt that says to use the tool. That is a long way from
realistic agent conditions. It does not exercise selection among competing
tools, optional parameters, nested objects, enums, chained calls, or prompts
that don't hint tools exist.

More broadly, this measures speed, size, and whether plumbing works. It says
nothing about answer quality.

## Notes

The script is standalone — a single file with no package layout, no config
file, and no state. Copy it anywhere.

It deliberately avoids a `test_` prefix. This is an interactive diagnostic
probe that makes live network calls, not a unit test: a `test_*.py` name would
make pytest collect it by default, and its `check_*` functions are not tests.
Keep it out of any directory your test runner scans.
