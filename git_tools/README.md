# Git Commit Notes

A small Python command-line utility for displaying the latest commit message from a Git repository.

The command can be run either from the repository itself or by specifying a target repository directory with `--target-directory`.

## Requirements

* Python 3.8 or later
* Git installed and available in `PATH`
* A Git repository

No external Python packages are required.

## Usage

### Current directory

Run the command without any arguments:

```bash
python3 git_notes.py
```

When no target directory is specified, the command uses the **current working directory**.

For example:

```bash
cd ~/Projects/MyGame
python3 git_notes.py
```

### Specify a repository

Use `--target-directory` to specify the Git repository:

```bash
python3 git_notes.py --target-directory ~/Projects/MyGame
```

The short form `-d` is also supported:

```bash
python3 git_notes.py -d ~/Projects/MyGame
```

## Example Output

The command displays the latest commit's short hash, subject, and body:

```text
a83f91c Add support for Apple TV controller

Added initial PS5 controller support.
Mapped the left and right analog sticks.
```

The output consists of:

* **Short commit hash** — e.g. `a83f91c`
* **Commit subject** — the first line of the commit message
* **Commit body** — any additional notes in the commit message

## How It Works

The script uses Git's command-line interface through Python's `subprocess` module.

Conceptually, it executes:

```bash
git log -1 --pretty=format:%h %s%n%b
```

The `-1` option requests the most recent commit.

The formatting options are:

| Format | Meaning           |
| ------ | ----------------- |
| `%h`   | Short commit hash |
| `%s`   | Commit subject    |
| `%n`   | New line          |
| `%b`   | Commit body       |

The command is executed with the target directory as its working directory.

## Error Handling

The command reports an error if:

* The specified directory does not exist.
* The directory is not a Git repository.
* Git is not installed or cannot be found in `PATH`.

For example:

```text
Error: directory does not exist: /some/path
```

or:

```text
Error: '/some/path' does not appear to be a Git repository.
```

## Examples

### Repository in the current directory

```bash
$ cd ~/Projects/MyGame
$ python3 git_notes.py

a83f91c Add support for Apple TV controller

Added initial PS5 controller support.
Mapped the left and right analog sticks.
```

### Repository elsewhere

```bash
$ python3 git_notes.py --target-directory ~/Projects/MyGame

a83f91c Add support for Apple TV controller

Added initial PS5 controller support.
Mapped the left and right analog sticks.
```

### Using the short option

```bash
$ python3 git_notes.py -d ~/Projects/MyGame
```

## Showing More Than One Commit

The script currently displays only the latest commit.

To display the last 10 commits, change:

```python
["git", "log", "-1", "--pretty=format:%h %s%n%b"]
```

to:

```python
["git", "log", "-10", "--pretty=format:%h %s%n%b---"]
```

This could also be exposed as a future command-line option such as:

```bash
python3 git_notes.py --last 10
```

## License

This project can be used and modified freely unless a separate license is added to the repository.
