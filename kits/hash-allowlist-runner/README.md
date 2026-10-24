# Hash allowlist runner

A small runner. It executes a Python script only when the script file's sha256 is in an allowlist and the git work tree is clean. A dirty tree, a tree that is not the git toplevel, a layout other than a plain repository, a hash that is not listed, a symlink, a path outside `--root`, a path that is not the blob at HEAD, or a repo filter driver refuses before the script starts.

The work tree is checked first, including ignored files and index flags. Only a clean tree is read. The runner opens the script without following a symlink, reads it again, and requires the two reads to be the same bytes. Those bytes must equal `git cat-file blob HEAD:<path>` for that path inside `--root`. The same git probe is used: no repo aliases, no filesystem monitor, and not the caller's git configuration. A path that is not in HEAD is refused, so an untracked file never runs. The matching bytes are hashed, and that same buffer is passed to `python -I -B -`. The path is not executed. The script has to be a regular file inside `--root`, with no symlink in between.

Ignored files, skip-worktree entries, and assume-unchanged entries count as a dirty tree. The git probe does not use repo aliases, a filesystem monitor, or the caller's git configuration. System gitattributes are not read.

A repo-local `filter.<name>.clean`, `smudge`, or `process` driver refuses with `unsafe-config` before `git status`. That includes a driver pulled in by the repo config. A `filter=` line in `.gitattributes` (any directory under `--root`) or in `info/attributes` refuses the same way. Every git call clears each discovered driver: `clean`, `smudge`, and `process` are set empty, and `required` is false, so the configured command does not run.

Every git call also passes `--no-optional-locks`, sets `GIT_OPTIONAL_LOCKS=0`, and points `core.hooksPath` at an empty directory the runner creates. Repo hooks are not started, including `post-index-change` and a `core.hooksPath` value from repo config. The probe does not refresh the index. An executable file in `.git/hooks`, other than a `*.sample` file, or a configured `core.hooksPath`, refuses with `unsafe-config` before `git status`.

Only a plain repository is supported. The git directory has to be the real directory `<root>/.git`, and that same directory has to be the common git directory. A gitdir file, a symlink, a linked worktree, a separate git directory, a bare repository, or any resolved path that contains a control character is refused with `unsupported-layout` before `git status`. Those paths are read from `git rev-parse -z` without splitting on newlines.

Repo config is one include-following query. A local or worktree `filter.*` value, `core.hooksPath`, or `core.fsmonitor` refuses with `unsafe-config` when it is non-empty and not false, including a value brought in by an include. System and global config are not used. An empty value, `false`, and `0` do not refuse.

The receipt is created as a new file before the script starts. An existing path, including a symlink, is not replaced or followed. The text is written through the export scrubber in the safe-helpers kit. The same generic patterns are removed, and an optional phrase file is applied the same way. The runner does not open the network.

## Allowlist

One sha256 per line, lowercase or uppercase hex. A label after the hash is ignored. Blank lines and lines that start with `#` are ignored. Any other line is an error.

`examples/allowlist.txt` lists `examples/hello.py`.

## Run

```bash
python3 kits/hash-allowlist-runner/runner.py \
  --allowlist kits/hash-allowlist-runner/examples/allowlist.txt \
  --script kits/hash-allowlist-runner/examples/hello.py \
  --root . \
  --receipt /tmp/hello.receipt.txt
```

`--root` is the git work tree to check. It defaults to the current directory. Put the receipt outside that tree, or ignore it, so the next run still sees a clean tree.

When `--phrases` is omitted, `phrases.local.txt` in the current directory is used if it exists. A missing default file is not an error. If you pass `--phrases` and the file is missing, the runner exits `2`.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | The script ran and exited 0. The receipt says `decision: allow`. |
| 1 | Refused (`dirty-tree`, `not-a-repo`, `unsupported-layout`, `unsafe-config`, `not-allowlisted`, `symlink`, `outside-root`, `not-a-file`, `changed`, or `not-in-head`), or the script ran and exited non-zero. |
| 2 | The allowlist, script, root, receipt path, phrase file, or scrubber is missing or not usable. |

Stdout is the redacted receipt. The same text is written to `--receipt`.
