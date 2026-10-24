# Hash allowlist runner

A small runner. It executes a Python script only when the script file's sha256 is in an allowlist and the git work tree is clean. A dirty tree, a tree that is not the git toplevel, a hash that is not listed, a symlink, or a path outside `--root` refuses before the script starts.

The runner opens the script without following a symlink, reads the bytes once, and hashes those bytes. Those bytes are the program. They are passed to `python -I -B -`. The path is not executed. The script has to be a regular file inside `--root`, with no symlink in between.

Ignored files, skip-worktree entries, and assume-unchanged entries count as a dirty tree. The git probe does not use repo aliases, a filesystem monitor, or the caller's git configuration.

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
| 1 | Refused (`dirty-tree`, `not-a-repo`, `not-allowlisted`, `symlink`, `outside-root`, or `not-a-file`), or the script ran and exited non-zero. |
| 2 | The allowlist, script, root, receipt path, phrase file, or scrubber is missing or not usable. |

Stdout is the redacted receipt. The same text is written to `--receipt`.
