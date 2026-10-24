# Hash allowlist runner

A small runner. It executes a Python script only when the script file's sha256 is in an allowlist and the git work tree is clean. A dirty tree, a tree that is not a git checkout, or a hash that is not listed refuses before the script starts.

The receipt is written through the export scrubber in the safe-helpers kit. The same generic patterns are removed, and an optional phrase file is applied the same way. The runner does not open the network.

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
| 1 | Refused (`dirty-tree`, `not-a-repo`, or `not-allowlisted`), or the script ran and exited non-zero. |
| 2 | The allowlist, script, root, receipt directory, phrase file, or scrubber is missing or not usable. |

Stdout is the redacted receipt. The same text is written to `--receipt`.
