# Review gate

A small check before a merge. It reads a verdict file you supply and allows the merge only when that verdict says `PASS` for the exact current head sha. A `PASS` for any other sha is refused, including a stale `PASS` on an older sha.

The script prints a decision and does not merge, open the network, or read credentials.

## Verdict file

JSON:

```json
{"verdict": "PASS", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

Text, one record per line, or a `verdict:` line paired with a `sha:` line. Blank lines and lines that start with `#` are ignored. `PASS` and the sha must belong to the same record. A sha mentioned somewhere else in the file does not count.

`examples/pass-current.json` matches the synthetic head `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`. `examples/pass-older.json` is a `PASS` for a different sha.

## Run

```bash
python3 kits/review-gate/review_gate.py \
  --verdict path/to/verdict.json \
  --head aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

python3 kits/review-gate/review_gate.py \
  --verdict path/to/verdict.txt \
  --head aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --dry-run
```

Omit `--head` to use the local `git rev-parse HEAD` in the current directory. That lookup stays on this machine.

`--dry-run` prints the same decision and always sets `approved: false`. It does not approve.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | A `PASS` names this exact head. Dry-run still prints `approved: false`. |
| 1 | Refuse. The reason is `stale`, `missing-sha`, or `no-pass`. |
| 2 | The verdict file or the head sha is missing or not usable. |

Stdout lines are `decision`, `reason`, `head`, and `approved`. Dry-run adds a `dry-run` line first.

## Optional comment capture

This tool does not run the command below. Save a comment yourself, then pass the file to `--verdict`.

```bash
gh api repos/OWNER/REPO/pulls/1/comments --jq '.[].body' > verdict.txt
```
