# Safe helpers

Three small tools. They print or return a result. They do not open the network, write files, or hand a message to a sender.

## Dry-run send

`dry_run_send.py` prints the message it would send and returns `delivered: false`.

```bash
python3 kits/safe-helpers/dry_run_send.py \
  --to "harbor desk" \
  --title "paper map" \
  --body "the crate is ready"
```

## Token bucket

`token_bucket.py` starts full. Each event is `time:cost`, in time order. A line is `allow` or `deny`. Exit `1` means at least one event was denied.

```bash
python3 kits/safe-helpers/token_bucket.py \
  --capacity 2 \
  --refill-per-second 1 \
  --event 0:1 --event 0:1 --event 0:1 --event 1:1
```

## Export scrubber

`export_scrub.py` replaces these shapes with `[redacted]`:

- email addresses
- phone numbers
- UUIDs
- private-key blocks and labeled secrets (`api key`, `secret key`, `access token` assignments)
- ids that start with `prj_` or `team_`
- wallet addresses (`0x` plus 40 hex digits, and a 32–44 character opaque address)

An optional phrase file adds exact phrases, one per line. Blank lines and lines that start with `#` are ignored. Matching is case-insensitive.

When `--phrases` is omitted, the script reads `phrases.local.txt` in the current directory if that file exists, and otherwise scrubs the generic patterns only. That name is gitignored. A missing default file is not an error. If you pass `--phrases` and the file is missing, the script exits `2`.

```bash
python3 kits/safe-helpers/export_scrub.py --input note.txt
python3 kits/safe-helpers/export_scrub.py --input note.txt --phrases phrases.local.txt
```

`examples/clean-note.txt` has none of these shapes.
