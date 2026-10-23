# Kintsugi audit kit

A weekly, read-only gap audit. The scripts print severity-ranked findings and do not write files, open the network, or change a repository.

Severity order, highest first: `critical`, `high`, `medium`, `low`.

## Weekly pass

1. Copy `WEEKLY-GAP-AUDIT.md` into the week's notes.
2. Run the three checks from the repository you are auditing.
3. Paste each result under the matching heading.
4. Leave a finding row blank when that severity has nothing to report.

```bash
python3 kits/kintsugi-audit/injected_instruction_check.py --root .
python3 kits/kintsugi-audit/repo_drift.py --root . --manifest path/to/manifest.txt
python3 kits/kintsugi-audit/watcher_health.py --status path/to/status.json --max-age-hours 168
```

The manifest is a list of paths relative to `--root`, one per line. Blank lines and lines that start with `#` are ignored.

The status file is JSON with `name`, `last_ok` (UTC timestamp), and `read_only: true`. See `examples/watcher-status.json`.

This kit does not merge, deploy, or edit data. A non-zero exit means the check found something to rank, not that a file was changed.
