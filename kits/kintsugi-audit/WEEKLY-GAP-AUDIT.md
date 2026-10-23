# Weekly gap audit

Read-only. This pass does not merge, deploy, or change data.

## Window

- Week of: YYYY-MM-DD
- Scope: <repository or directory>
- Operator: <role>
- Tool usage (week): [count or not read]

## Findings

Ranked by severity. One row per finding. Delete unused severity rows when that rank is empty.

| severity | area | finding | evidence | suggested next step |
| --- | --- | --- | --- | --- |
| critical |  |  |  |  |
| high |  |  |  |  |
| medium |  |  |  |  |
| low |  |  |  |  |

Severity order: critical, high, medium, low.

## Injected-instruction check

Command:

`python3 kits/kintsugi-audit/injected_instruction_check.py --root <path>`

Result: pass or fail

Notes:

## Repo drift

Command:

`python3 kits/kintsugi-audit/repo_drift.py --root <path> --manifest <manifest>`

Result: pass or fail

Notes:

## Watcher health

Command:

`python3 kits/kintsugi-audit/watcher_health.py --status <status.json> --max-age-hours 168`

Result: pass or fail

Notes:

## Close

- Read-only: yes
- Writes performed: none
- Spend ceiling changed: no
