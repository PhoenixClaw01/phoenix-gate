# Red team

An optional review before a merge. An outside reviewer, separate from the author, tries to break a change. The review returns one `PASS` or `FAIL` verdict pinned to a commit SHA.

Only real breakage blocks. That is an attacker-reachable issue, or a leak. Every other repair goes on a kintsugi list with a size. Those items are gold seams: they are logged in the open and never hidden. A gold seam does not block.

The loop is:

1. The author writes the change.
2. A red-team reviewer, distinct from that author, reviews that head.
3. The author fixes what the review found.
4. The reviewer reviews again at the new head. A verdict for an older SHA is stale.
5. A `PASS` for the new head is the review result.
6. A human says yes.
7. The review gate allows the merge only when a `PASS` exists for the current head.

This kit is optional. A project can use its own review process. The scripts print a decision and do not merge, open the network, or read credentials.

It pairs with the review gate, which allows a merge only when a `PASS` verdict exists for the current head, and with the kintsugi audit, which keeps repairs visible.

## Verdict

`verdict.schema.json` is the machine-readable shape. A verdict file is one JSON object:

| field | meaning |
| --- | --- |
| `repo` | Repository name, `owner/name`. |
| `pr` | Pull request id. |
| `head_sha` | The commit that was reviewed. |
| `sha` | The same commit. The review gate reads this field. |
| `verdict` | `PASS` or `FAIL`, as a whole token. |
| `blocking` | Findings that block. Each `kind` is `attacker-reachable` or `leak`. |
| `kintsugi` | Repairs that do not block. Each item has a `size` of `small`, `medium`, or `large`. |
| `reviewer_id` | Who reviewed. |
| `author_id` | Who authored the change. This differs from `reviewer_id`. |
| `timestamp` | UTC time, `YYYY-MM-DDTHH:MM:SSZ`. |

`PASS` requires an empty `blocking` list. Kintsugi items may still be present. `FAIL` requires at least one blocking finding. A kintsugi list on its own is not a `FAIL`. `head_sha` and `sha` are the same value, and both match the current head. Anything else is rejected as `sha-mismatch` or `stale`.

`examples/pass-current.json` is a `PASS` for `a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0`. `examples/pass-with-kintsugi.json` is a `PASS` with one open repair. `examples/fail-blocking.json` is a `FAIL` with one leak and one repair. `examples/stale.json` is a `PASS` for a different sha.

## Check a verdict

```bash
python3 kits/red-team/verdict.py \
  --verdict kits/red-team/examples/pass-current.json \
  --head a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
```

Hand the same file to the review gate:

```bash
python3 kits/review-gate/review_gate.py \
  --verdict kits/red-team/examples/pass-current.json \
  --head a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0
```

The validator rejects a verdict whose head SHA is not the current head. The review gate then allows a merge only when the verdict it reads is `PASS` for that same head.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | The verdict is valid and its head SHA is the current head. |
| 1 | Reject. The reason is `stale`, `sha-mismatch`, `author-is-reviewer`, `blocking-on-pass`, or `fail-without-blocking`. |
| 2 | The verdict file or the head SHA is missing or not usable. |

Stdout lines are `decision`, `reason`, `head`, `verdict`, and `reviewer`.

## Routing

Routing is model-agnostic. A job names a lane. The reviewer config chooses which reviewer and which backend run that job. The author id is never chosen as the reviewer.

```bash
python3 kits/red-team/routing.py \
  --config kits/red-team/examples/reviewer-config.json \
  --repo example/repo \
  --pr 7 \
  --head a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 \
  --author author-one \
  --lane default
```

This command prints the chosen reviewer and backend. It does not write a verdict and it does not approve a merge.

Backends are pluggable adapters. The interface is one method:

```text
review(job) -> ReviewDraft
```

`ReviewDraft` carries `verdict`, `blocking`, and `kintsugi`. The router stamps `reviewer_id`, `author_id`, the head SHA, and the timestamp, then checks the document.

This kit ships one adapter, named `local` in `examples/reviewer-config.json`. `local` is an in-process stand-in for tests and wiring. It returns a draft only when the caller supplies one. It does not inspect a diff and it does not invent a `PASS`. A project that wants another backend registers an adapter under a backend name in its own config. Backend names are strings in that config.

`REVIEW-PROMPT.md` is the template for what a review checks, and for the blocking-versus-kintsugi rule.

## Optional

Use this kit when a project wants an outside review pinned to a head. A project can skip it and keep its own process. Nothing here turns the kit on by itself.
