# Public-copy leak check

Scan a directory of pages against a phrase file you supply. The script prints one row per hit and does not write files, open the network, or change a repository.

Every hit is severity `high`. A non-zero exit means at least one phrase was found. Exit `2` means the phrase file is missing or empty, or the directory to scan is missing. Exit `0` means no phrase was found.

## Phrase file

One phrase per line. Blank lines and lines that start with `#` are ignored. Matching is case-insensitive. Keep the phrase file outside the scanned directory when you can. If it sits inside that directory, the script skips that one file so the list does not report itself.

`examples/phrases.txt` is a synthetic list (`crimson widget`, `orbit lantern`). `examples/pages/clean-page.md` does not contain those phrases. Scan `examples/pages`, not `examples`, so the phrase file stays outside the scan.

Real phrases go in an untracked `phrases.local.txt`. That name is gitignored. This repository only commits the synthetic example.

## Run

```bash
python3 kits/public-copy-leak-check/leak_check.py \
  --root path/to/pages \
  --phrases path/to/phrases.txt
```

Each hit is four tab-separated fields: severity, check name, path, phrase.

This kit does not decide which phrases matter. You do, by what you put in the phrase file.
