"""Scrub and behavior checks for the public-copy leak check kit."""

from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "public-copy-leak-check"


def load_script():
    path = KIT / "leak_check.py"
    spec = importlib.util.spec_from_file_location("leak_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def joined(*parts: str) -> str:
    return "".join(parts)


def _rule(name: str, pattern: str, flags: int = 0) -> tuple[str, re.Pattern[str]]:
    return name, re.compile(pattern, flags)


SCRUB_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    _rule("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    _rule(
        "business-id",
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ),
    _rule("supabase-host", joined("supabase", ".co"), re.IGNORECASE),
    _rule("supabase-ref", r"\b[a-z0-9]{20}\." + joined("supabase"), re.IGNORECASE),
    _rule("drive-backslash", r"[A-Za-z]:\\"),
    _rule("drive-slash", r"[A-Za-z]:/"),
    _rule("phone", r"(?<!\d)(?:\+\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    _rule("vercel-project", r"\b" + joined("prj_") + r"[A-Za-z0-9]{8,}\b"),
    _rule("vercel-team", r"\b" + joined("team_") + r"[A-Za-z0-9]{8,}\b"),
    _rule("eth-wallet", r"\b0x[a-fA-F0-9]{40}\b"),
    _rule("solana-address", r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
    _rule("starlink", joined("star", "link"), re.IGNORECASE),
    _rule("phoenix-collective-hyphen", joined("phoenix-", "collective"), re.IGNORECASE),
    _rule("phoenix-collective-space", joined("phoenix ", "collective"), re.IGNORECASE),
    _rule("annapolis-valley", joined("annapolis", " valley"), re.IGNORECASE),
    _rule("small-business", joined("small ", "business"), re.IGNORECASE),
    _rule("constitution", joined("consti", "tution"), re.IGNORECASE),
    _rule("sovereignty", joined("sover", "eignty"), re.IGNORECASE),
    _rule("named-lock", joined("named ", "lock"), re.IGNORECASE),
    _rule("routing-engine", joined("routing_", "engine"), re.IGNORECASE),
    _rule("check-routing", joined("check_", "routing"), re.IGNORECASE),
    _rule("routing-yaml", joined("routing.", "yaml"), re.IGNORECASE),
    _rule("tooling-repo", joined("sa-", "tooling"), re.IGNORECASE),
    _rule("iter-doors", joined("iter_", "doors"), re.IGNORECASE),
    _rule("fractal", joined("frac", "tal"), re.IGNORECASE),
    _rule("tenant", joined("ten", "ant"), re.IGNORECASE),
    _rule("partner", joined("part", "ner"), re.IGNORECASE),
    _rule("phoenix-farms", joined("Phoenix", " Farms")),
    _rule("claw", r"\b" + joined("Cl", "aw") + r"\b", re.IGNORECASE),
    _rule("founder", r"\b" + joined("Found", "er") + r"\b", re.IGNORECASE),
)


def scrub_hits(text: str) -> list[str]:
    return [name for name, pattern in SCRUB_RULES if pattern.search(text)]


# Fictional samples. They live in this test, not in the kit.
PLANTED_SAMPLES: tuple[tuple[str, str], ...] = (
    ("email", "ada@example.com"),
    ("business-id", "00000000-0000-4000-8000-000000000000"),
    ("supabase-host", "example." + joined("supabase", ".co")),
    ("supabase-ref", "abcdefghijklmnopqrst." + joined("supabase", ".co")),
    ("drive-backslash", "D:\\work\\notes"),
    ("drive-slash", "D:/work/notes"),
    ("phone", "+1 202 555 0147"),
    ("vercel-project", joined("prj_") + "example1234567890"),
    ("vercel-team", joined("team_") + "example1234567890"),
    ("eth-wallet", "0x" + ("a0" * 20)),
    ("solana-address", "2" * 32),
    ("starlink", joined("star", "link")),
    ("phoenix-collective-hyphen", joined("phoenix-", "collective")),
    ("phoenix-collective-space", joined("phoenix ", "collective")),
    ("annapolis-valley", joined("annapolis", " valley")),
    ("small-business", joined("small ", "business")),
    ("constitution", joined("consti", "tution")),
    ("sovereignty", joined("sover", "eignty")),
    ("named-lock", joined("named ", "lock")),
    ("routing-engine", joined("routing_", "engine")),
    ("check-routing", joined("check_", "routing")),
    ("routing-yaml", joined("routing.", "yaml")),
    ("tooling-repo", joined("sa-", "tooling")),
    ("iter-doors", joined("iter_", "doors")),
    ("fractal", joined("frac", "tal")),
    ("tenant", joined("ten", "ant")),
    ("partner", joined("part", "ner")),
    ("phoenix-farms", joined("Phoenix", " Farms")),
    ("claw", joined("Cl", "aw")),
    ("founder", joined("Found", "er")),
)


class PublicCopyLeakScrubTests(unittest.TestCase):
    def test_kit_has_no_local_content(self):
        hits = []
        for path in sorted(KIT.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            for name in scrub_hits(text):
                hits.append(f"{path.relative_to(ROOT)} matches {name}")
        self.assertEqual(hits, [])

    def test_each_planted_sample_fails_its_class(self):
        planted = dict(PLANTED_SAMPLES)
        self.assertEqual(set(planted), {name for name, _pattern in SCRUB_RULES})
        for name, sample in PLANTED_SAMPLES:
            hits = scrub_hits(sample)
            self.assertIn(name, hits, sample)


class PublicCopyLeakBehaviorTests(unittest.TestCase):
    def test_clean_fixture_passes_and_a_planted_page_fails(self):
        module = load_script()
        phrases = module.parse_phrases((KIT / "examples" / "phrases.txt").read_text(encoding="utf-8"))
        self.assertEqual(phrases, ["crimson widget", "orbit lantern"])
        clean = module.scan(KIT / "examples" / "pages", phrases)
        self.assertEqual(clean, [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "page.md").write_text("A quiet note about a Crimson Widget on the table.\n", encoding="utf-8")
            findings = module.scan(root, phrases)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["check"], "public-copy-leak")
        self.assertEqual(findings[0]["path"], "page.md")
        self.assertEqual(findings[0]["phrase"], "crimson widget")

    def test_phrase_file_inside_the_root_is_not_a_hit(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            phrases = root / "phrases.txt"
            phrases.write_text("crimson widget\n", encoding="utf-8")
            (root / "page.md").write_text("A harbor and a paper map.\n", encoding="utf-8")
            parsed = module.parse_phrases(phrases.read_text(encoding="utf-8"))
            self.assertEqual(module.scan(root, parsed, skip=phrases), [])

    def test_cli_exits_for_a_hit_a_clean_tree_and_an_empty_list(self):
        module = load_script()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pages = root / "pages"
            pages.mkdir()
            (pages / "page.md").write_text("orbit lantern\n", encoding="utf-8")
            phrase_file = root / "phrases.txt"
            phrase_file.write_text("# note\n\norbit lantern\n", encoding="utf-8")
            self.assertEqual(module.main(["--root", str(pages), "--phrases", str(phrase_file)]), 1)
            (pages / "page.md").write_text("A harbor and a paper map.\n", encoding="utf-8")
            self.assertEqual(module.main(["--root", str(pages), "--phrases", str(phrase_file)]), 0)
            phrase_file.write_text("# only a comment\n\n", encoding="utf-8")
            self.assertEqual(module.main(["--root", str(pages), "--phrases", str(phrase_file)]), 2)
            self.assertEqual(module.main(["--root", str(root / "missing"), "--phrases", str(phrase_file)]), 2)
