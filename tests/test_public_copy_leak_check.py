"""Behavior checks for the public-copy leak check kit.

The example phrase list is synthetic. Real phrases belong in an untracked
phrases.local.txt, never in this file.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "public-copy-leak-check"
SYNTHETIC_PHRASES = ("crimson widget", "orbit lantern")
LOCAL_PHRASE_FILE = "phrases.local.txt"


def load_script():
    path = KIT / "leak_check.py"
    spec = importlib.util.spec_from_file_location("leak_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicCopyLeakPhraseFileTests(unittest.TestCase):
    def test_example_list_is_synthetic(self):
        module = load_script()
        phrases = module.parse_phrases((KIT / "examples" / "phrases.txt").read_text(encoding="utf-8"))
        self.assertEqual(phrases, list(SYNTHETIC_PHRASES))

    def test_real_phrases_stay_in_an_untracked_file(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(LOCAL_PHRASE_FILE, ignore)
        tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True)
        self.assertNotIn(LOCAL_PHRASE_FILE, tracked.splitlines())


class PublicCopyLeakBehaviorTests(unittest.TestCase):
    def test_clean_fixture_passes_and_a_planted_page_fails(self):
        module = load_script()
        phrases = module.parse_phrases((KIT / "examples" / "phrases.txt").read_text(encoding="utf-8"))
        self.assertEqual(phrases, list(SYNTHETIC_PHRASES))
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
