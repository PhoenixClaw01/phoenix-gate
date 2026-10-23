"""Behavior checks for the safe-helpers kit. Fixtures are synthetic."""

from __future__ import annotations

import importlib.util
import io
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "kits" / "safe-helpers"

HEX_WALLET = "0x" + ("a0" * 20)
OPAQUE_WALLET = "z" * 32


def load_script(name: str):
    path = KIT / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DryRunSendTests(unittest.TestCase):
    def test_prints_the_message_and_does_not_send(self):
        module = load_script("dry_run_send.py")
        buffer = io.StringIO()
        message = {"to": "harbor desk", "title": "paper map", "body": "the crate is ready"}

        def fail_open(*_args, **_kwargs):
            raise AssertionError("network")

        original = socket.socket
        socket.socket = fail_open
        try:
            result = module.deliver(message, out=buffer)
        finally:
            socket.socket = original

        preview = buffer.getvalue()
        self.assertIn("dry-run", preview)
        self.assertIn("to: harbor desk", preview)
        self.assertIn("title: paper map", preview)
        self.assertIn("the crate is ready", preview)
        self.assertFalse(result["delivered"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["preview"], preview)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = module.main(["--to", "harbor desk", "--title", "paper map", "--body", "the crate is ready"])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue(), preview)

    def test_kit_scripts_do_not_import_a_sender(self):
        needles = (
            "import socket",
            "from socket",
            "import urllib",
            "import smtplib",
            "import http",
            "import requests",
        )
        for path in sorted(KIT.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for needle in needles:
                self.assertNotIn(needle, text, path.name)


class TokenBucketTests(unittest.TestCase):
    def test_bucket_refills_up_to_capacity(self):
        module = load_script("token_bucket.py")
        now = {"t": 0.0}
        bucket = module.TokenBucket(2, 1, clock=lambda: now["t"])
        self.assertTrue(bucket.take(1))
        self.assertTrue(bucket.take(1))
        self.assertFalse(bucket.take(1))
        now["t"] = 0.5
        self.assertFalse(bucket.take(1))
        self.assertTrue(bucket.take(0.5))
        now["t"] = 10
        self.assertTrue(bucket.take(1))
        self.assertTrue(bucket.take(1))
        self.assertFalse(bucket.take(1))

    def test_cost_above_capacity_is_denied(self):
        module = load_script("token_bucket.py")
        bucket = module.TokenBucket(1, 0, clock=lambda: 0.0)
        self.assertFalse(bucket.take(2))
        self.assertTrue(bucket.take(1))

    def test_cli_replays_a_timeline(self):
        module = load_script("token_bucket.py")
        results = module.run(2, 1, [(0, 1), (0, 1), (0, 1), (1, 1)])
        self.assertEqual(results, [True, True, False, True])
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = module.main(
                [
                    "--capacity",
                    "2",
                    "--refill-per-second",
                    "1",
                    "--event",
                    "0:1",
                    "--event",
                    "0:1",
                    "--event",
                    "0:1",
                    "--event",
                    "1:1",
                ]
            )
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue().splitlines(), ["allow", "allow", "deny", "allow"])


class ExportScrubTests(unittest.TestCase):
    def test_each_generic_shape_is_redacted(self):
        module = load_script("export_scrub.py")
        samples = {
            "email": "ada@example.com",
            "phone": "+1 202 555 0147",
            "uuid": "00000000-0000-4000-8000-000000000000",
            "private-key": "-----BEGIN PRIVATE KEY-----",
            "labeled-secret": "api_key: orbitlanternexample1",
            "project-id": "prj_example1234567890",
            "team-id": "team_example1234567890",
            "hex-wallet": HEX_WALLET,
            "opaque-wallet": OPAQUE_WALLET,
        }
        self.assertEqual(set(samples), {name for name, _pattern in module.PATTERNS})
        for name, sample in samples.items():
            self.assertIn(name, module.hits(sample), sample)
            cleaned = module.scrub(sample)
            self.assertNotIn(sample, cleaned, sample)
            self.assertIn("[redacted]", cleaned)

    def test_optional_phrase_file_and_a_clean_fixture(self):
        module = load_script("export_scrub.py")
        clean = (KIT / "examples" / "clean-note.txt").read_text(encoding="utf-8")
        self.assertEqual(module.scrub(clean), clean)
        self.assertEqual(module.load_phrases(Path("phrases.local.txt")), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            note = root / "note.txt"
            note.write_text("A quiet note about a Crimson Widget on the table.\n", encoding="utf-8")
            phrases = root / "phrases.local.txt"
            phrases.write_text("# note\n\ncrimson widget\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = module.main(["--input", str(note), "--phrases", str(phrases)])
            self.assertEqual(code, 0)
            self.assertNotIn("Crimson Widget", stdout.getvalue())
            self.assertIn("[redacted]", stdout.getvalue())
            scrubbed = module.scrub(note.read_text(encoding="utf-8"), module.load_phrases(phrases))
            self.assertNotIn("Crimson Widget", scrubbed)
            self.assertIn("[redacted]", scrubbed)
            self.assertEqual(module.main(["--input", str(note), "--phrases", str(root / "missing.txt")]), 2)
            self.assertEqual(module.main(["--input", str(root / "missing.txt")]), 2)

    def test_kit_text_has_no_generic_hits(self):
        module = load_script("export_scrub.py")
        hits = []
        for path in sorted(KIT.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            text = path.read_text(encoding="utf-8")
            found = module.hits(text)
            if found or module.scrub(text) != text:
                hits.append(f"{path.relative_to(ROOT)} {found}")
        self.assertEqual(hits, [])

    def test_real_phrases_stay_untracked(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("phrases.local.txt", ignore)


if __name__ == "__main__":
    unittest.main()
