import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import leakcheck  # noqa: E402

SAMPLES = HERE.parent / "samples"


def kinds(findings):
    return sorted((f.kind, f.label) for f in findings)


class TestSecrets(unittest.TestCase):
    def test_aws_key(self):
        found = leakcheck.scan_text("key=AKIAIOSFODNN7EXAMPLE", "t")
        self.assertIn(("SECRET", "AWS access key ID"), kinds(found))

    def test_connection_string_password(self):
        found = leakcheck.scan_text("postgres://app:hunter2@db.internal:5432/main", "t")
        self.assertIn(("SECRET", "Password in connection string"), kinds(found))

    def test_url_without_credentials_is_ignored(self):
        self.assertEqual(leakcheck.scan_text("see https://example.com/docs", "t"), [])

    def test_private_key_header(self):
        found = leakcheck.scan_text("-----BEGIN RSA PRIVATE KEY-----", "t")
        self.assertIn(("SECRET", "Private key block"), kinds(found))


class TestPII(unittest.TestCase):
    def test_valid_test_card_is_flagged(self):
        found = leakcheck.scan_text("card 4111 1111 1111 1111", "t")
        self.assertIn(("PII", "Card number"), kinds(found))

    def test_luhn_rejects_random_digits(self):
        self.assertFalse(leakcheck.luhn_valid("4111 1111 1111 1112"))
        self.assertEqual(leakcheck.scan_text("tracking 4111111111111112", "t"), [])

    def test_order_number_is_not_a_phone(self):
        self.assertEqual(leakcheck.scan_text("Order 1234567890 shipped", "t"), [])

    def test_formatted_phone_is_flagged(self):
        found = leakcheck.scan_text("call +1 415 555 0134", "t")
        self.assertIn(("PII", "Phone number"), kinds(found))


class TestMasking(unittest.TestCase):
    """The scanner must never become the leak."""

    def test_full_secret_never_appears_in_text_report(self):
        out = self._run([str(SAMPLES / "leaky_request.json")])
        for value in ("AKIAIOSFODNN7EXAMPLE", "Summer2026!", "4111 1111 1111 1111", "jane.doe@globex.example"):
            self.assertNotIn(value, out)

    def test_full_secret_never_appears_in_json_report(self):
        out = self._run([str(SAMPLES / "leaky_request.json"), "--json"])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)
        self.assertNotIn("Summer2026!", out)

    def test_short_values_are_fully_masked(self):
        self.assertEqual(leakcheck.mask("abc123"), "****")

    @staticmethod
    def _run(argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            leakcheck.main(argv)
        return buf.getvalue()


class TestRedact(unittest.TestCase):
    def test_redacts_every_finding(self):
        text = "card 4111 1111 1111 1111, db postgres://u:p4ss@h/db"
        out = leakcheck.redact(text)
        self.assertNotIn("4111", out)
        self.assertNotIn("p4ss", out)
        self.assertIn("[REDACTED:CARD_NUMBER]", out)

    def test_clean_text_is_unchanged(self):
        self.assertEqual(leakcheck.redact("nothing to see here"), "nothing to see here")


class TestRequestChecks(unittest.TestCase):
    def test_leaky_sample(self):
        req = leakcheck.load_request(str(SAMPLES / "leaky_request.json"))
        found = leakcheck.check_request(req)
        self.assertEqual(len(found), 7)
        self.assertEqual({f.kind for f in found}, {"SECRET", "PII", "ACCESS", "CANARY"})

    def test_clean_sample_passes(self):
        req = leakcheck.load_request(str(SAMPLES / "clean_request.json"))
        self.assertEqual(leakcheck.check_request(req), [])

    def test_cross_tenant_document(self):
        req = {
            "requesting_user": {"id": "u1", "tenant": "acme"},
            "context_parts": [{"source": "rag", "name": "doc", "owner_tenant": "globex", "content": "hello"}],
        }
        self.assertEqual([f.kind for f in leakcheck.check_request(req)], ["ACCESS"])

    def test_canary_only_checked_in_response(self):
        req = {
            "requesting_user": {"id": "u1", "tenant": "acme"},
            "canary": "CANARY-x",
            "context_parts": [{"source": "system", "name": "sp", "content": "CANARY-x be nice"}],
            "model_response": "Hi! How can I help?",
        }
        self.assertEqual(leakcheck.check_request(req), [])


class TestExitCodes(unittest.TestCase):
    def run_main(self, argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return leakcheck.main(argv)

    def test_findings_exit_1(self):
        self.assertEqual(self.run_main([str(SAMPLES / "leaky_request.json")]), 1)

    def test_clean_exit_0(self):
        self.assertEqual(self.run_main([str(SAMPLES / "clean_request.json")]), 0)

    def test_missing_file_exit_2(self):
        self.assertEqual(self.run_main(["does-not-exist.json"]), 2)

    def test_malformed_request_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"requesting_user": {"id": "u1"}}, f)
        self.assertEqual(self.run_main([f.name]), 2)


if __name__ == "__main__":
    unittest.main()
