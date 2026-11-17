import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import agencycheck  # noqa: E402

SAMPLES = HERE.parent / "samples"
OVER = str(SAMPLES / "overprivileged_agent.json")
LEAST = str(SAMPLES / "least_privilege_agent.json")
SESSION = str(SAMPLES / "injected_session.json")


def base_manifest():
    """Smallest valid manifest that passes the audit."""
    return {
        "agent": "test-agent",
        "needs": [
            {"capability": "orders.read", "scope": "own"},
            {"capability": "refunds.create", "scope": "own", "max_amount": 100},
        ],
        "max_steps": 5,
        "tools": [
            {"name": "lookup_order", "grants": [{"capability": "orders.read", "scope": "own"}]},
            {"name": "issue_refund",
             "grants": [{"capability": "refunds.create", "scope": "own", "max_amount": 100}]},
        ],
    }


def tool(manifest, name):
    return next(t for t in manifest["tools"] if t["name"] == name)


def kinds(findings):
    return sorted((f.kind, f.tool) for f in findings)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = agencycheck.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestAuditFunction(unittest.TestCase):
    def test_least_privilege_manifest_passes(self):
        self.assertEqual(agencycheck.audit(base_manifest()), [])

    def test_unneeded_tool_is_flagged_once(self):
        m = base_manifest()
        m["tools"].append({"name": "send_email", "grants": [{"capability": "email.send", "scope": "all"}],
                           "credential": "service"})
        # One finding: removing the tool fixes its scope and credential too.
        self.assertEqual(kinds(agencycheck.audit(m)), [("FUNCTION", "send_email")])

    def test_open_ended_tool_is_flagged_even_when_needed(self):
        m = base_manifest()
        tool(m, "lookup_order")["open_ended"] = True
        self.assertIn(("FUNCTION", "lookup_order"), kinds(agencycheck.audit(m)))


class TestAuditPermission(unittest.TestCase):
    def test_extra_capability_on_needed_tool(self):
        m = base_manifest()
        tool(m, "lookup_order")["grants"].append({"capability": "orders.delete", "scope": "own"})
        findings = agencycheck.audit(m)
        self.assertEqual(kinds(findings), [("PERMISSION", "lookup_order")])
        self.assertIn("orders.delete", findings[0].message)

    def test_scope_broader_than_need(self):
        m = base_manifest()
        tool(m, "lookup_order")["grants"][0]["scope"] = "tenant"
        self.assertEqual(kinds(agencycheck.audit(m)), [("PERMISSION", "lookup_order")])

    def test_narrower_scope_is_fine(self):
        m = base_manifest()
        m["needs"][0]["scope"] = "tenant"
        self.assertEqual(agencycheck.audit(m), [])

    def test_missing_limit(self):
        m = base_manifest()
        del tool(m, "issue_refund")["grants"][0]["max_amount"]
        findings = agencycheck.audit(m)
        self.assertEqual(kinds(findings), [("PERMISSION", "issue_refund")])
        self.assertIn("no limit", findings[0].message)

    def test_limit_above_need(self):
        m = base_manifest()
        tool(m, "issue_refund")["grants"][0]["max_amount"] = 5000
        self.assertEqual(kinds(agencycheck.audit(m)), [("PERMISSION", "issue_refund")])

    def test_service_credential_on_user_scoped_tool(self):
        m = base_manifest()
        tool(m, "lookup_order")["credential"] = "service"
        self.assertEqual(kinds(agencycheck.audit(m)), [("PERMISSION", "lookup_order")])

    def test_service_credential_fine_when_scope_is_not_own(self):
        m = base_manifest()
        m["needs"][0]["scope"] = "tenant"
        tool(m, "lookup_order").update(credential="service")
        tool(m, "lookup_order")["grants"][0]["scope"] = "tenant"
        self.assertEqual(agencycheck.audit(m), [])


class TestAuditAutonomy(unittest.TestCase):
    def test_high_impact_without_approval_or_limit(self):
        m = base_manifest()
        m["needs"].append({"capability": "orders.cancel", "scope": "own"})
        m["tools"].append({"name": "cancel_order", "grants": [{"capability": "orders.cancel", "scope": "own"}]})
        self.assertEqual(kinds(agencycheck.audit(m)), [("AUTONOMY", "cancel_order")])

    def test_human_approval_clears_it(self):
        m = base_manifest()
        m["needs"].append({"capability": "orders.cancel", "scope": "own"})
        m["tools"].append({"name": "cancel_order", "approval": "human",
                           "grants": [{"capability": "orders.cancel", "scope": "own"}]})
        self.assertEqual(agencycheck.audit(m), [])

    def test_hard_limit_counts_as_a_guardrail(self):
        # issue_refund in base_manifest is high-impact, but capped at 100.
        self.assertTrue(agencycheck.is_high_impact("refunds.create"))
        self.assertEqual(agencycheck.audit(base_manifest()), [])

    def test_reads_are_not_high_impact(self):
        self.assertFalse(agencycheck.is_high_impact("orders.read"))

    def test_missing_step_budget(self):
        m = base_manifest()
        del m["max_steps"]
        self.assertEqual(kinds(agencycheck.audit(m)), [("AUTONOMY", "agent")])


class TestGate(unittest.TestCase):
    def setUp(self):
        self.m = base_manifest()

    def decide(self, call, manifest=None):
        return agencycheck.gate_call(manifest or self.m, "user_1", call)

    def test_allow_own_data(self):
        d = self.decide({"tool": "lookup_order", "args": {"owner": "user_1"}})
        self.assertEqual(d.decision, "ALLOW")

    def test_deny_unknown_tool(self):
        self.assertEqual(self.decide({"tool": "run_sql"}).decision, "DENY")

    def test_deny_other_users_data(self):
        d = self.decide({"tool": "lookup_order", "args": {"owner": "user_2"}})
        self.assertEqual(d.decision, "DENY")
        self.assertIn("user_2", d.reasons[0])

    def test_fail_closed_without_owner(self):
        self.assertEqual(self.decide({"tool": "lookup_order", "args": {}}).decision, "DENY")

    def test_deny_over_limit(self):
        d = self.decide({"tool": "issue_refund", "args": {"owner": "user_1", "amount": 101}})
        self.assertEqual(d.decision, "DENY")

    def test_allow_at_limit(self):
        d = self.decide({"tool": "issue_refund", "args": {"owner": "user_1", "amount": 100}})
        self.assertEqual(d.decision, "ALLOW")

    def test_deny_non_numeric_amount(self):
        for amount in ("50", None, True):
            d = self.decide({"tool": "issue_refund", "args": {"owner": "user_1", "amount": amount}})
            self.assertEqual(d.decision, "DENY", amount)

    def test_hold_when_tool_needs_approval(self):
        tool(self.m, "issue_refund")["approval"] = "human"
        d = self.decide({"tool": "issue_refund", "args": {"owner": "user_1", "amount": 10}})
        self.assertEqual(d.decision, "HOLD")

    def test_policy_violation_beats_approval(self):
        # Don't ask a human to approve something policy already forbids.
        tool(self.m, "issue_refund")["approval"] = "human"
        d = self.decide({"tool": "issue_refund", "args": {"owner": "user_2", "amount": 10}})
        self.assertEqual(d.decision, "DENY")

    def test_gate_enforces_needs_not_grants(self):
        # The tool is over-granted (scope all, no limit), the gate still holds the line.
        m = copy.deepcopy(self.m)
        tool(m, "issue_refund")["grants"] = [{"capability": "refunds.create", "scope": "all"}]
        d = self.decide({"tool": "issue_refund", "args": {"owner": "user_2", "amount": 9999}}, m)
        self.assertEqual(d.decision, "DENY")
        self.assertEqual(len(d.reasons), 2)

    def test_step_budget(self):
        self.m["max_steps"] = 2
        session = {"requesting_user": {"id": "user_1"},
                   "calls": [{"tool": "lookup_order", "args": {"owner": "user_1"}}] * 3}
        decisions = agencycheck.replay(self.m, session)
        self.assertEqual([d.decision for d in decisions], ["ALLOW", "ALLOW", "DENY"])


class TestSamples(unittest.TestCase):
    def test_overprivileged_sample(self):
        findings = agencycheck.audit(agencycheck.load_manifest(OVER))
        self.assertEqual(len(findings), 10)
        self.assertEqual({f.kind for f in findings}, {"FUNCTION", "PERMISSION", "AUTONOMY"})

    def test_least_privilege_sample(self):
        self.assertEqual(agencycheck.audit(agencycheck.load_manifest(LEAST)), [])

    def test_injected_session_against_least_privilege(self):
        decisions = agencycheck.replay(agencycheck.load_manifest(LEAST), agencycheck.load_session(SESSION))
        self.assertEqual([d.decision for d in decisions], ["ALLOW", "DENY", "DENY", "DENY", "ALLOW", "HOLD"])


class TestValidation(unittest.TestCase):
    def check_rejected(self, manifest, fragment):
        with self.assertRaises(agencycheck.InputError) as ctx:
            agencycheck.validate_manifest(manifest)
        self.assertIn(fragment, str(ctx.exception))

    def test_needs_required(self):
        m = base_manifest()
        m["needs"] = []
        self.check_rejected(m, "needs")

    def test_bad_capability(self):
        m = base_manifest()
        m["needs"][0]["capability"] = "orders"
        self.check_rejected(m, "resource.action")

    def test_bad_scope(self):
        m = base_manifest()
        tool(m, "lookup_order")["grants"][0]["scope"] = "everyone"
        self.check_rejected(m, "scope")

    def test_bad_approval(self):
        m = base_manifest()
        tool(m, "lookup_order")["approval"] = "sometimes"
        self.check_rejected(m, "approval")

    def test_duplicate_tool_name(self):
        m = base_manifest()
        m["tools"].append(copy.deepcopy(m["tools"][0]))
        self.check_rejected(m, "used twice")


class TestCLI(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(run(["audit", OVER])[0], agencycheck.EXIT_FINDINGS)
        self.assertEqual(run(["audit", LEAST])[0], agencycheck.EXIT_CLEAN)
        self.assertEqual(run(["replay", LEAST, SESSION])[0], agencycheck.EXIT_FINDINGS)

    def test_missing_file(self):
        code, _, err = run(["audit", "does-not-exist.json"])
        self.assertEqual(code, agencycheck.EXIT_BAD_INPUT)
        self.assertIn("not found", err)

    def test_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{not json")
        code, _, err = run(["audit", f.name])
        Path(f.name).unlink()
        self.assertEqual(code, agencycheck.EXIT_BAD_INPUT)
        self.assertIn("not valid JSON", err)

    def test_audit_json_output(self):
        _, out, _ = run(["audit", OVER, "--json"])
        data = json.loads(out)
        self.assertEqual(data["verdict"], "excessive")
        self.assertEqual(len(data["findings"]), 10)

    def test_replay_json_output(self):
        _, out, _ = run(["replay", LEAST, SESSION, "--json"])
        data = json.loads(out)
        self.assertEqual(data["verdict"], "denied")
        self.assertEqual(data["decisions"][5]["decision"], "HOLD")


if __name__ == "__main__":
    unittest.main()
