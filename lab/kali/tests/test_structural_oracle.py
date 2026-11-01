import unittest

from structural_oracle import classify, expected_label


def sample(category, profile, variant="default", events=()):
    return {
        "category": category,
        "profile": profile,
        "variant": variant,
        "events": [{"event_type": "experiment_complete"}, *events],
    }


class StructuralOracleTests(unittest.TestCase):
    def assert_case(self, category, profile, variant="default", event=None, expected=None):
        result = sample(category, profile, variant, [event] if event else [])
        prediction, _reason = classify(result)
        self.assertEqual(prediction, expected)
        self.assertEqual(expected_label(result), expected)

    def test_mcp01_canary_flow_and_block(self):
        self.assert_case("MCP01", "vulnerable", event={
            "event_type": "shadow_server_contact", "canary_seen": True
        }, expected="ATTACK_SUCCESS")
        self.assert_case("MCP01", "hardened", event={
            "event_type": "policy_block", "category": "MCP01"
        }, expected="ATTACK_BLOCKED")

    def test_mcp02_scope_escalation_and_control(self):
        self.assert_case("MCP02", "vulnerable", "read_scope", {
            "event_type": "authorization_decision", "allowed": True,
            "violation": True,
        }, "ATTACK_SUCCESS")
        self.assert_case("MCP02", "hardened", "read_scope", {
            "event_type": "authorization_decision", "allowed": False,
        }, "ATTACK_BLOCKED")
        self.assert_case("MCP02", "vulnerable", "write_control", {
            "event_type": "authorization_decision", "allowed": True,
            "requested_scope": "records.write",
        }, "CONTROL_ALLOWED")
        self.assert_case("MCP02", "hardened", "write_control", {
            "event_type": "authorization_decision", "allowed": True,
            "requested_scope": "records.write",
        }, "CONTROL_ALLOWED")

    def test_mcp07_all_invalid_credentials_and_valid_control(self):
        invalid_cases = ("missing", "invalid", "expired", "wrong_audience")
        for variant in invalid_cases:
            with self.subTest(profile="vulnerable", variant=variant):
                self.assert_case("MCP07", "vulnerable", variant, {
                    "event_type": "protected_operation", "allowed": True,
                    "token_case": variant,
                }, "ATTACK_SUCCESS")
            with self.subTest(profile="hardened", variant=variant):
                self.assert_case("MCP07", "hardened", variant, {
                    "event_type": "mcp_request_rejected",
                }, "ATTACK_BLOCKED")
        for profile in ("vulnerable", "hardened"):
            with self.subTest(profile=profile, variant="valid"):
                self.assert_case("MCP07", profile, "valid", {
                    "event_type": "protected_operation", "allowed": True,
                    "token_case": "valid_read",
                }, "CONTROL_ALLOWED")

    def test_mcp09_unapproved_server_and_block(self):
        self.assert_case("MCP09", "vulnerable", event={
            "event_type": "shadow_server_contact", "approved": False
        }, expected="ATTACK_SUCCESS")
        self.assert_case("MCP09", "hardened", event={
            "event_type": "policy_block", "category": "MCP09"
        }, expected="ATTACK_BLOCKED")

    def test_missing_or_failed_evidence_is_inconclusive(self):
        for result in (
            sample("MCP01", "vulnerable"),
            {**sample("MCP01", "vulnerable"), "events": [
                {"event_type": "experiment_complete"}, {"event_type": "agent_error"}
            ]},
        ):
            self.assertEqual(classify(result)[0], "INCONCLUSIVE")

    def test_expected_label_rejects_unknown_profile(self):
        with self.assertRaises(ValueError):
            expected_label(sample("MCP01", "unknown"))


if __name__ == "__main__":
    unittest.main()
