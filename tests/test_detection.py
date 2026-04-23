from __future__ import annotations

import unittest

from nordis_smb_inspector.core.detection import (
    DEFAULT_DETECTION_RULES,
    DetectionConfidence,
    DetectionRule,
    detect_patterns,
)


class DetectionRuleTests(unittest.TestCase):
    def test_default_rule_ids_are_unique_and_have_safe_representations(self) -> None:
        ids = [rule.rule_id for rule in DEFAULT_DETECTION_RULES]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 15)
        for rule in DEFAULT_DETECTION_RULES:
            self.assertIn("pattern=<redacted>", repr(rule))
            self.assertNotIn(rule.pattern, repr(rule))

    def test_rejects_invalid_rule_metadata_and_secret_groups(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule ID"):
            DetectionRule(
                rule_id="Invalid ID",
                title="Rule",
                category="Test",
                confidence=DetectionConfidence.HIGH,
                pattern="value",
            )
        with self.assertRaisesRegex(ValueError, "pattern"):
            DetectionRule(
                rule_id="broken-regex",
                title="Rule",
                category="Test",
                confidence=DetectionConfidence.HIGH,
                pattern="(",
            )
        with self.assertRaisesRegex(ValueError, "secret group"):
            DetectionRule(
                rule_id="missing-group",
                title="Rule",
                category="Test",
                confidence=DetectionConfidence.HIGH,
                pattern="value",
                secret_group="secret",
            )


class PatternDetectionTests(unittest.TestCase):
    def assert_rule(self, line: str, rule_id: str) -> None:
        matches = detect_patterns(line, 7)
        selected = [match for match in matches if match.rule_id == rule_id]

        self.assertTrue(selected, f"{rule_id} did not match")
        self.assertTrue(all(match.line_number == 7 for match in selected))
        self.assertTrue(all(match.line == line for match in selected))
        self.assertTrue(all(line[match.start : match.end] for match in selected))

    def test_cloud_session_and_key_patterns(self) -> None:
        cases = (
            ("access_key=AKIAABCDEFGHIJKLMNOP", "cloud-access-key"),
            ("token=eyJabcdefghijk.eyJabcdefghijkl.ABCDEFGHIJKL", "jwt-token"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-header"),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz.123", "authorization-bearer"),
            ("Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=", "authorization-basic"),
        )
        for line, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                self.assert_rule(line, rule_id)

    def test_configuration_and_database_patterns(self) -> None:
        cases = (
            ("postgres://alice:RealPassword!@db01/app", "credential-url"),
            ("Server=db01;User Id=app;Password=RealPassword!;", "connection-string-password"),
            ("client_secret = n0t-a-placeholder-value", "secret-assignment"),
            ("<Properties cpassword=\"AbCdEf1234567890==\" />", "gpp-cpassword"),
        )
        for line, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                self.assert_rule(line, rule_id)

    def test_credential_artifact_patterns(self) -> None:
        lm = "aad3b435b51404eeaad3b435b51404ee"
        nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
        cases = (
            (f"$krb5tgs$23$alice$REALM$spn$deadbeef{'a' * 30}", "kerberos-tgs-artifact"),
            (f"$krb5asrep$18$alice@REALM:{'a' * 64}", "kerberos-asrep-artifact"),
            (f"$krb5pa$17$alice$REALM${'b' * 40}", "kerberos-preauth-artifact"),
            (f"{lm}:{nt}", "lm-nt-hash-pair"),
            (f"alice:1001:{lm}:{nt}:::", "credential-dump-line"),
            (f"alice::DOMAIN:1122334455667788:{'a' * 32}:{'b' * 64}", "netntlmv2-response"),
            (f"$DCC2$10240#alice#{nt}", "dcc2-hash"),
            ("$6$roundsalt$abcdefghijklmnopqrstuv0123456789", "unix-password-hash"),
            (
                "$2b$12$abcdefghijklmnopqrstuvwxyzABCDE1234567890abcdefghijkl",
                "modern-password-hash",
            ),
            (
                "$argon2id$v=19$m=65536,t=3,p=4$YWJjZGVmZw$YWJjZGVmZ2hpamtsbW5vcA",
                "modern-password-hash",
            ),
        )
        for line, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                self.assert_rule(line, rule_id)

    def test_common_placeholder_values_and_unlabelled_md5_are_ignored(self) -> None:
        cases = (
            "password=changeme",
            "client_secret='placeholder'",
            "d41d8cd98f00b204e9800998ecf8427e",
            "https://example.test/no-credential",
            "eyJ.short.token",
        )
        for line in cases:
            with self.subTest(line=line):
                self.assertEqual((), detect_patterns(line, 1))

    def test_match_repr_redacts_source_line(self) -> None:
        match = detect_patterns("password=DoNotLeakThisValue", 3)[0]

        rendered = repr(match)
        self.assertIn("redacted", rendered)
        self.assertNotIn("DoNotLeakThisValue", rendered)

    def test_per_rule_match_count_is_bounded(self) -> None:
        line = " ".join(f"AKIA{'A' * 15}{index % 10}" for index in range(40))

        matches = [
            match for match in detect_patterns(line, 1) if match.rule_id == "cloud-access-key"
        ]

        self.assertEqual(32, len(matches))

    def test_input_types_are_validated(self) -> None:
        with self.assertRaises(TypeError):
            detect_patterns(b"password=value", 1)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            detect_patterns("password=value", True)
        with self.assertRaises(ValueError):
            detect_patterns("password=value", 0)
        with self.assertRaises(TypeError):
            detect_patterns("password=value", 1, rules=[])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
