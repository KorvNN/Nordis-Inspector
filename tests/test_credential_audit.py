from __future__ import annotations

import unittest

from nordis_smb_inspector.core.credential_audit import classify_audit_material


class CredentialAuditClassificationTests(unittest.TestCase):
    def test_extracts_nt_hash_without_exposing_it_in_repr_or_metadata(self) -> None:
        secret_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

        candidates = classify_audit_material(
            "windows-nt-hash",
            f"NTLM Hash: {secret_hash}",
        )

        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertEqual(secret_hash, candidate.material)
        self.assertEqual("ntlm", candidate.format_id)
        self.assertEqual("1000", candidate.binding_for("hashcat").format_name)
        self.assertEqual("nt", candidate.binding_for("john").format_name)
        self.assertEqual(64, len(candidate.candidate_id))
        self.assertNotIn(secret_hash, repr(candidate))
        self.assertNotIn(secret_hash, str(candidate.public_metadata()))

    def test_account_dump_produces_nt_and_nonempty_lm_variants(self) -> None:
        lm_hash = "e52cac67419a9a224a3b108f3fa6cb6d"
        nt_hash = "8846f7eaee8fb117ad06bdd830b7586c"

        candidates = classify_audit_material(
            "credential-dump-line",
            f"alice:1001:{lm_hash}:{nt_hash}:::",
        )

        self.assertEqual(["nt", "lm"], [candidate.variant for candidate in candidates])
        self.assertEqual([nt_hash, lm_hash], [candidate.material for candidate in candidates])

    def test_empty_lm_component_is_not_presented_as_an_audit_candidate(self) -> None:
        candidates = classify_audit_material(
            "credential-dump-line",
            "alice:1001:aad3b435b51404eeaad3b435b51404ee:"
            "8846f7eaee8fb117ad06bdd830b7586c:::",
        )

        self.assertEqual(["nt"], [candidate.variant for candidate in candidates])

    def test_maps_network_cached_and_unix_formats(self) -> None:
        cases = (
            (
                "netntlmv1-response",
                f"alice::DOMAIN:{'a' * 48}:{'b' * 48}:{'c' * 16}",
                "netntlmv1",
                "5500",
            ),
            (
                "netntlmv2-response",
                f"alice::DOMAIN:1122334455667788:{'a' * 32}:{'b' * 64}",
                "netntlmv2",
                "5600",
            ),
            (
                "dcc2-hash",
                "$DCC2$10240#alice#8846f7eaee8fb117ad06bdd830b7586c",
                "dcc2",
                "2100",
            ),
            (
                "unix-password-hash",
                "$6$roundsalt$abcdefghijklmnopqrstuv0123456789",
                "sha512crypt",
                "1800",
            ),
            (
                "modern-password-hash",
                "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
                "bcrypt",
                "3200",
            ),
            (
                "modern-password-hash",
                "$argon2id$v=19$m=65536,t=3,p=4$YWJjZGVmZw$"
                "YWJjZGVmZ2hpamtsbW5vcA",
                "argon2",
                "34000",
            ),
        )
        for rule_id, line, format_id, hashcat_mode in cases:
            with self.subTest(rule_id=rule_id, format_id=format_id):
                candidate = classify_audit_material(rule_id, line)[0]
                self.assertEqual(format_id, candidate.format_id)
                self.assertEqual(hashcat_mode, candidate.binding_for("hashcat").format_name)

    def test_maps_supported_kerberos_etypes(self) -> None:
        cases = (
            ("kerberos-tgs-artifact", "$krb5tgs$23$alice$REALM$spn$" + "a" * 40, "13100"),
            ("kerberos-asrep-artifact", "$krb5asrep$18$alice@REALM:" + "a" * 64, "32200"),
            ("kerberos-preauth-artifact", "$krb5pa$17$alice$REALM$" + "b" * 40, "19800"),
            ("kerberos-db-key", "$krb5db$18$alice$REALM$" + "c" * 64, "28900"),
        )
        for rule_id, line, hashcat_mode in cases:
            with self.subTest(rule_id=rule_id):
                candidate = classify_audit_material(rule_id, line)[0]
                self.assertEqual(hashcat_mode, candidate.binding_for("hashcat").format_name)
                self.assertIsNotNone(candidate.binding_for("john"))

    def test_plaintext_binary_unknown_and_malformed_findings_are_not_candidates(self) -> None:
        cases: tuple[tuple[object, object], ...] = (
            ("secret-assignment", "password=AlreadyPlaintext"),
            ("kerberos-ccache-file", None),
            ("kerberos-aes256-key", "aes256_hmac: " + "a" * 64),
            ("windows-nt-hash", "NTLM: not-a-hash"),
            ("unknown-rule", "$6$salt$abcdefghijklmnop"),
            (None, "text"),
            ("windows-nt-hash", "x" * (256 * 1024 + 1)),
        )
        for rule_id, line in cases:
            with self.subTest(rule_id=rule_id):
                self.assertEqual((), classify_audit_material(rule_id, line))


if __name__ == "__main__":
    unittest.main()
