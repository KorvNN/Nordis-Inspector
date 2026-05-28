from __future__ import annotations

import unittest

from nordis_smb_inspector.core.credential_artifacts import (
    credential_artifact_header_bytes,
    detect_credential_artifact,
)


class CredentialArtifactDetectionTests(unittest.TestCase):
    def test_supported_binary_credential_containers_require_name_and_magic(self) -> None:
        cases = (
            ("tickets/admin.ccache", b"\x05\x04\x00\x00header", "kerberos-ccache-file"),
            ("tmp/krb5cc_1000", b"\x05\x03\x00\x00data", "kerberos-ccache-file"),
            ("etc/krb5.keytab", b"\x05\x02\x00\x00\x00\x10", "kerberos-keytab-file"),
            ("tickets/admin.kirbi", b"\x76\x82\x01\x00", "kerberos-kirbi-file"),
        )
        for path, header, expected_rule in cases:
            with self.subTest(path=path):
                match = detect_credential_artifact(path, header)
                self.assertIsNotNone(match)
                self.assertEqual(expected_rule, match.rule_id)

    def test_ccache_and_keytab_version_two_are_disambiguated_by_name(self) -> None:
        header = b"\x05\x02\x00\x00\x00\x10"

        ccache = detect_credential_artifact("alice.ccache", header)
        keytab = detect_credential_artifact("service.keytab", header)

        self.assertEqual("kerberos-ccache-file", ccache.rule_id)
        self.assertEqual("kerberos-keytab-file", keytab.rule_id)

    def test_unlabelled_or_invalid_binary_data_is_ignored(self) -> None:
        cases = (
            ("random.bin", b"\x05\x04\x00\x00"),
            ("fake.ccache", b"not-a-cache"),
            ("fake.keytab", b"\x05\x02"),
            ("fake.kirbi", b"\x30\x82\x01\x00"),
        )
        for path, header in cases:
            with self.subTest(path=path):
                self.assertIsNone(detect_credential_artifact(path, header))

    def test_header_contract_is_small_and_input_types_are_validated(self) -> None:
        self.assertEqual(16, credential_artifact_header_bytes())
        with self.assertRaises(TypeError):
            detect_credential_artifact(b"cache.ccache", b"\x05\x04\x00\x00")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            detect_credential_artifact("cache.ccache", "not-bytes")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
