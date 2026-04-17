from __future__ import annotations

import unittest

from nordis_smb_inspector.core.credentials import (
    AuthMode,
    Credential,
    CredentialKind,
    CredentialValidationError,
)


class CredentialTests(unittest.TestCase):
    def test_password_repr_is_redacted(self) -> None:
        credential = Credential.from_password(
            username="audit.user",
            password="DoNotLeakThis",
            domain="NORDIS.LOCAL",
        )

        rendered = repr(credential)

        self.assertNotIn("DoNotLeakThis", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertTrue(credential.ntlm_fallback_available)

    def test_nt_hash_accepts_lm_nt_pair_and_keeps_only_nt_hash(self) -> None:
        credential = Credential.from_nt_hash(
            username="audit.user",
            domain="NORDIS",
            nt_hash=(
                "aad3b435b51404eeaad3b435b51404ee:"
                "8846f7eaee8fb117ad06bdd830b7586c"
            ),
        )

        self.assertEqual(credential.kind, CredentialKind.NT_HASH)
        self.assertEqual(credential.nt_hash, "8846f7eaee8fb117ad06bdd830b7586c")

    def test_nt_hash_rejects_kerberos_artifact(self) -> None:
        with self.assertRaises(CredentialValidationError):
            Credential.from_nt_hash(
                username="audit.user",
                domain="NORDIS",
                nt_hash="$krb5tgs$23$not-an-nt-hash",
            )

    def test_ccache_forces_kerberos_and_has_no_ntlm_fallback(self) -> None:
        credential = Credential.from_ccache(
            filename="../../private/ticket.ccache",
            data=b"\x05\x04ticket",
        )

        self.assertEqual(credential.auth_mode, AuthMode.KERBEROS_ONLY)
        self.assertFalse(credential.ntlm_fallback_available)
        self.assertEqual(credential.ccache_name, "ticket.ccache")
        self.assertNotIn("ticket", repr(credential))

    def test_nt_hash_is_restricted_to_ntlm(self) -> None:
        with self.assertRaises(CredentialValidationError):
            Credential.from_nt_hash(
                username="audit.user",
                domain="NORDIS",
                nt_hash="8846f7eaee8fb117ad06bdd830b7586c",
                auth_mode=AuthMode.AUTO,
            )

    def test_runtime_enum_misuse_is_rejected_early(self) -> None:
        with self.assertRaises(CredentialValidationError):
            Credential(
                kind=CredentialKind.PASSWORD,
                auth_mode="auto",  # type: ignore[arg-type]
                username="audit.user",
                password="DoNotLeakThis",
            )

    def test_non_text_form_values_are_validation_errors(self) -> None:
        with self.assertRaises(CredentialValidationError):
            Credential.from_password(
                username=123,  # type: ignore[arg-type]
                domain="NORDIS",
                password="secret",
            )
        with self.assertRaises(CredentialValidationError):
            Credential.from_ccache(
                filename="ticket.ccache",
                data="not bytes",  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
