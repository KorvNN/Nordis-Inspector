from __future__ import annotations

import errno
import unittest

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb.cancellation import NEVER_CANCELLED, CancellationFlag
from nordis_smb_inspector.smb.impacket_discovery import (
    ImpacketShareDiscoverer,
    ImpacketShareDiscoveryError,
)
from nordis_smb_inspector.smb.models import AuthMechanism, TargetStatus


class _SessionError(Exception):
    def __init__(self, code: int) -> None:
        super().__init__("DoNotLeakNativeError")
        self.code = code

    def getErrorCode(self) -> int:
        return self.code


class _Connection:
    def __init__(
        self,
        *,
        shares: tuple[object, ...] = (),
        error: BaseException | None = None,
    ) -> None:
        self.shares = shares
        self.error = error
        self.login_calls: list[tuple[object, ...]] = []
        self.kerberos_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.closed = False

    def login(self, *args: object) -> None:
        self.login_calls.append(args)
        if self.error is not None:
            raise self.error

    def kerberosLogin(self, *args: object, **kwargs: object) -> None:
        self.kerberos_calls.append((args, kwargs))
        if self.error is not None:
            raise self.error

    def listShares(self) -> tuple[object, ...]:
        if self.error is not None:
            raise self.error
        return self.shares

    def close(self) -> None:
        self.closed = True


class _ConnectionFactory:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> _Connection:
        self.calls.append(kwargs)
        return self.connection


class _PrincipalPart:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def __getitem__(self, key: str) -> bytes:
        if key != "data":
            raise KeyError(key)
        return self.value


class _Principal:
    realm = _PrincipalPart(b"NORDIS.TEST")
    components = (_PrincipalPart(b"alice"),)


class _Ticket:
    def __init__(self, kind: str) -> None:
        self.kind = kind

    def toTGS(self, principal: str) -> dict[str, str]:
        return {"kind": self.kind, "principal": principal}

    def toTGT(self) -> dict[str, str]:
        return {"kind": self.kind}


class _Cache:
    principal = _Principal()

    def __init__(self, *, ticket: _Ticket | None) -> None:
        self.ticket = ticket
        self.queries: list[str] = []

    def getCredential(self, principal: str) -> _Ticket | None:
        self.queries.append(principal)
        return self.ticket if principal.startswith("CIFS/") else None


def _password() -> Credential:
    return Credential.from_password(
        username="alice",
        password="DoNotLeakPassword",
        domain="NORDIS",
        auth_mode=AuthMode.NTLM_ONLY,
    )


class ImpacketShareDiscoveryTests(unittest.TestCase):
    def test_custom_port_is_validated_and_forwarded(self) -> None:
        connection = _Connection(shares=({"shi1_netname": "Data\x00"},))
        factory = _ConnectionFactory(connection)

        ImpacketShareDiscoverer(port=1445, connection_factory=factory).discover(
            target="192.0.2.10",
            credential=_password(),
            kerberos_hostname=None,
            mechanism=AuthMechanism.NTLM,
            timeout_seconds=5,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(1445, factory.calls[0]["sess_port"])
        for invalid in (0, 65536, -1):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError,
                r"^port must be between 1 and 65535\.$",
            ):
                ImpacketShareDiscoverer(port=invalid)
        for invalid in (True, 445.0, "445"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                TypeError,
                r"^port must be an integer\.$",
            ):
                ImpacketShareDiscoverer(port=invalid)  # type: ignore[arg-type]

    def test_ntlm_password_enumerates_deduplicated_safe_names_and_closes(self) -> None:
        connection = _Connection(
            shares=(
                {"shi1_netname": "Public\x00"},
                {"shi1_netname": "public\x00"},
                {"shi1_netname": "Finance\x00"},
                {"shi1_netname": "bad\\name\x00"},
                {"wrong": "ignored"},
            )
        )
        factory = _ConnectionFactory(connection)
        discoverer = ImpacketShareDiscoverer(connection_factory=factory)

        result = discoverer.discover(
            target="192.0.2.10",
            credential=_password(),
            kerberos_hostname=None,
            mechanism=AuthMechanism.NTLM,
            timeout_seconds=4,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(("Public", "Finance"), result.names)
        self.assertEqual(AuthMechanism.NTLM, result.mechanism)
        self.assertEqual("192.0.2.10", factory.calls[0]["remoteName"])
        self.assertEqual(
            ("alice", "DoNotLeakPassword", "NORDIS", "", "", False),
            connection.login_calls[0],
        )
        self.assertTrue(connection.closed)
        self.assertNotIn("Public", repr(result))

    def test_nt_hash_uses_ntlm_pass_the_hash_without_password(self) -> None:
        connection = _Connection(shares=({"shi1_netname": "Data\x00"},))
        credential = Credential.from_nt_hash(
            username="NORDIS\\alice",
            nt_hash="31d6cfe0d16ae931b73c59d7e0c089c0",
            domain=None,
        )

        ImpacketShareDiscoverer(connection_factory=lambda **_kwargs: connection).discover(
            target="192.0.2.10",
            credential=credential,
            kerberos_hostname=None,
            mechanism=AuthMechanism.NTLM,
            timeout_seconds=5,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual("alice", connection.login_calls[0][0])
        self.assertEqual("", connection.login_calls[0][1])
        self.assertEqual("NORDIS", connection.login_calls[0][2])
        self.assertEqual(credential.nt_hash, connection.login_calls[0][4])

    def test_password_kerberos_uses_verified_hostname_and_no_cache_lookup(self) -> None:
        connection = _Connection(shares=({"shi1_netname": "SYSVOL\x00"},))
        factory = _ConnectionFactory(connection)
        credential = Credential.from_password(
            username="alice@NORDIS.TEST",
            password="DoNotLeakPassword",
            domain=None,
            auth_mode=AuthMode.KERBEROS_ONLY,
        )

        ImpacketShareDiscoverer(connection_factory=factory).discover(
            target="192.0.2.10",
            credential=credential,
            kerberos_hostname="dc1.nordis.test",
            mechanism=AuthMechanism.KERBEROS,
            timeout_seconds=5,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual("dc1.nordis.test", factory.calls[0]["remoteName"])
        args, kwargs = connection.kerberos_calls[0]
        self.assertEqual(("alice", "DoNotLeakPassword", "NORDIS.TEST"), args)
        self.assertFalse(kwargs["useCache"])

    def test_ccache_bytes_are_parsed_without_environment_or_disk_file(self) -> None:
        connection = _Connection(shares=({"shi1_netname": "NETLOGON\x00"},))
        cache = _Cache(ticket=_Ticket("tgs"))
        observed_data: list[bytes] = []

        def cache_factory(data: bytes) -> _Cache:
            observed_data.append(data)
            return cache

        credential = Credential.from_ccache(filename="ticket.ccache", data=b"cache-bytes")
        ImpacketShareDiscoverer(
            connection_factory=lambda **_kwargs: connection,
            ccache_factory=cache_factory,
        ).discover(
            target="192.0.2.10",
            credential=credential,
            kerberos_hostname="dc1.nordis.test",
            mechanism=AuthMechanism.KERBEROS,
            timeout_seconds=5,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual([b"cache-bytes"], observed_data)
        args, kwargs = connection.kerberos_calls[0]
        self.assertEqual(("alice", "", "NORDIS.TEST"), args)
        self.assertEqual("tgs", kwargs["TGS"]["kind"])
        self.assertIsNone(kwargs["TGT"])
        self.assertFalse(kwargs["useCache"])

    def test_errors_are_normalized_without_native_text_and_connection_closes(self) -> None:
        connection = _Connection(error=_SessionError(0xC0000022))

        with self.assertRaises(ImpacketShareDiscoveryError) as caught:
            ImpacketShareDiscoverer(connection_factory=lambda **_kwargs: connection).discover(
                target="192.0.2.10",
                credential=_password(),
                kerberos_hostname=None,
                mechanism=AuthMechanism.NTLM,
                timeout_seconds=5,
                cancellation=NEVER_CANCELLED,
            )

        self.assertEqual(TargetStatus.SHARE_ENUM_DENIED, caught.exception.detail.status)
        self.assertEqual(0xC0000022, caught.exception.detail.raw_code)
        self.assertNotIn("DoNotLeak", str(caught.exception))
        self.assertTrue(connection.closed)

    def test_timeout_and_generic_errors_are_distinct(self) -> None:
        for error, status, raw_code in (
            (
                TimeoutError(errno.ETIMEDOUT, "DoNotLeak"),
                TargetStatus.SHARE_ENUM_UNAVAILABLE,
                errno.ETIMEDOUT,
            ),
            (RuntimeError("DoNotLeak"), TargetStatus.SHARE_ENUM_FAILED, errno.EPROTO),
        ):
            with self.subTest(status=status):
                connection = _Connection(error=error)
                factory = _ConnectionFactory(connection)
                with self.assertRaises(ImpacketShareDiscoveryError) as caught:
                    ImpacketShareDiscoverer(connection_factory=factory).discover(
                        target="192.0.2.10",
                        credential=_password(),
                        kerberos_hostname=None,
                        mechanism=AuthMechanism.NTLM,
                        timeout_seconds=5,
                        cancellation=NEVER_CANCELLED,
                    )
                self.assertEqual(status, caught.exception.detail.status)
                self.assertEqual(raw_code, caught.exception.detail.raw_code)

    def test_cancellation_before_connect_never_constructs_connection(self) -> None:
        cancellation = CancellationFlag()
        cancellation.cancel()

        with self.assertRaises(Exception) as caught:
            ImpacketShareDiscoverer(
                connection_factory=lambda **_kwargs: self.fail("must not connect")
            ).discover(
                target="192.0.2.10",
                credential=_password(),
                kerberos_hostname=None,
                mechanism=AuthMechanism.NTLM,
                timeout_seconds=5,
                cancellation=cancellation,
            )

        self.assertEqual("ScanCancelled", type(caught.exception).__name__)

    def test_kerberos_requires_verified_hostname(self) -> None:
        with self.assertRaises(ImpacketShareDiscoveryError) as caught:
            ImpacketShareDiscoverer(connection_factory=lambda **_kwargs: self.fail()).discover(
                target="192.0.2.10",
                credential=_password(),
                kerberos_hostname=None,
                mechanism=AuthMechanism.KERBEROS,
                timeout_seconds=5,
                cancellation=NEVER_CANCELLED,
            )

        self.assertEqual("KERBEROS_HOSTNAME_REQUIRED", caught.exception.detail.symbolic_name)


if __name__ == "__main__":
    unittest.main()
