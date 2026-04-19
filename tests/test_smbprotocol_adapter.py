from __future__ import annotations

import errno
import unittest
import uuid
from dataclasses import dataclass

from nordis_smb_inspector.smb import (
    NEVER_CANCELLED,
    AlgorithmSource,
    ConnectionHandle,
    ConnectRequest,
    ScanCancelled,
    SmbDialect,
    TargetStage,
    TargetStatus,
)
from nordis_smb_inspector.smb.smbprotocol_adapter import (
    NegotiationMetadataError,
    SmbProtocolCloseError,
    SmbProtocolConnectError,
    SmbProtocolConnector,
    classify_connect_exception,
    make_smb1_only_outcome,
    negotiation_info_from_native,
)


@dataclass
class _Transport:
    connected: bool = False


class _NativeConnection:
    def __init__(
        self,
        *,
        dialect: int = 0x0311,
        max_read_size: int | None = 1_048_576,
        server_security_mode: int | None = 0x0003,
        supports_encryption: bool | None = True,
        signing_algorithm_id: int | None = 0x0002,
        cipher_id: int | None = 0x0002,
        connect_error: Exception | None = None,
        connected_before_error: bool = False,
        disconnect_error: Exception | None = None,
    ) -> None:
        self.dialect = dialect
        self.max_read_size = max_read_size
        self.server_security_mode = server_security_mode
        self.supports_encryption = supports_encryption
        self.signing_algorithm_id = signing_algorithm_id
        self.cipher_id = cipher_id
        self.connect_error = connect_error
        self.connected_before_error = connected_before_error
        self.disconnect_error = disconnect_error
        self.transport = _Transport()
        self.connect_calls: list[dict[str, object]] = []
        self.disconnect_calls: list[dict[str, object]] = []

    def connect(self, dialect=None, timeout=60, **kwargs) -> None:
        self.connect_calls.append(
            {"dialect": dialect, "timeout": timeout, "kwargs": dict(kwargs)}
        )
        if self.connect_error is not None:
            self.transport.connected = self.connected_before_error
            raise self.connect_error
        self.transport.connected = True

    def disconnect(self, close=True, timeout=None) -> None:
        self.disconnect_calls.append({"close": close, "timeout": timeout})
        self.transport.connected = False
        if self.disconnect_error is not None:
            raise self.disconnect_error


class _Factory:
    def __init__(self, native: _NativeConnection) -> None:
        self.native = native
        self.calls: list[tuple[uuid.UUID, str, int, bool]] = []

    def __call__(
        self,
        guid: uuid.UUID,
        server_name: str,
        port: int = 445,
        require_signing: bool = True,
    ) -> _NativeConnection:
        self.calls.append((guid, server_name, port, require_signing))
        return self.native


class _FailIfCalledFactory:
    def __init__(self) -> None:
        self.called = False

    def __call__(self, *args, **kwargs) -> _NativeConnection:
        self.called = True
        raise AssertionError("Network factory must not run after cancellation.")


class _CancelOnSecondCheck:
    def __init__(self) -> None:
        self.checks = 0

    @property
    def cancelled(self) -> bool:
        return self.checks >= 2

    def raise_if_cancelled(self) -> None:
        self.checks += 1
        if self.checks >= 2:
            raise ScanCancelled()


class ConnectorTests(unittest.TestCase):
    def test_connector_calls_pinned_native_api_and_returns_narrow_handle(self) -> None:
        native = _NativeConnection()
        factory = _Factory(native)
        fixed_guid = uuid.UUID("b2e41ff1-fd45-4656-9dab-d9959287f384")
        connector = SmbProtocolConnector(
            connection_factory=factory,
            guid_factory=lambda: fixed_guid,
        )
        request = ConnectRequest(
            target="10.20.30.40",
            port=1445,
            timeout_seconds=3.25,
            require_signing=True,
            require_encryption=True,
            require_secure_negotiate=True,
        )

        handle = connector.connect(request, cancellation=NEVER_CANCELLED)

        self.assertIsInstance(handle, ConnectionHandle)
        self.assertEqual(factory.calls, [(fixed_guid, "10.20.30.40", 1445, True)])
        self.assertEqual(
            native.connect_calls,
            [{"dialect": None, "timeout": 3.25, "kwargs": {}}],
        )
        self.assertIs(handle.negotiation.dialect, SmbDialect.SMB_3_1_1)
        self.assertEqual(handle.negotiation.max_read_size, 1_048_576)
        self.assertTrue(handle.require_encryption)
        self.assertTrue(handle.require_secure_negotiate)
        self.assertFalse(hasattr(handle, "send"))
        self.assertFalse(hasattr(handle, "write"))
        self.assertNotIn("10.20.30.40", repr(handle))

    def test_close_is_idempotent_and_hides_native_connection(self) -> None:
        native = _NativeConnection()
        handle = SmbProtocolConnector(connection_factory=_Factory(native)).connect(
            ConnectRequest(target="10.20.30.40"),
            cancellation=NEVER_CANCELLED,
        )

        handle.close()
        handle.close()

        self.assertTrue(handle.closed)
        self.assertEqual(native.disconnect_calls, [{"close": True, "timeout": None}])
        with self.assertRaisesRegex(ValueError, "closed"):
            _ = handle._native_connection

    def test_close_wraps_sensitive_native_error_and_still_marks_handle_closed(self) -> None:
        native = _NativeConnection(
            disconnect_error=RuntimeError("failed closing 10.20.30.40 for alice")
        )
        handle = SmbProtocolConnector(connection_factory=_Factory(native)).connect(
            ConnectRequest(target="10.20.30.40"),
            cancellation=NEVER_CANCELLED,
        )

        with self.assertRaises(SmbProtocolCloseError) as caught:
            handle.close()

        self.assertTrue(handle.closed)
        self.assertNotIn("10.20.30.40", str(caught.exception))
        self.assertNotIn("alice", repr(caught.exception))

    def test_cancellation_before_connect_does_not_construct_native_client(self) -> None:
        factory = _FailIfCalledFactory()

        with self.assertRaises(ScanCancelled):
            from nordis_smb_inspector.smb import CancellationFlag

            cancellation = CancellationFlag()
            cancellation.cancel()
            SmbProtocolConnector(connection_factory=factory).connect(
                ConnectRequest(target="10.20.30.40"),
                cancellation=cancellation,
            )

        self.assertFalse(factory.called)

    def test_cancellation_after_negotiate_discards_native_connection(self) -> None:
        native = _NativeConnection()
        cancellation = _CancelOnSecondCheck()

        with self.assertRaises(ScanCancelled):
            SmbProtocolConnector(connection_factory=_Factory(native)).connect(
                ConnectRequest(target="10.20.30.40"),
                cancellation=cancellation,
            )

        self.assertEqual(native.disconnect_calls, [{"close": True, "timeout": None}])
        self.assertFalse(native.transport.connected)

    def test_connect_failure_is_normalized_and_native_connection_is_discarded(self) -> None:
        refused = ConnectionRefusedError(errno.ECONNREFUSED, "10.20.30.40")
        wrapped = ValueError("Failed to connect to 10.20.30.40")
        wrapped.__cause__ = refused
        native = _NativeConnection(connect_error=wrapped)
        ticks = iter((10.0, 10.4))

        with self.assertRaises(SmbProtocolConnectError) as caught:
            SmbProtocolConnector(
                connection_factory=_Factory(native),
                clock=lambda: next(ticks),
            ).connect(
                ConnectRequest(target="10.20.30.40"),
                cancellation=NEVER_CANCELLED,
            )

        outcome = caught.exception.outcome
        self.assertIs(outcome.stage, TargetStage.NETWORK)
        self.assertIs(outcome.status, TargetStatus.CONNECTION_REFUSED)
        self.assertAlmostEqual(outcome.elapsed_seconds or 0, 0.4)
        self.assertEqual(native.disconnect_calls, [{"close": True, "timeout": None}])
        self.assertNotIn("10.20.30.40", repr(caught.exception))
        self.assertNotIn("10.20.30.40", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_policy_failure_is_negotiate_error_and_closes_transport(self) -> None:
        native = _NativeConnection(
            dialect=0x0210,
            supports_encryption=None,
            signing_algorithm_id=None,
            cipher_id=None,
        )

        with self.assertRaises(SmbProtocolConnectError) as caught:
            SmbProtocolConnector(connection_factory=_Factory(native)).connect(
                ConnectRequest(target="server", require_encryption=True),
                cancellation=NEVER_CANCELLED,
            )

        self.assertIs(caught.exception.outcome.status, TargetStatus.NEGOTIATION_FAILED)
        self.assertEqual(
            str(caught.exception),
            "The server does not support the required SMB encryption policy.",
        )
        self.assertEqual(len(native.disconnect_calls), 1)

    def test_missing_required_signing_support_fails_closed(self) -> None:
        native = _NativeConnection(server_security_mode=0)

        with self.assertRaises(SmbProtocolConnectError) as caught:
            SmbProtocolConnector(connection_factory=_Factory(native)).connect(
                ConnectRequest(target="server", require_signing=True),
                cancellation=NEVER_CANCELLED,
            )

        self.assertEqual(
            str(caught.exception),
            "The server does not support the required SMB signing policy.",
        )


class NegotiationMetadataTests(unittest.TestCase):
    def test_all_supported_dialects_are_normalized(self) -> None:
        cases = (
            (0x0202, SmbDialect.SMB_2_0_2, "HMAC-SHA256", False),
            (0x0210, SmbDialect.SMB_2_1, "HMAC-SHA256", False),
            (0x0300, SmbDialect.SMB_3_0, "AES-128-CMAC", True),
            (0x0302, SmbDialect.SMB_3_0_2, "AES-128-CMAC", True),
            (0x0311, SmbDialect.SMB_3_1_1, "AES-128-GMAC", True),
        )
        for dialect, expected, signing_algorithm, supports_encryption in cases:
            with self.subTest(dialect=hex(dialect)):
                native = _NativeConnection(
                    dialect=dialect,
                    supports_encryption=supports_encryption if dialect >= 0x0300 else None,
                )
                result = negotiation_info_from_native(native)
                self.assertIs(result.dialect, expected)
                self.assertEqual(result.security.signing.algorithm, signing_algorithm)
                self.assertIs(
                    result.security.encryption.supported,
                    supports_encryption,
                )

    def test_signing_support_requirement_and_active_are_distinct(self) -> None:
        supported = negotiation_info_from_native(
            _NativeConnection(server_security_mode=0x0001)
        ).security.signing
        required = negotiation_info_from_native(
            _NativeConnection(server_security_mode=0x0002)
        ).security.signing

        self.assertTrue(supported.supported)
        self.assertFalse(supported.required)
        self.assertIsNone(supported.active)
        self.assertTrue(required.supported)
        self.assertTrue(required.required)
        self.assertIsNone(required.active)

    def test_smb311_algorithms_are_reported_as_negotiated(self) -> None:
        result = negotiation_info_from_native(
            _NativeConnection(signing_algorithm_id=0x0001, cipher_id=0x0004)
        )

        self.assertEqual(result.security.signing.algorithm, "AES-128-CMAC")
        self.assertIs(
            result.security.signing.algorithm_source,
            AlgorithmSource.NEGOTIATED,
        )
        self.assertEqual(result.security.encryption.algorithm, "AES-256-GCM")
        self.assertIs(
            result.security.encryption.algorithm_source,
            AlgorithmSource.NEGOTIATED,
        )
        self.assertIsNone(result.security.encryption.required)
        self.assertIsNone(result.security.encryption.active)

    def test_smb30_algorithms_are_dialect_inferred(self) -> None:
        result = negotiation_info_from_native(
            _NativeConnection(dialect=0x0302, signing_algorithm_id=None, cipher_id=None)
        )

        self.assertIs(
            result.security.signing.algorithm_source,
            AlgorithmSource.DIALECT_INFERRED,
        )
        self.assertEqual(result.security.encryption.algorithm, "AES-128-CCM")
        self.assertIs(
            result.security.encryption.algorithm_source,
            AlgorithmSource.DIALECT_INFERRED,
        )

    def test_unsupported_dialect_and_invalid_sizes_fail_closed(self) -> None:
        with self.assertRaisesRegex(NegotiationMetadataError, "unsupported SMB dialect"):
            negotiation_info_from_native(_NativeConnection(dialect=0x0100))
        with self.assertRaisesRegex(NegotiationMetadataError, "read size"):
            negotiation_info_from_native(_NativeConnection(max_read_size=0))
        with self.assertRaisesRegex(NegotiationMetadataError, "dialect metadata"):
            negotiation_info_from_native(_NativeConnection(dialect=True))

    def test_unknown_smb311_algorithms_fail_closed(self) -> None:
        with self.assertRaisesRegex(NegotiationMetadataError, "signing algorithm"):
            negotiation_info_from_native(_NativeConnection(signing_algorithm_id=99))
        with self.assertRaisesRegex(NegotiationMetadataError, "encryption algorithm"):
            negotiation_info_from_native(_NativeConnection(cipher_id=99))

    def test_no_signing_support_carries_no_algorithm(self) -> None:
        signing = negotiation_info_from_native(
            _NativeConnection(server_security_mode=0)
        ).security.signing
        self.assertFalse(signing.supported)
        self.assertIsNone(signing.algorithm)
        self.assertIsNone(signing.algorithm_source)


class FailureClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = ConnectRequest(target="10.20.30.40")

    def test_wrapped_connection_refused_retains_errno_without_exception_text(self) -> None:
        wrapped = ValueError("Failed to connect to 10.20.30.40")
        wrapped.__cause__ = ConnectionRefusedError(
            errno.ECONNREFUSED,
            "connection to 10.20.30.40 refused",
        )

        outcome = classify_connect_exception(
            self.request,
            wrapped,
            tcp_connected=False,
        )

        self.assertIs(outcome.status, TargetStatus.CONNECTION_REFUSED)
        self.assertEqual(outcome.error.raw_code if outcome.error else None, errno.ECONNREFUSED)
        self.assertNotIn("10.20.30.40", repr(outcome))
        self.assertNotIn("10.20.30.40", repr(outcome.error))

    def test_network_timeout_and_unreachable_are_separate(self) -> None:
        timeout = classify_connect_exception(
            self.request,
            TimeoutError("10.20.30.40 did not answer"),
            tcp_connected=False,
        )
        unreachable = classify_connect_exception(
            self.request,
            OSError(errno.ENETUNREACH, "10.20.30.40 unreachable"),
            tcp_connected=False,
        )

        self.assertIs(timeout.status, TargetStatus.TIMEOUT_NO_RESPONSE)
        self.assertTrue(timeout.error.retryable if timeout.error else False)
        self.assertIs(unreachable.status, TargetStatus.NETWORK_UNREACHABLE)
        self.assertEqual(
            unreachable.error.raw_code if unreachable.error else None,
            errno.ENETUNREACH,
        )

    def test_timeout_after_tcp_connect_is_a_negotiation_timeout(self) -> None:
        outcome = classify_connect_exception(
            self.request,
            TimeoutError("SMB response contained 10.20.30.40"),
            tcp_connected=True,
        )

        self.assertIs(outcome.stage, TargetStage.NEGOTIATION)
        self.assertIs(outcome.status, TargetStatus.NEGOTIATION_FAILED)
        self.assertTrue(outcome.error.retryable if outcome.error else False)
        self.assertEqual(outcome.error.raw_code if outcome.error else None, errno.ETIMEDOUT)

    def test_native_smb_status_is_retained_as_numeric_code(self) -> None:
        class FakeSmbResponseError(Exception):
            status = 0xC000000D

        outcome = classify_connect_exception(
            self.request,
            FakeSmbResponseError("response from 10.20.30.40"),
            tcp_connected=True,
        )

        self.assertIs(outcome.status, TargetStatus.NEGOTIATION_FAILED)
        self.assertEqual(outcome.error.raw_code if outcome.error else None, 0xC000000D)
        self.assertEqual(
            outcome.error.symbolic_name if outcome.error else None,
            "SMB_NEGOTIATION_ERROR",
        )
        self.assertNotIn("10.20.30.40", str(outcome.error))

    def test_generic_negotiate_failure_has_stable_protocol_errno(self) -> None:
        outcome = classify_connect_exception(
            self.request,
            ValueError("secret target and parser detail"),
            tcp_connected=True,
            elapsed_seconds=0.2,
        )

        self.assertEqual(outcome.error.raw_code if outcome.error else None, errno.EPROTO)
        self.assertEqual(
            str(outcome.error),
            "TCP connected, but SMB negotiation did not complete.",
        )

    def test_smb1_only_is_explicit_probe_result_not_usable_connection(self) -> None:
        outcome = make_smb1_only_outcome(self.request, elapsed_seconds=0.1)

        self.assertIs(outcome.stage, TargetStage.NEGOTIATION)
        self.assertIs(outcome.status, TargetStatus.SMB1_ONLY_UNSUPPORTED)
        self.assertIn("file access was not attempted", str(outcome.error))


if __name__ == "__main__":
    unittest.main()
