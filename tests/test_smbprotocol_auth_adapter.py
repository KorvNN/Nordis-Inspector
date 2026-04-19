from __future__ import annotations

import errno
import logging
import unittest

import spnego
from spnego.exceptions import (
    BadMechanismError,
    BadNameError,
    CredentialsExpiredError,
    ErrorCode,
    InvalidCredentialError,
)

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb import (
    NEVER_CANCELLED,
    AuthAttemptOutcome,
    AuthenticationRequest,
    AuthMechanism,
    CancellationFlag,
    FallbackReason,
    ScanCancelled,
)
from nordis_smb_inspector.smb.smbprotocol_auth_adapter import (
    SmbProtocolAuthenticationError,
    SmbProtocolAuthenticator,
    SmbProtocolFallbackConnectionError,
    SmbProtocolSessionCloseError,
    UnsupportedAuthenticationCredential,
    classify_authentication_exception,
    suppress_sensitive_dependency_logging,
)


class _NativeConnection:
    pass


class _Connection:
    def __init__(self, *, require_encryption: bool = False) -> None:
        self.native = _NativeConnection()
        self.require_encryption = require_encryption
        self.closed = False
        self.close_calls = 0
        self.close_error: Exception | None = None

    @property
    def _native_connection(self) -> _NativeConnection:
        if self.closed:
            raise ValueError("connection closed")
        return self.native

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _NativeSession:
    def __init__(
        self,
        connection: object,
        username: object = None,
        password: object = None,
        require_encryption: bool = True,
        hostname_override: str | None = None,
        auth_protocol: str = "negotiate",
        *,
        connect_error: Exception | None = None,
        disconnect_error: Exception | None = None,
        cancellation_on_connect: CancellationFlag | None = None,
    ) -> None:
        self.connection = connection
        self.constructor_username = username
        self.constructor_password = password
        self.username = username
        self.password = password
        self.require_encryption = require_encryption
        self.hostname_override = hostname_override
        self.auth_protocol = auth_protocol
        self.connect_error = connect_error
        self.disconnect_error = disconnect_error
        self.cancellation_on_connect = cancellation_on_connect
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.disconnect_username: object = "not-called"
        self.seen_provider_credential: object | None = None
        self.signing_required: bool | None = True
        self.encrypt_data: bool | None = require_encryption

    def connect(self) -> None:
        self.connect_calls += 1
        self.seen_provider_credential = self.username
        if self.cancellation_on_connect is not None:
            self.cancellation_on_connect.cancel()
        if self.connect_error is not None:
            raise self.connect_error

    def disconnect(self, close: bool = True, timeout: float | None = None) -> None:
        self.disconnect_calls += 1
        self.disconnect_username = self.username
        if self.disconnect_error is not None:
            raise self.disconnect_error


class _SessionFactory:
    def __init__(
        self,
        errors: tuple[Exception | None, ...] = (None,),
        *,
        disconnect_errors: tuple[Exception | None, ...] = (),
        cancellation_on_connect: CancellationFlag | None = None,
    ) -> None:
        self.errors = iter(errors)
        self.disconnect_errors = iter(disconnect_errors)
        self.cancellation_on_connect = cancellation_on_connect
        self.sessions: list[_NativeSession] = []

    def __call__(self, *args, **kwargs) -> _NativeSession:
        session = _NativeSession(
            *args,
            **kwargs,
            connect_error=next(self.errors, None),
            disconnect_error=next(self.disconnect_errors, None),
            cancellation_on_connect=self.cancellation_on_connect,
        )
        self.sessions.append(session)
        return session


class _Reconnect:
    def __init__(
        self,
        connection: _Connection | None = None,
        error: Exception | None = None,
    ) -> None:
        self.connection = connection or _Connection()
        self.error = error
        self.calls = 0
        self.cancellation = None

    def __call__(self, *, cancellation) -> _Connection:
        self.calls += 1
        self.cancellation = cancellation
        if self.error is not None:
            raise self.error
        return self.connection


def _password(
    *,
    mode: AuthMode = AuthMode.AUTO,
    value: str = "CorrectHorseBatteryStaple!",
) -> Credential:
    return Credential.from_password(
        username="alice",
        password=value,
        domain="NORDIS",
        auth_mode=mode,
    )


def _nt_hash(value: str = "0123456789abcdef0123456789abcdef") -> Credential:
    return Credential.from_nt_hash(username="alice", nt_hash=value, domain="NORDIS")


def _request(
    mechanism: AuthMechanism,
    *,
    credential: Credential | None = None,
) -> AuthenticationRequest:
    selected = credential or _password()
    return AuthenticationRequest(
        credential=selected,
        mechanism=mechanism,
        spn_hostname=("files01.nordis.local" if mechanism is AuthMechanism.KERBEROS else None),
    )


class ExplicitAuthenticationTests(unittest.TestCase):
    def test_password_kerberos_uses_real_pyspnego_credential_and_redacted_constructor(self) -> None:
        factory = _SessionFactory()
        ticks = iter((1.0, 1.2))
        authenticator = SmbProtocolAuthenticator(
            session_factory=factory,
            clock=lambda: next(ticks),
        )
        connection = _Connection(require_encryption=True)

        handle = authenticator.authenticate(
            connection,
            _request(AuthMechanism.KERBEROS),
            cancellation=NEVER_CANCELLED,
        )

        session = factory.sessions[0]
        self.assertIsNone(session.constructor_username)
        self.assertIsNone(session.constructor_password)
        self.assertIsInstance(session.seen_provider_credential, spnego.Password)
        self.assertEqual(session.seen_provider_credential.username, "NORDIS\\alice")
        self.assertEqual(
            session.seen_provider_credential.password,
            "CorrectHorseBatteryStaple!",
        )
        self.assertEqual(session.auth_protocol, "kerberos")
        self.assertEqual(session.hostname_override, "files01.nordis.local")
        self.assertTrue(session.require_encryption)
        self.assertIs(handle.authentication.selected_mechanism, AuthMechanism.KERBEROS)
        self.assertIs(handle.authentication.attempts[0].outcome, AuthAttemptOutcome.SUCCEEDED)
        self.assertAlmostEqual(handle.authentication.attempts[0].elapsed_seconds or 0, 0.2)

        rendered = repr(handle)
        for sensitive in (
            "alice",
            "NORDIS",
            "CorrectHorseBatteryStaple!",
            "files01.nordis.local",
        ):
            self.assertNotIn(sensitive, rendered)

    def test_nt_hash_uses_ntlmhash_and_never_treats_hash_as_password(self) -> None:
        factory = _SessionFactory()
        authenticator = SmbProtocolAuthenticator(session_factory=factory)
        credential = _nt_hash()

        handle = authenticator.authenticate(
            _Connection(),
            _request(AuthMechanism.NTLM, credential=credential),
            cancellation=NEVER_CANCELLED,
        )

        session = factory.sessions[0]
        provider = session.seen_provider_credential
        self.assertIsInstance(provider, spnego.NTLMHash)
        self.assertEqual(provider.username, "NORDIS\\alice")
        self.assertEqual(provider.nt_hash, credential.nt_hash)
        self.assertIsNone(provider.lm_hash)
        self.assertIsNone(session.password)
        self.assertEqual(session.auth_protocol, "ntlm")
        self.assertIsNone(session.hostname_override)
        self.assertIs(handle.authentication.selected_mechanism, AuthMechanism.NTLM)

    def test_explicit_failure_has_safe_history_numeric_code_and_no_native_cause(self) -> None:
        secret = "CorrectHorseBatteryStaple!"
        native = InvalidCredentialError(error_code=ErrorCode.invalid_credential)
        factory = _SessionFactory((native,))
        authenticator = SmbProtocolAuthenticator(session_factory=factory)

        with self.assertRaises(SmbProtocolAuthenticationError) as caught:
            authenticator.authenticate(
                _Connection(),
                _request(AuthMechanism.KERBEROS, credential=_password(value=secret)),
                cancellation=NEVER_CANCELLED,
            )

        error = caught.exception
        self.assertEqual(error.detail.raw_code, 0xC000006D)
        self.assertEqual(error.detail.symbolic_name, "LOGON_FAILURE")
        self.assertIsNone(error.fallback_reason)
        self.assertIsNone(error.__cause__)
        self.assertEqual(error.history.attempts[0].outcome, AuthAttemptOutcome.FAILED)
        for rendered in (str(error), repr(error), repr(error.history)):
            self.assertNotIn(secret, rendered)
            self.assertNotIn("alice", rendered)
        self.assertEqual(factory.sessions[0].disconnect_username, None)

    def test_ccache_is_explicitly_owned_by_a_separate_adapter(self) -> None:
        credential = Credential.from_ccache(filename="ticket.ccache", data=b"ticket-data")
        request = AuthenticationRequest(
            credential=credential,
            mechanism=AuthMechanism.KERBEROS,
            spn_hostname="files01.nordis.local",
        )

        with self.assertRaises(UnsupportedAuthenticationCredential):
            SmbProtocolAuthenticator(session_factory=_SessionFactory()).authenticate(
                _Connection(),
                request,
                cancellation=NEVER_CANCELLED,
            )

    def test_pre_cancelled_attempt_does_not_construct_session(self) -> None:
        cancellation = CancellationFlag()
        cancellation.cancel()
        factory = _SessionFactory()

        with self.assertRaises(ScanCancelled):
            SmbProtocolAuthenticator(session_factory=factory).authenticate(
                _Connection(),
                _request(AuthMechanism.KERBEROS),
                cancellation=cancellation,
            )

        self.assertEqual(factory.sessions, [])

    def test_cancellation_after_native_auth_discards_session(self) -> None:
        cancellation = CancellationFlag()
        factory = _SessionFactory(cancellation_on_connect=cancellation)

        with self.assertRaises(ScanCancelled):
            SmbProtocolAuthenticator(session_factory=factory).authenticate(
                _Connection(),
                _request(AuthMechanism.KERBEROS),
                cancellation=cancellation,
            )

        self.assertEqual(factory.sessions[0].disconnect_calls, 1)
        self.assertIsNone(factory.sessions[0].disconnect_username)

    def test_session_close_is_idempotent_scrubs_identity_and_wraps_error(self) -> None:
        factory = _SessionFactory(disconnect_errors=(RuntimeError("alice secret"),))
        handle = SmbProtocolAuthenticator(session_factory=factory).authenticate(
            _Connection(),
            _request(AuthMechanism.KERBEROS),
            cancellation=NEVER_CANCELLED,
        )

        with self.assertRaises(SmbProtocolSessionCloseError) as caught:
            handle.close()

        self.assertTrue(handle.closed)
        self.assertIsNone(factory.sessions[0].disconnect_username)
        self.assertNotIn("alice", str(caught.exception))
        handle.close()
        self.assertEqual(factory.sessions[0].disconnect_calls, 1)


class CredentialModeTests(unittest.TestCase):
    def test_kerberos_only_and_ntlm_only_route_one_explicit_attempt(self) -> None:
        kerberos_factory = _SessionFactory()
        kerberos = SmbProtocolAuthenticator(session_factory=kerberos_factory)
        kerberos_handle = kerberos.authenticate_credential(
            _Connection(),
            _password(mode=AuthMode.KERBEROS_ONLY),
            kerberos_hostname="files01.nordis.local",
            cancellation=NEVER_CANCELLED,
        )
        self.assertIs(
            kerberos_handle.authentication.selected_mechanism,
            AuthMechanism.KERBEROS,
        )

        ntlm_factory = _SessionFactory()
        ntlm = SmbProtocolAuthenticator(session_factory=ntlm_factory)
        ntlm_handle = ntlm.authenticate_credential(
            _Connection(),
            _nt_hash(),
            kerberos_hostname=None,
            cancellation=NEVER_CANCELLED,
        )
        self.assertIs(ntlm_handle.authentication.selected_mechanism, AuthMechanism.NTLM)

    def test_kerberos_only_without_hostname_is_visible_failure(self) -> None:
        with self.assertRaises(SmbProtocolAuthenticationError) as caught:
            SmbProtocolAuthenticator(session_factory=_SessionFactory()).authenticate_credential(
                _Connection(),
                _password(mode=AuthMode.KERBEROS_ONLY),
                kerberos_hostname=None,
                cancellation=NEVER_CANCELLED,
            )

        self.assertEqual(
            caught.exception.detail.symbolic_name,
            "KERBEROS_HOSTNAME_UNRESOLVED",
        )
        self.assertIsNone(caught.exception.fallback_reason)

    def test_auto_requires_reconnect_hook_before_any_attempt(self) -> None:
        factory = _SessionFactory()
        with self.assertRaisesRegex(ValueError, "fresh NTLM reconnect"):
            SmbProtocolAuthenticator(session_factory=factory).authenticate_credential(
                _Connection(),
                _password(),
                kerberos_hostname="files01.nordis.local",
                cancellation=NEVER_CANCELLED,
            )
        self.assertEqual(factory.sessions, [])

    def test_ccache_mode_routing_stays_separate(self) -> None:
        credential = Credential.from_ccache(filename="ticket.ccache", data=b"ticket")
        with self.assertRaises(UnsupportedAuthenticationCredential):
            SmbProtocolAuthenticator(session_factory=_SessionFactory()).authenticate_credential(
                _Connection(),
                credential,
                kerberos_hostname="files01.nordis.local",
                cancellation=NEVER_CANCELLED,
            )


class AutoAuthenticationTests(unittest.TestCase):
    def test_successful_kerberos_does_not_call_reconnect_or_ntlm(self) -> None:
        factory = _SessionFactory()
        reconnect = _Reconnect()

        handle = SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
            _Connection(),
            _password(),
            kerberos_hostname="files01.nordis.local",
            reconnect_for_ntlm=reconnect,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(len(factory.sessions), 1)
        self.assertEqual(factory.sessions[0].auth_protocol, "kerberos")
        self.assertEqual(reconnect.calls, 0)
        self.assertIs(handle.authentication.selected_mechanism, AuthMechanism.KERBEROS)
        self.assertIsNone(handle.authentication.fallback_reason)

    def test_spn_failure_closes_primary_reconnects_and_records_both_attempts(self) -> None:
        factory = _SessionFactory(
            (BadNameError(error_code=ErrorCode.bad_name), None)
        )
        primary = _Connection()
        replacement = _Connection()
        reconnect = _Reconnect(replacement)

        handle = SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
            primary,
            _password(),
            kerberos_hostname="files01.nordis.local",
            reconnect_for_ntlm=reconnect,
            cancellation=NEVER_CANCELLED,
        )

        self.assertTrue(primary.closed)
        self.assertEqual(primary.close_calls, 1)
        self.assertIs(handle.connection, replacement)
        self.assertEqual([item.auth_protocol for item in factory.sessions], ["kerberos", "ntlm"])
        self.assertEqual(
            tuple(attempt.mechanism for attempt in handle.authentication.attempts),
            (AuthMechanism.KERBEROS, AuthMechanism.NTLM),
        )
        self.assertIs(handle.authentication.selected_mechanism, AuthMechanism.NTLM)
        self.assertIs(handle.authentication.fallback_reason, FallbackReason.SPN_NOT_FOUND)
        self.assertEqual(reconnect.calls, 1)

    def test_missing_hostname_is_a_visible_failed_attempt_before_ntlm(self) -> None:
        factory = _SessionFactory((None,))
        reconnect = _Reconnect()

        handle = SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
            _Connection(),
            _password(),
            kerberos_hostname=None,
            reconnect_for_ntlm=reconnect,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(len(factory.sessions), 1)
        self.assertEqual(factory.sessions[0].auth_protocol, "ntlm")
        self.assertEqual(
            handle.authentication.attempts[0].error.symbolic_name,
            "KERBEROS_HOSTNAME_UNRESOLVED",
        )
        self.assertIs(
            handle.authentication.fallback_reason,
            FallbackReason.KERBEROS_HOSTNAME_UNRESOLVED,
        )

    def test_invalid_credentials_never_trigger_second_logon(self) -> None:
        factory = _SessionFactory(
            (InvalidCredentialError(error_code=ErrorCode.invalid_credential),)
        )
        primary = _Connection()
        reconnect = _Reconnect()

        with self.assertRaises(SmbProtocolAuthenticationError) as caught:
            SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
                primary,
                _password(),
                kerberos_hostname="files01.nordis.local",
                reconnect_for_ntlm=reconnect,
                cancellation=NEVER_CANCELLED,
            )

        self.assertIsNone(caught.exception.fallback_reason)
        self.assertEqual(len(factory.sessions), 1)
        self.assertEqual(reconnect.calls, 0)
        self.assertFalse(primary.closed)

    def test_ntlm_failure_returns_combined_history_and_closes_replacement(self) -> None:
        factory = _SessionFactory(
            (
                BadMechanismError(error_code=ErrorCode.bad_mech),
                InvalidCredentialError(error_code=ErrorCode.invalid_credential),
            )
        )
        replacement = _Connection()

        with self.assertRaises(SmbProtocolAuthenticationError) as caught:
            SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
                _Connection(),
                _password(),
                kerberos_hostname="files01.nordis.local",
                reconnect_for_ntlm=_Reconnect(replacement),
                cancellation=NEVER_CANCELLED,
            )

        history = caught.exception.history
        self.assertEqual(len(history.attempts), 2)
        self.assertEqual(
            tuple(attempt.mechanism for attempt in history.attempts),
            (AuthMechanism.KERBEROS, AuthMechanism.NTLM),
        )
        self.assertIsNone(history.selected_mechanism)
        self.assertIs(history.fallback_reason, FallbackReason.UNSUPPORTED_MECHANISM)
        self.assertTrue(replacement.closed)

    def test_reconnect_failure_is_safe_and_retains_kerberos_history(self) -> None:
        factory = _SessionFactory((BadNameError(error_code=ErrorCode.bad_name),))
        secret_error = RuntimeError("10.20.30.40 alice CorrectHorseBatteryStaple!")

        with self.assertRaises(SmbProtocolFallbackConnectionError) as caught:
            SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
                _Connection(),
                _password(),
                kerberos_hostname="files01.nordis.local",
                reconnect_for_ntlm=_Reconnect(error=secret_error),
                cancellation=NEVER_CANCELLED,
            )

        error = caught.exception
        self.assertEqual(len(error.kerberos_history.attempts), 1)
        for rendered in (str(error), repr(error)):
            self.assertNotIn("10.20.30.40", rendered)
            self.assertNotIn("alice", rendered)
            self.assertNotIn("CorrectHorseBatteryStaple!", rendered)
        self.assertIsNone(error.__cause__)

    def test_auto_rejects_wrong_credential_modes(self) -> None:
        authenticator = SmbProtocolAuthenticator(session_factory=_SessionFactory())
        for credential in (_password(mode=AuthMode.KERBEROS_ONLY), _nt_hash()):
            with (
                self.subTest(kind=credential.kind, mode=credential.auth_mode),
                self.assertRaisesRegex(ValueError, "Auto-mode password"),
            ):
                authenticator.authenticate_auto(
                    _Connection(),
                    credential,
                    kerberos_hostname="files01.nordis.local",
                    reconnect_for_ntlm=_Reconnect(),
                    cancellation=NEVER_CANCELLED,
                )

    def test_cancellation_before_fallback_prevents_reconnect(self) -> None:
        cancellation = CancellationFlag()

        class _CancelAfterKerberos(_SessionFactory):
            def __call__(self, *args, **kwargs) -> _NativeSession:
                session = super().__call__(*args, **kwargs)
                original_connect = session.connect

                def connect() -> None:
                    try:
                        original_connect()
                    finally:
                        cancellation.cancel()

                session.connect = connect
                return session

        factory = _CancelAfterKerberos((BadNameError(error_code=ErrorCode.bad_name),))
        reconnect = _Reconnect()

        with self.assertRaises(ScanCancelled):
            SmbProtocolAuthenticator(session_factory=factory).authenticate_auto(
                _Connection(),
                _password(),
                kerberos_hostname="files01.nordis.local",
                reconnect_for_ntlm=reconnect,
                cancellation=cancellation,
            )

        self.assertEqual(reconnect.calls, 0)


class FailureClassificationTests(unittest.TestCase):
    def test_structured_kerberos_failures_map_to_explicit_fallback_reasons(self) -> None:
        class MinorCodeError(Exception):
            def __init__(self, min_code: int) -> None:
                self.min_code = min_code

        cases: tuple[tuple[BaseException, FallbackReason, str], ...] = (
            (
                BadNameError(error_code=ErrorCode.bad_name),
                FallbackReason.SPN_NOT_FOUND,
                "KERBEROS_SPN_NOT_FOUND",
            ),
            (
                MinorCodeError((-1765328347) & 0xFFFFFFFF),
                FallbackReason.CLOCK_SKEW,
                "KERBEROS_CLOCK_SKEW",
            ),
            (
                MinorCodeError(-1765328230),
                FallbackReason.REALM_MISMATCH,
                "KERBEROS_REALM_MISMATCH",
            ),
            (
                OSError(errno.ENETUNREACH, "sensitive target"),
                FallbackReason.KDC_UNREACHABLE,
                "KERBEROS_KDC_UNREACHABLE",
            ),
            (
                BadMechanismError(error_code=ErrorCode.bad_mech),
                FallbackReason.UNSUPPORTED_MECHANISM,
                "KERBEROS_MECHANISM_UNAVAILABLE",
            ),
        )

        for exception, reason, symbolic_name in cases:
            with self.subTest(reason=reason):
                failure = classify_authentication_exception(
                    AuthMechanism.KERBEROS,
                    exception,
                )
                self.assertIs(failure.fallback_reason, reason)
                self.assertEqual(failure.detail.symbolic_name, symbolic_name)
                self.assertNotIn("sensitive target", repr(failure.detail))

    def test_account_states_never_allow_fallback(self) -> None:
        exceptions: tuple[BaseException, ...] = (
            InvalidCredentialError(error_code=ErrorCode.invalid_credential),
            CredentialsExpiredError(error_code=ErrorCode.credentials_expired),
            _StatusError(0xC0000072),
            _StatusError(0xC0000234),
        )
        for exception in exceptions:
            with self.subTest(exception=type(exception).__name__):
                failure = classify_authentication_exception(
                    AuthMechanism.KERBEROS,
                    exception,
                )
                self.assertIsNone(failure.fallback_reason)

    def test_ntlm_never_exposes_a_kerberos_fallback_reason(self) -> None:
        failure = classify_authentication_exception(
            AuthMechanism.NTLM,
            BadNameError(error_code=ErrorCode.bad_name),
        )
        self.assertIsNone(failure.fallback_reason)
        self.assertEqual(failure.detail.symbolic_name, "AUTH_INFRASTRUCTURE_ERROR")

    def test_native_status_code_is_retained_without_exception_message(self) -> None:
        failure = classify_authentication_exception(
            AuthMechanism.NTLM,
            _StatusError(0xC0000072, "alice at 10.20.30.40"),
        )
        self.assertEqual(failure.detail.raw_code, 0xC0000072)
        self.assertEqual(failure.detail.symbolic_name, "ACCOUNT_DISABLED")
        self.assertNotIn("alice", str(failure.detail))
        self.assertNotIn("10.20.30.40", repr(failure.detail))


class _StatusError(Exception):
    def __init__(self, status: int, message: str = "native error") -> None:
        self.status = status
        super().__init__(message)


class DependencyLoggingTests(unittest.TestCase):
    def test_sensitive_dependency_loggers_are_disabled(self) -> None:
        names = (
            "smbprotocol.connection",
            "smbprotocol.session",
            "smbprotocol.transport",
            "spnego._gss",
            "spnego._negotiate",
            "spnego._ntlm",
            "spnego._sspi",
        )
        for name in names:
            logging.getLogger(name).disabled = False

        suppress_sensitive_dependency_logging()

        for name in names:
            self.assertTrue(logging.getLogger(name).disabled, name)


if __name__ == "__main__":
    unittest.main()
