from __future__ import annotations

import errno
import unittest

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb import (
    NEVER_CANCELLED,
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthMechanism,
    CancellationFlag,
    ConnectRequest,
    FallbackReason,
    NegotiationInfo,
    RequirementSource,
    ScanCancelled,
    SecurityFeatureState,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
)
from nordis_smb_inspector.smb.smbprotocol_adapter import SmbProtocolConnectError
from nordis_smb_inspector.smb.smbprotocol_auth_adapter import (
    SmbProtocolAuthenticationError,
    SmbProtocolFallbackConnectionError,
    UnsupportedAuthenticationCredential,
)
from nordis_smb_inspector.smb.workflow import (
    AccessEventKind,
    AccessWorkflowStatus,
    inspect_target_access,
)


def _negotiation() -> NegotiationInfo:
    return NegotiationInfo(
        dialect=SmbDialect.SMB_3_1_1,
        security=TransportSecurity(
            signing=SecurityFeatureState(
                supported=True,
                required=True,
                active=None,
                requirement_source=RequirementSource.SERVER,
            ),
            encryption=SecurityFeatureState(
                supported=True,
                required=None,
                active=None,
            ),
        ),
        max_read_size=1_048_576,
    )


def _auth_error(message: str = "The account was not accepted.") -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=TargetStage.AUTHENTICATION,
        status=TargetStatus.AUTH_FAILED,
        operation="authenticate_ntlm",
        raw_code=0xC000006D,
        symbolic_name="LOGON_FAILURE",
        safe_message=message,
    )


def _failed_history(
    mechanism: AuthMechanism = AuthMechanism.NTLM,
) -> AuthenticationHistory:
    return AuthenticationHistory(
        attempts=(
            AuthAttempt(
                mechanism=mechanism,
                outcome=AuthAttemptOutcome.FAILED,
                error=_auth_error(),
            ),
        ),
        selected_mechanism=None,
    )


def _success_history(
    mechanism: AuthMechanism = AuthMechanism.KERBEROS,
) -> AuthenticationHistory:
    return AuthenticationHistory(
        attempts=(
            AuthAttempt(
                mechanism=mechanism,
                outcome=AuthAttemptOutcome.SUCCEEDED,
            ),
        ),
        selected_mechanism=mechanism,
    )


def _password(mode: AuthMode = AuthMode.AUTO) -> Credential:
    return Credential.from_password(
        username="alice",
        password="CorrectHorseBatteryStaple!",
        domain="NORDIS",
        auth_mode=mode,
    )


def _hash() -> Credential:
    return Credential.from_nt_hash(
        username="alice",
        nt_hash="0123456789abcdef0123456789abcdef",
        domain="NORDIS",
    )


class _Connection:
    def __init__(self, *, close_error: Exception | None = None) -> None:
        self.negotiation = _negotiation()
        self.closed = False
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _Connector:
    def __init__(
        self,
        connections: tuple[_Connection, ...] = (),
        *,
        errors: tuple[Exception | None, ...] = (),
    ) -> None:
        self.connections = list(connections)
        self.errors = list(errors)
        self.calls: list[tuple[ConnectRequest, object]] = []

    def connect(self, request: ConnectRequest, *, cancellation) -> _Connection:
        self.calls.append((request, cancellation))
        error = self.errors.pop(0) if self.errors else None
        if error is not None:
            raise error
        if not self.connections:
            raise AssertionError("No mock connection configured.")
        return self.connections.pop(0)


class _Session:
    def __init__(
        self,
        connection: _Connection,
        history: AuthenticationHistory,
        *,
        close_error: Exception | None = None,
    ) -> None:
        self.connection = connection
        self.authentication = history
        self.closed = False
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _Authenticator:
    def __init__(self, action) -> None:
        self.action = action
        self.calls: list[dict[str, object]] = []

    def authenticate_credential(
        self,
        connection,
        credential,
        *,
        kerberos_hostname,
        cancellation,
        reconnect_for_ntlm=None,
    ):
        self.calls.append(
            {
                "connection": connection,
                "credential": credential,
                "kerberos_hostname": kerberos_hostname,
                "cancellation": cancellation,
                "reconnect_for_ntlm": reconnect_for_ntlm,
            }
        )
        if isinstance(self.action, BaseException):
            raise self.action
        if callable(self.action):
            return self.action(
                connection=connection,
                reconnect_for_ntlm=reconnect_for_ntlm,
                cancellation=cancellation,
            )
        return self.action


class SuccessfulWorkflowTests(unittest.TestCase):
    def test_password_success_returns_events_and_closes_session_then_connection(self) -> None:
        order: list[str] = []

        class OrderedConnection(_Connection):
            def close(self) -> None:
                order.append("connection")
                super().close()

        class OrderedSession(_Session):
            def close(self) -> None:
                order.append("session")
                super().close()

        connection = OrderedConnection()
        session = OrderedSession(connection, _success_history())
        observed = []

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(mode=AuthMode.KERBEROS_ONLY),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session),
            cancellation=NEVER_CANCELLED,
            on_event=observed.append,
        )

        self.assertIs(result.status, AccessWorkflowStatus.AUTHENTICATED)
        self.assertTrue(result.authenticated)
        self.assertEqual(
            tuple(event.kind for event in result.events),
            (
                AccessEventKind.NEGOTIATION_SUCCEEDED,
                AccessEventKind.AUTHENTICATION_SUCCEEDED,
            ),
        )
        self.assertEqual(tuple(observed), result.events)
        self.assertEqual(order, ["session", "connection"])
        self.assertTrue(session.closed)
        self.assertTrue(connection.closed)

    def test_nt_hash_uses_same_single_call_facade(self) -> None:
        connection = _Connection()
        session = _Session(connection, _success_history(AuthMechanism.NTLM))
        authenticator = _Authenticator(session)

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_hash(),
            kerberos_hostname=None,
            connector=_Connector((connection,)),
            authenticator=authenticator,
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.authentication.selected_mechanism, AuthMechanism.NTLM)
        self.assertIs(authenticator.calls[0]["credential"].kind, _hash().kind)
        self.assertIsNone(authenticator.calls[0]["kerberos_hostname"])

    def test_auto_reconnect_is_owned_and_all_connections_are_closed(self) -> None:
        primary = _Connection()
        replacement = _Connection()
        connector = _Connector((primary, replacement))

        def auto_action(*, connection, reconnect_for_ntlm, cancellation):
            connection.close()
            active = reconnect_for_ntlm(cancellation=cancellation)
            kerberos_error = _auth_error("Kerberos SPN was not found.")
            history = AuthenticationHistory(
                attempts=(
                    AuthAttempt(
                        mechanism=AuthMechanism.KERBEROS,
                        outcome=AuthAttemptOutcome.FAILED,
                        error=kerberos_error,
                    ),
                    AuthAttempt(
                        mechanism=AuthMechanism.NTLM,
                        outcome=AuthAttemptOutcome.SUCCEEDED,
                    ),
                ),
                selected_mechanism=AuthMechanism.NTLM,
                fallback_reason=FallbackReason.SPN_NOT_FOUND,
            )
            return _Session(active, history)

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=connector,
            authenticator=_Authenticator(auto_action),
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.AUTHENTICATED)
        self.assertIs(result.authentication.selected_mechanism, AuthMechanism.NTLM)
        self.assertEqual(len(connector.calls), 2)
        self.assertIs(connector.calls[0][0], connector.calls[1][0])
        self.assertTrue(primary.closed)
        self.assertTrue(replacement.closed)
        self.assertGreaterEqual(primary.close_calls, 1)


class FailureWorkflowTests(unittest.TestCase):
    def test_connect_failure_is_returned_without_calling_authenticator(self) -> None:
        request = ConnectRequest(target="10.20.30.40")
        detail = SmbErrorDetail(
            stage=TargetStage.NETWORK,
            status=TargetStatus.CONNECTION_REFUSED,
            operation="connect",
            raw_code=errno.ECONNREFUSED,
            symbolic_name="ECONNREFUSED",
            safe_message="The target refused the TCP connection.",
            target=request.target,
        )
        outcome = TargetOutcome(
            target=request.target,
            stage=TargetStage.NETWORK,
            status=TargetStatus.CONNECTION_REFUSED,
            error=detail,
        )
        authenticator = _Authenticator(AssertionError("must not authenticate"))

        result = inspect_target_access(
            target=request.target,
            connect_request=request,
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector(errors=(SmbProtocolConnectError(outcome),)),
            authenticator=authenticator,
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.CONNECT_FAILED)
        self.assertIs(result.outcome, outcome)
        self.assertEqual(result.events[0].kind, AccessEventKind.NEGOTIATION_FAILED)
        self.assertEqual(authenticator.calls, [])

    def test_auth_failure_returns_history_and_closes_connection(self) -> None:
        connection = _Connection()
        error = _auth_error()
        history = _failed_history()
        exception = SmbProtocolAuthenticationError(history=history, detail=error)

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(exception),
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.AUTH_FAILED)
        self.assertIs(result.authentication, history)
        self.assertIs(result.outcome.error, error)
        self.assertTrue(connection.closed)

    def test_fallback_connect_failure_is_a_distinct_terminal_result(self) -> None:
        primary = _Connection()
        kerberos_history = _failed_history(AuthMechanism.KERBEROS)
        exception = SmbProtocolFallbackConnectionError(kerberos_history)

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((primary,)),
            authenticator=_Authenticator(exception),
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.FALLBACK_CONNECT_FAILED)
        self.assertEqual(
            result.events[-1].kind,
            AccessEventKind.FALLBACK_CONNECTION_FAILED,
        )
        self.assertIs(result.authentication, kerberos_history)
        self.assertTrue(primary.closed)

    def test_ccache_is_explicit_result_and_does_not_touch_network(self) -> None:
        connector = _Connector()
        authenticator = _Authenticator(UnsupportedAuthenticationCredential())
        credential = Credential.from_ccache(filename="ticket.ccache", data=b"ticket")

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=credential,
            kerberos_hostname="files01.nordis.local",
            connector=connector,
            authenticator=authenticator,
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.CCACHE_UNSUPPORTED)
        self.assertEqual(result.events[0].kind, AccessEventKind.CREDENTIAL_UNSUPPORTED)
        self.assertEqual(connector.calls, [])
        self.assertEqual(authenticator.calls, [])

    def test_cancellation_returns_normalized_event_and_closes_owned_handle(self) -> None:
        connection = _Connection()
        cancellation = CancellationFlag()

        def cancel_action(**kwargs):
            cancellation.cancel()
            raise ScanCancelled()

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(cancel_action),
            cancellation=cancellation,
        )

        self.assertIs(result.status, AccessWorkflowStatus.CANCELLED)
        self.assertEqual(result.events[-1].kind, AccessEventKind.CANCELLED)
        self.assertTrue(connection.closed)

    def test_unknown_exception_is_safe_internal_result_and_hides_native_text(self) -> None:
        connection = _Connection()
        native = RuntimeError("10.20.30.40 alice CorrectHorseBatteryStaple!")

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(native),
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.INTERNAL_ERROR)
        for rendered in (repr(result), repr(result.events), str(result.outcome.error)):
            self.assertNotIn("10.20.30.40", rendered)
            self.assertNotIn("alice", rendered)
            self.assertNotIn("CorrectHorseBatteryStaple!", rendered)

    def test_cleanup_failure_is_visible_but_does_not_replace_scan_result(self) -> None:
        connection = _Connection(close_error=RuntimeError("sensitive target"))
        session = _Session(
            connection,
            _success_history(),
            close_error=RuntimeError("sensitive identity"),
        )

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session),
            cancellation=NEVER_CANCELLED,
        )

        self.assertIs(result.status, AccessWorkflowStatus.AUTHENTICATED)
        self.assertEqual(result.events[-1].kind, AccessEventKind.CLEANUP_FAILED)
        self.assertIsNone(result.events[-1].error)
        self.assertNotIn("sensitive", repr(result.events[-1]))


class WorkflowInvariantTests(unittest.TestCase):
    def test_target_and_request_must_match_before_network_use(self) -> None:
        connector = _Connector((_Connection(),))
        with self.assertRaisesRegex(ValueError, "must match"):
            inspect_target_access(
                target="10.20.30.41",
                connect_request=ConnectRequest(target="10.20.30.40"),
                credential=_password(),
                kerberos_hostname="files01.nordis.local",
                connector=connector,
                authenticator=_Authenticator(AssertionError()),
                cancellation=NEVER_CANCELLED,
            )
        self.assertEqual(connector.calls, [])

    def test_event_callback_failure_isolated_and_cleanup_still_runs(self) -> None:
        connection = _Connection()

        def callback(event) -> None:
            raise RuntimeError("callback contains target and secret")

        result = inspect_target_access(
            target="10.20.30.40",
            connect_request=ConnectRequest(target="10.20.30.40"),
            credential=_password(),
            kerberos_hostname="files01.nordis.local",
            connector=_Connector((connection,)),
            authenticator=_Authenticator(
                _Session(connection, _success_history(AuthMechanism.KERBEROS))
            ),
            cancellation=NEVER_CANCELLED,
            on_event=callback,
        )

        self.assertIs(result.status, AccessWorkflowStatus.AUTHENTICATED)
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main()
