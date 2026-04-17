from __future__ import annotations

import inspect
import unittest

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb import (
    NEVER_CANCELLED,
    AlgorithmSource,
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthenticationRequest,
    AuthMechanism,
    CancellationFlag,
    ConnectRequest,
    FallbackReason,
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
    NegotiationInfo,
    OpenFileRequest,
    ReadOnlyAuthenticator,
    ReadOnlyConnector,
    ReadOnlyFileOpener,
    ReadOnlyShareEnumerator,
    ReadOnlyTreeWalker,
    RequirementSource,
    ScanCancelled,
    SecurityFeatureState,
    ShareAccessStatus,
    ShareEnumerationResult,
    ShareInfo,
    ShareKind,
    SmbDialect,
    SmbErrorDetail,
    TargetOutcome,
    TargetStage,
    TargetStatus,
    TransportSecurity,
    TreeWalkRequest,
    ValidatedRangeReader,
)


def _error(
    *,
    stage: TargetStage,
    status: TargetStatus,
    message: str = "The operation was rejected.",
    target: str = "10.20.30.40",
    path: str = "Finance/secret.txt",
    identity: str = "NORDIS/alice",
) -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=stage,
        status=status,
        operation="test_operation",
        raw_code=0xC0000022,
        symbolic_name="STATUS_ACCESS_DENIED",
        safe_message=message,
        target=target,
        path=path,
        identity=identity,
    )


class TargetResultTests(unittest.TestCase):
    def test_statuses_preserve_required_failure_distinctions(self) -> None:
        statuses = {
            TargetStatus.TIMEOUT_NO_RESPONSE,
            TargetStatus.CONNECTION_REFUSED,
            TargetStatus.NETWORK_UNREACHABLE,
            TargetStatus.NEGOTIATION_FAILED,
            TargetStatus.AUTH_FAILED,
            TargetStatus.ACCESS_DENIED,
            TargetStatus.SHARE_ENUM_FAILED,
            TargetStatus.FILE_READ_ERROR,
            TargetStatus.DIRECTORY_LIST_ERROR,
            TargetStatus.SHARING_VIOLATION,
            TargetStatus.SMB1_ONLY_UNSUPPORTED,
        }
        self.assertEqual(len(statuses), 11)

    def test_error_keeps_numeric_code_and_safe_message(self) -> None:
        error = _error(
            stage=TargetStage.AUTHORIZATION,
            status=TargetStatus.ACCESS_DENIED,
        )

        self.assertEqual(error.raw_code, 0xC0000022)
        self.assertEqual(str(error), "The operation was rejected.")

    def test_error_repr_redacts_all_context_and_message(self) -> None:
        error = _error(
            stage=TargetStage.FILE_READ,
            status=TargetStatus.FILE_READ_DENIED,
            message="A display-safe explanation.",
        )

        rendered = repr(error)
        for sensitive in (
            "10.20.30.40",
            "Finance/secret.txt",
            "NORDIS/alice",
            "A display-safe explanation.",
        ):
            self.assertNotIn(sensitive, rendered)
        self.assertIn("raw_code=3221225506", rendered)
        self.assertIn("context=<redacted>", rendered)

    def test_error_rejects_status_at_wrong_stage(self) -> None:
        with self.assertRaisesRegex(ValueError, "not valid at stage"):
            _error(stage=TargetStage.NETWORK, status=TargetStatus.AUTH_FAILED)

    def test_error_rejects_non_numeric_code_and_multiline_message(self) -> None:
        with self.assertRaisesRegex(TypeError, "raw_code"):
            SmbErrorDetail(
                stage=TargetStage.NETWORK,
                status=TargetStatus.CONNECTION_REFUSED,
                operation="connect",
                raw_code=True,
                safe_message="Connection refused.",
            )
        with self.assertRaisesRegex(ValueError, "single line"):
            SmbErrorDetail(
                stage=TargetStage.NETWORK,
                status=TargetStatus.CONNECTION_REFUSED,
                operation="connect",
                raw_code=111,
                safe_message="Connection\nrefused.",
            )

    def test_target_outcome_enforces_stage_and_error_alignment(self) -> None:
        error = _error(
            stage=TargetStage.NEGOTIATION,
            status=TargetStatus.NEGOTIATION_FAILED,
        )
        outcome = TargetOutcome(
            target="10.20.30.40",
            stage=TargetStage.NEGOTIATION,
            status=TargetStatus.NEGOTIATION_FAILED,
            elapsed_seconds=0.25,
            error=error,
        )
        self.assertNotIn("10.20.30.40", repr(outcome))

        with self.assertRaisesRegex(ValueError, "must match"):
            TargetOutcome(
                target="10.20.30.40",
                stage=TargetStage.AUTHENTICATION,
                status=TargetStatus.AUTH_FAILED,
                error=error,
            )


class AuthenticationHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth_error = _error(
            stage=TargetStage.AUTHENTICATION,
            status=TargetStatus.AUTH_FAILED,
            message="Authentication failed.",
        )

    def test_visible_kerberos_to_ntlm_fallback_records_both_attempts(self) -> None:
        kerberos = AuthAttempt(
            mechanism=AuthMechanism.KERBEROS,
            outcome=AuthAttemptOutcome.FAILED,
            error=self.auth_error,
        )
        ntlm = AuthAttempt(
            mechanism=AuthMechanism.NTLM,
            outcome=AuthAttemptOutcome.SUCCEEDED,
        )

        history = AuthenticationHistory(
            attempts=(kerberos, ntlm),
            selected_mechanism=AuthMechanism.NTLM,
            fallback_reason=FallbackReason.SPN_NOT_FOUND,
        )

        self.assertTrue(history.authenticated)
        self.assertIs(history.attempt_for(AuthMechanism.KERBEROS), kerberos)
        self.assertIs(history.attempt_for(AuthMechanism.NTLM), ntlm)

    def test_two_mechanisms_require_explicit_fallback_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "record its reason"):
            AuthenticationHistory(
                attempts=(
                    AuthAttempt(
                        mechanism=AuthMechanism.KERBEROS,
                        outcome=AuthAttemptOutcome.FAILED,
                        error=self.auth_error,
                    ),
                    AuthAttempt(
                        mechanism=AuthMechanism.NTLM,
                        outcome=AuthAttemptOutcome.SUCCEEDED,
                    ),
                ),
                selected_mechanism=AuthMechanism.NTLM,
            )

    def test_selected_mechanism_must_be_the_success(self) -> None:
        with self.assertRaisesRegex(ValueError, "successful attempt"):
            AuthenticationHistory(
                attempts=(
                    AuthAttempt(
                        mechanism=AuthMechanism.KERBEROS,
                        outcome=AuthAttemptOutcome.SUCCEEDED,
                    ),
                ),
                selected_mechanism=AuthMechanism.NTLM,
            )

    def test_ntlm_fallback_unavailable_is_explicit_without_fake_attempt(self) -> None:
        history = AuthenticationHistory(
            attempts=(
                AuthAttempt(
                    mechanism=AuthMechanism.KERBEROS,
                    outcome=AuthAttemptOutcome.FAILED,
                    error=self.auth_error,
                ),
            ),
            selected_mechanism=None,
            fallback_reason=FallbackReason.NTLM_FALLBACK_UNAVAILABLE,
        )
        self.assertFalse(history.authenticated)
        self.assertIsNone(history.attempt_for(AuthMechanism.NTLM))

    def test_duplicate_or_reverse_order_attempts_are_rejected(self) -> None:
        failed_kerberos = AuthAttempt(
            mechanism=AuthMechanism.KERBEROS,
            outcome=AuthAttemptOutcome.FAILED,
            error=self.auth_error,
        )
        with self.assertRaisesRegex(ValueError, "at most once"):
            AuthenticationHistory(
                attempts=(failed_kerberos, failed_kerberos),
                selected_mechanism=None,
            )
        with self.assertRaisesRegex(ValueError, "must precede"):
            AuthenticationHistory(
                attempts=(
                    AuthAttempt(
                        mechanism=AuthMechanism.NTLM,
                        outcome=AuthAttemptOutcome.FAILED,
                        error=self.auth_error,
                    ),
                    failed_kerberos,
                ),
                selected_mechanism=None,
                fallback_reason=FallbackReason.KDC_UNREACHABLE,
            )

    def test_failed_attempt_requires_error_and_success_forbids_one(self) -> None:
        with self.assertRaisesRegex(ValueError, "must contain an error"):
            AuthAttempt(
                mechanism=AuthMechanism.KERBEROS,
                outcome=AuthAttemptOutcome.FAILED,
            )
        with self.assertRaisesRegex(ValueError, "cannot contain an error"):
            AuthAttempt(
                mechanism=AuthMechanism.KERBEROS,
                outcome=AuthAttemptOutcome.SUCCEEDED,
                error=self.auth_error,
            )


class RequestContractTests(unittest.TestCase):
    def test_connect_request_validates_transport_values_and_redacts_target(self) -> None:
        request = ConnectRequest(target="10.20.30.40", port=445, timeout_seconds=2.5)
        self.assertNotIn("10.20.30.40", repr(request))

        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            ConnectRequest(target="host", port=0)
        with self.assertRaisesRegex(ValueError, "positive"):
            ConnectRequest(target="host", timeout_seconds=float("inf"))

    def test_authentication_request_redacts_secret_identity_and_spn(self) -> None:
        credential = Credential.from_password(
            username="alice",
            password="CorrectHorseBatteryStaple!",
            domain="NORDIS",
            auth_mode=AuthMode.AUTO,
        )
        request = AuthenticationRequest(
            credential=credential,
            mechanism=AuthMechanism.KERBEROS,
            spn_hostname="files01.nordis.local",
        )

        rendered = repr(request)
        for sensitive in (
            "alice",
            "CorrectHorseBatteryStaple!",
            "NORDIS",
            "files01.nordis.local",
        ):
            self.assertNotIn(sensitive, rendered)

    def test_authentication_request_enforces_credential_mechanism(self) -> None:
        nt_hash = Credential.from_nt_hash(
            username="alice",
            nt_hash="0123456789abcdef0123456789abcdef",
            domain="NORDIS",
        )
        with self.assertRaisesRegex(ValueError, "cannot be used for Kerberos"):
            AuthenticationRequest(
                credential=nt_hash,
                mechanism=AuthMechanism.KERBEROS,
                spn_hostname="files01.nordis.local",
            )

        ccache = Credential.from_ccache(filename="ticket.ccache", data=b"ticket")
        with self.assertRaisesRegex(ValueError, "cannot be used for NTLM"):
            AuthenticationRequest(
                credential=ccache,
                mechanism=AuthMechanism.NTLM,
            )

    def test_open_file_request_has_no_write_intent_and_redacts_location(self) -> None:
        request = OpenFileRequest(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Payroll/secrets.txt",
            expected_size=42,
        )
        rendered = repr(request)
        self.assertNotIn("10.20.30.40", rendered)
        self.assertNotIn("Finance", rendered)
        self.assertNotIn("Payroll/secrets.txt", rendered)
        self.assertFalse(hasattr(request, "write"))

    def test_public_adapter_protocols_expose_no_mutating_operations(self) -> None:
        protocols = (
            ReadOnlyConnector,
            ReadOnlyAuthenticator,
            ReadOnlyShareEnumerator,
            ReadOnlyTreeWalker,
            ReadOnlyFileOpener,
        )
        forbidden = {"write", "create", "delete", "rename", "chmod", "set_acl"}
        for protocol in protocols:
            public = {name for name in vars(protocol) if not name.startswith("_")}
            self.assertTrue(public.isdisjoint(forbidden), protocol.__name__)
            self.assertTrue(inspect.isclass(protocol))


class SecurityStateTests(unittest.TestCase):
    def test_signing_and_encryption_states_remain_independent(self) -> None:
        signing = SecurityFeatureState(
            supported=True,
            required=True,
            active=True,
            algorithm="AES-128-GMAC",
            algorithm_source=AlgorithmSource.NEGOTIATED,
            requirement_source=RequirementSource.SERVER,
        )
        encryption = SecurityFeatureState(
            supported=True,
            required=False,
            active=False,
        )
        security = TransportSecurity(signing=signing, encryption=encryption)

        self.assertTrue(security.signing.required)
        self.assertTrue(security.signing.active)
        self.assertFalse(security.encryption.required)
        self.assertFalse(security.encryption.active)

    def test_feature_state_rejects_impossible_or_ambiguous_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported"):
            SecurityFeatureState(supported=False, required=True, active=False)
        with self.assertRaisesRegex(ValueError, "supplied together"):
            SecurityFeatureState(
                supported=True,
                required=False,
                active=True,
                algorithm="AES-128-GCM",
            )
        with self.assertRaisesRegex(ValueError, "only valid"):
            SecurityFeatureState(
                supported=True,
                required=False,
                active=False,
                requirement_source=RequirementSource.SHARE,
            )

    def test_smb1_is_probe_status_not_a_usable_negotiation(self) -> None:
        blank = SecurityFeatureState(supported=None, required=None, active=None)
        security = TransportSecurity(signing=blank, encryption=blank)
        with self.assertRaisesRegex(ValueError, "probe-only"):
            NegotiationInfo(
                dialect=SmbDialect.SMB1,
                security=security,
                max_read_size=65_536,
            )

        outcome = TargetOutcome(
            target="legacy-host",
            stage=TargetStage.NEGOTIATION,
            status=TargetStatus.SMB1_ONLY_UNSUPPORTED,
        )
        self.assertIs(outcome.status, TargetStatus.SMB1_ONLY_UNSUPPORTED)


class InventoryModelTests(unittest.TestCase):
    def test_readable_and_unreadable_files_and_directories_are_representable(self) -> None:
        readable_file = InventoryEntry(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Budget.xlsx",
            kind=InventoryEntryKind.FILE,
            status=InventoryStatus.FILE_READABLE,
            size=1024,
        )
        unreadable_file = InventoryEntry(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Locked.xlsx",
            kind=InventoryEntryKind.FILE,
            status=InventoryStatus.FILE_READ_DENIED,
            size=2048,
            error=_error(
                stage=TargetStage.FILE_READ,
                status=TargetStatus.FILE_READ_DENIED,
            ),
        )
        readable_directory = InventoryEntry(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Reports",
            kind=InventoryEntryKind.DIRECTORY,
            status=InventoryStatus.DIRECTORY_LISTABLE,
        )
        unreadable_directory = InventoryEntry(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Private",
            kind=InventoryEntryKind.DIRECTORY,
            status=InventoryStatus.DIRECTORY_LIST_DENIED,
            error=_error(
                stage=TargetStage.TREE_WALK,
                status=TargetStatus.DIRECTORY_LIST_DENIED,
            ),
        )

        self.assertTrue(readable_file.readable)
        self.assertFalse(unreadable_file.readable)
        self.assertTrue(readable_directory.readable)
        self.assertFalse(unreadable_directory.readable)

    def test_non_file_share_is_visible_but_not_walkable(self) -> None:
        share = ShareInfo(
            target="10.20.30.40",
            name="IPC$",
            kind=ShareKind.NAMED_PIPE,
            access_status=ShareAccessStatus.CONNECTED,
        )
        entry = InventoryEntry(
            target="10.20.30.40",
            share_name="IPC$",
            kind=InventoryEntryKind.SHARE,
            status=InventoryStatus.NON_FILE_SHARE,
            share_kind=ShareKind.NAMED_PIPE,
        )

        self.assertFalse(share.content_walkable)
        self.assertFalse(entry.readable)
        with self.assertRaisesRegex(ValueError, "connected disk shares"):
            TreeWalkRequest(share=share, max_depth=3)

    def test_connected_disk_share_can_create_bounded_walk_request(self) -> None:
        share = ShareInfo(
            target="10.20.30.40",
            name="Finance",
            kind=ShareKind.DISK,
            access_status=ShareAccessStatus.CONNECTED,
        )
        request = TreeWalkRequest(share=share, start_path="Reports", max_depth=8)
        self.assertEqual(request.max_depth, 8)

        with self.assertRaisesRegex(ValueError, "cannot be negative"):
            TreeWalkRequest(share=share, max_depth=-1)

    def test_inventory_kind_status_size_and_error_invariants(self) -> None:
        with self.assertRaisesRegex(ValueError, "not valid"):
            InventoryEntry(
                target="host",
                share_name="share",
                relative_path="file.txt",
                kind=InventoryEntryKind.FILE,
                status=InventoryStatus.DIRECTORY_LISTABLE,
            )
        with self.assertRaisesRegex(ValueError, "Only file"):
            InventoryEntry(
                target="host",
                share_name="share",
                relative_path="folder",
                kind=InventoryEntryKind.DIRECTORY,
                status=InventoryStatus.DIRECTORY_LISTABLE,
                size=1,
            )
        with self.assertRaisesRegex(ValueError, "requires an error"):
            InventoryEntry(
                target="host",
                share_name="share",
                relative_path="file.txt",
                kind=InventoryEntryKind.FILE,
                status=InventoryStatus.FILE_READ_DENIED,
            )

    def test_inventory_repr_redacts_target_share_and_path(self) -> None:
        entry = InventoryEntry(
            target="10.20.30.40",
            share_name="Finance",
            relative_path="Passwords/production.txt",
            kind=InventoryEntryKind.FILE,
            status=InventoryStatus.FILE_READABLE,
            size=10,
        )
        rendered = repr(entry)
        self.assertNotIn("10.20.30.40", rendered)
        self.assertNotIn("Finance", rendered)
        self.assertNotIn("Passwords/production.txt", rendered)

    def test_share_access_result_requires_matching_error(self) -> None:
        access_error = _error(
            stage=TargetStage.AUTHORIZATION,
            status=TargetStatus.ACCESS_DENIED,
        )
        denied = ShareInfo(
            target="host",
            name="Finance",
            kind=ShareKind.DISK,
            access_status=ShareAccessStatus.ACCESS_DENIED,
            error=access_error,
        )
        self.assertFalse(denied.content_walkable)

        with self.assertRaisesRegex(ValueError, "must agree"):
            ShareInfo(
                target="host",
                name="Finance",
                kind=ShareKind.DISK,
                access_status=ShareAccessStatus.NOT_FOUND,
                error=access_error,
            )

    def test_share_enumeration_distinguishes_complete_and_partial(self) -> None:
        complete = ShareEnumerationResult(shares=(), complete=True)
        self.assertTrue(complete.complete)

        enumeration_error = _error(
            stage=TargetStage.SHARE_ENUMERATION,
            status=TargetStatus.SHARE_ENUM_DENIED,
        )
        partial = ShareEnumerationResult(
            shares=(),
            complete=False,
            error=enumeration_error,
        )
        self.assertFalse(partial.complete)
        with self.assertRaisesRegex(ValueError, "must contain"):
            ShareEnumerationResult(shares=(), complete=False)


class _BytesRangeReader(ValidatedRangeReader):
    def __init__(self, data: bytes, *, max_read_size: int = 4) -> None:
        super().__init__(size=len(data), max_read_size=max_read_size)
        self.data = data
        self.calls: list[tuple[int, int]] = []
        self.close_calls = 0

    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: object,
    ) -> bytes:
        self.calls.append((offset, length))
        return self.data[offset : offset + length]

    def _close_remote(self) -> None:
        self.close_calls += 1


class _OversizedRangeReader(ValidatedRangeReader):
    def __init__(self) -> None:
        super().__init__(size=4, max_read_size=4)

    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: object,
    ) -> bytes:
        return b"x" * (length + 1)


class _CancellingRangeReader(ValidatedRangeReader):
    def __init__(self, flag: CancellationFlag) -> None:
        super().__init__(size=4, max_read_size=4)
        self.flag = flag

    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: object,
    ) -> bytes:
        self.flag.cancel()
        return b"data"


class RangeReaderTests(unittest.TestCase):
    def test_range_reads_validate_and_only_request_remaining_bytes(self) -> None:
        reader = _BytesRangeReader(b"abcdefghij", max_read_size=4)

        self.assertEqual(
            reader.read_range(2, 4, cancellation=NEVER_CANCELLED),
            b"cdef",
        )
        self.assertEqual(
            reader.read_range(9, 4, cancellation=NEVER_CANCELLED),
            b"j",
        )
        self.assertEqual(reader.calls, [(2, 4), (9, 1)])

    def test_zero_length_and_end_of_file_do_not_call_remote_adapter(self) -> None:
        reader = _BytesRangeReader(b"abcd")
        self.assertEqual(reader.read_range(0, 0, cancellation=NEVER_CANCELLED), b"")
        self.assertEqual(reader.read_range(4, 4, cancellation=NEVER_CANCELLED), b"")
        self.assertEqual(reader.calls, [])

    def test_invalid_offsets_lengths_and_sizes_are_rejected(self) -> None:
        reader = _BytesRangeReader(b"abcd", max_read_size=2)
        cases = ((-1, 1), (0, -1), (5, 1), (0, 3))
        for offset, length in cases:
            with (
                self.subTest(offset=offset, length=length),
                self.assertRaises(ValueError),
            ):
                reader.read_range(offset, length, cancellation=NEVER_CANCELLED)
        with self.assertRaises(TypeError):
            reader.read_range(True, 1, cancellation=NEVER_CANCELLED)
        with self.assertRaises(ValueError):
            _BytesRangeReader(b"data", max_read_size=0)

    def test_adapter_cannot_return_more_than_requested(self) -> None:
        reader = _OversizedRangeReader()
        with self.assertRaisesRegex(RuntimeError, "more bytes"):
            reader.read_range(0, 2, cancellation=NEVER_CANCELLED)

    def test_iter_chunks_streams_forward_without_whole_file_api(self) -> None:
        reader = _BytesRangeReader(b"abcdefghij", max_read_size=4)
        chunks = list(reader.iter_chunks(chunk_size=4, cancellation=NEVER_CANCELLED))

        self.assertEqual(chunks, [b"abcd", b"efgh", b"ij"])
        self.assertEqual(reader.calls, [(0, 4), (4, 4), (8, 2)])
        for forbidden in ("download", "local_path", "temporary_file", "write"):
            self.assertFalse(hasattr(reader, forbidden))

    def test_cancellation_is_checked_before_and_after_remote_read(self) -> None:
        before = CancellationFlag()
        before.cancel()
        reader = _BytesRangeReader(b"abcd")
        with self.assertRaises(ScanCancelled):
            reader.read_range(0, 4, cancellation=before)
        self.assertEqual(reader.calls, [])

        during = CancellationFlag()
        reader_during = _CancellingRangeReader(during)
        with self.assertRaises(ScanCancelled):
            reader_during.read_range(0, 4, cancellation=during)

    def test_close_is_idempotent_and_context_manager_closes_remote_handle(self) -> None:
        reader = _BytesRangeReader(b"abcd")
        with reader as active:
            self.assertFalse(active.closed)
        self.assertTrue(reader.closed)
        self.assertEqual(reader.close_calls, 1)
        reader.close()
        self.assertEqual(reader.close_calls, 1)
        with self.assertRaisesRegex(ValueError, "closed"):
            reader.read_range(0, 1, cancellation=NEVER_CANCELLED)


class CancellationTests(unittest.TestCase):
    def test_flag_is_a_cooperative_one_way_cancellation_hook(self) -> None:
        flag = CancellationFlag()
        self.assertFalse(flag.cancelled)
        flag.raise_if_cancelled()

        flag.cancel()
        self.assertTrue(flag.cancelled)
        with self.assertRaises(ScanCancelled):
            flag.raise_if_cancelled()


if __name__ == "__main__":
    unittest.main()
