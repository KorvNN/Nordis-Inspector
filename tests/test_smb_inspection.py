from __future__ import annotations

import errno
import gzip
import io
import tarfile
import unittest
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from zipfile import ZipFile

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb.cancellation import (
    NEVER_CANCELLED,
    CancellationFlag,
    CancellationToken,
)
from nordis_smb_inspector.smb.contracts import (
    ConnectRequest,
    OpenFileRequest,
    TreeWalkRequest,
    ValidatedRangeReader,
)
from nordis_smb_inspector.smb.impacket_discovery import (
    ImpacketShareDiscoveryError,
    ShareDiscoveryResult,
)
from nordis_smb_inspector.smb.inspection import (
    ContentFinding,
    FindingMethod,
    InspectionEventKind,
    InspectionTargetEvent,
    inspect_target,
)
from nordis_smb_inspector.smb.models import (
    AuthAttempt,
    AuthAttemptOutcome,
    AuthenticationHistory,
    AuthMechanism,
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
    NegotiationInfo,
    RequirementSource,
    SecurityFeatureState,
    ShareAccessStatus,
    ShareInfo,
    ShareKind,
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
)


def _negotiation(*, max_read_size: int = 1_048_576) -> NegotiationInfo:
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
        max_read_size=max_read_size,
    )


def _authentication(
    mechanism: AuthMechanism = AuthMechanism.NTLM,
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


def _credential() -> Credential:
    return Credential.from_password(
        username="analyst",
        password="test-only-password",
        domain="NORDIS",
        auth_mode=AuthMode.AUTO,
    )


def _request() -> ConnectRequest:
    return ConnectRequest(target="192.0.2.10")


def _detail(
    stage: TargetStage,
    status: TargetStatus,
    *,
    operation: str = "mock_operation",
    raw_code: int = errno.EIO,
) -> SmbErrorDetail:
    return SmbErrorDetail(
        stage=stage,
        status=status,
        operation=operation,
        raw_code=raw_code,
        symbolic_name="MOCK_NORMALIZED_ERROR",
        safe_message="The operation was not available.",
    )


class _Connection:
    def __init__(
        self,
        *,
        negotiation: NegotiationInfo | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.negotiation = negotiation or _negotiation()
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
        connections: Iterable[_Connection] = (),
        *,
        error: BaseException | None = None,
    ) -> None:
        self.connections = list(connections)
        self.error = error
        self.calls = 0

    def connect(
        self,
        request: ConnectRequest,
        *,
        cancellation: CancellationToken,
    ) -> _Connection:
        cancellation.raise_if_cancelled()
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.connections[self.calls - 1]


class _Session:
    def __init__(
        self,
        connection: _Connection,
        *,
        authentication: AuthenticationHistory | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.connection = connection
        self.authentication = authentication or _authentication()
        self.signing_active = True
        self.encryption_active = False
        self.closed = False
        self.close_calls = 0
        self.close_error = close_error

    def close(self) -> None:
        self.close_calls += 1
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class _Authenticator:
    def __init__(
        self,
        *,
        session: _Session | None = None,
        error: BaseException | None = None,
        reconnect: bool = False,
    ) -> None:
        self.session = session
        self.error = error
        self.reconnect = reconnect
        self.connections: list[_Connection] = []

    def authenticate_credential(
        self,
        connection: _Connection,
        credential: Credential,
        *,
        kerberos_hostname: str | None,
        cancellation: CancellationToken,
        reconnect_for_ntlm=None,
    ) -> _Session:
        del credential, kerberos_hostname
        cancellation.raise_if_cancelled()
        self.connections.append(connection)
        if self.error is not None:
            raise self.error
        if self.reconnect:
            connection.close()
            replacement = reconnect_for_ntlm(cancellation=cancellation)
            self.connections.append(replacement)
            return _Session(replacement)
        if self.session is None:
            raise AssertionError("test authenticator has no session")
        return self.session


@dataclass(frozen=True)
class _Probe:
    share: ShareInfo
    inventory: InventoryEntry | None


class _Reader(ValidatedRangeReader):
    def __init__(
        self,
        data: bytes,
        *,
        cancellation_to_trigger: CancellationFlag | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        super().__init__(size=len(data), max_read_size=7)
        self.data = data
        self.read_calls: list[tuple[int, int]] = []
        self.cancellation_to_trigger = cancellation_to_trigger
        self.close_error = close_error
        self.remote_close_calls = 0

    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: CancellationToken,
    ) -> bytes:
        del cancellation
        self.read_calls.append((offset, length))
        if self.cancellation_to_trigger is not None:
            self.cancellation_to_trigger.cancel()
        return self.data[offset : offset + length]

    def _close_remote(self) -> None:
        self.remote_close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _FileAdapter:
    def __init__(
        self,
        *,
        probes: Iterable[_Probe] = (),
        entries: dict[str, Iterable[InventoryEntry]] | None = None,
        readers: dict[str, _Reader | BaseException] | None = None,
    ) -> None:
        self.probes = tuple(probes)
        self.entries = {key: tuple(value) for key, value in (entries or {}).items()}
        self.readers = readers or {}
        self.sessions: list[_Session] = []
        self.share_names: tuple[str, ...] = ()

    def probe_known_shares(
        self,
        session: _Session,
        *,
        target: str,
        share_names: Iterable[str],
        cancellation: CancellationToken,
    ) -> tuple[_Probe, ...]:
        del target
        cancellation.raise_if_cancelled()
        self.sessions.append(session)
        self.share_names = tuple(share_names)
        return self.probes

    def walk_tree(
        self,
        session: _Session,
        request: TreeWalkRequest,
        *,
        cancellation: CancellationToken,
    ) -> Iterator[InventoryEntry]:
        self.sessions.append(session)
        for entry in self.entries.get(request.share.name, ()):
            cancellation.raise_if_cancelled()
            yield entry

    def open_reader(
        self,
        session: _Session,
        request: OpenFileRequest,
        *,
        cancellation: CancellationToken,
    ) -> _Reader:
        cancellation.raise_if_cancelled()
        self.sessions.append(session)
        value = self.readers[request.relative_path]
        if isinstance(value, BaseException):
            raise value
        return value


class _ShareDiscoverer:
    def __init__(
        self,
        *,
        names: tuple[str, ...] = (),
        error: BaseException | None = None,
    ) -> None:
        self.names = names
        self.error = error
        self.calls: list[dict[str, object]] = []

    def discover(self, **kwargs: object) -> ShareDiscoveryResult:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return ShareDiscoveryResult(
            names=self.names,
            mechanism=kwargs["mechanism"],  # type: ignore[arg-type]
        )


def _connected_share(name: str = "Data") -> tuple[ShareInfo, InventoryEntry]:
    share = ShareInfo(
        target="192.0.2.10",
        name=name,
        kind=ShareKind.DISK,
        access_status=ShareAccessStatus.CONNECTED,
    )
    inventory = InventoryEntry(
        target="192.0.2.10",
        share_name=name,
        kind=InventoryEntryKind.SHARE,
        status=InventoryStatus.SHARE_CONNECTED,
        share_kind=ShareKind.DISK,
    )
    return share, inventory


def _file(
    path: str,
    *,
    status: InventoryStatus = InventoryStatus.FILE_READABLE,
    error: SmbErrorDetail | None = None,
) -> InventoryEntry:
    return InventoryEntry(
        target="192.0.2.10",
        share_name="Data",
        relative_path=path,
        kind=InventoryEntryKind.FILE,
        status=status,
        size=41,
        error=error,
    )


class InspectionTests(unittest.TestCase):
    def test_auto_reconnect_keeps_replacement_session_alive_through_stream_scan(self) -> None:
        initial = _Connection()
        replacement = _Connection(negotiation=_negotiation(max_read_size=131_072))
        connector = _Connector((initial, replacement))
        authenticator = _Authenticator(reconnect=True)
        share, share_inventory = _connected_share()
        reader = _Reader(b"header\nPASSWORD=alpha\npassword and password\ntail\n")
        file_entry = _file("configs/app.txt")
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (file_entry,)},
            readers={file_entry.relative_path: reader},
        )
        target_events: list[InspectionTargetEvent] = []
        inventory: list[InventoryEntry] = []
        findings: list[ContentFinding] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname="filesrv.nordis.local",
            share_discoverer=_ShareDiscoverer(names=("Data", "data")),
            search_terms=("password", "PASSWORD"),
            max_depth=8,
            connector=connector,
            authenticator=authenticator,
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            detect_patterns=False,
            on_target=target_events.append,
            on_inventory=inventory.append,
            on_finding=findings.append,
        )

        self.assertEqual(result.status, TargetStatus.COMPLETED)
        self.assertEqual(result.negotiation.dialect, replacement.negotiation.dialect)
        self.assertTrue(result.negotiation.security.signing.active)
        self.assertFalse(result.negotiation.security.encryption.active)
        self.assertEqual(result.shares_probed, 1)
        self.assertEqual(result.shares_accessible, 1)
        self.assertEqual(result.inventory_items, 2)
        self.assertEqual(result.files_seen, 1)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.findings, 2)
        self.assertEqual([item.line_number for item in findings], [2, 3])
        self.assertEqual(findings[0].full_line, "PASSWORD=alpha")
        self.assertEqual(findings[0].term, "password")
        self.assertTrue(reader.closed)
        self.assertGreater(len(reader.read_calls), 1)
        self.assertTrue(all(session is adapter.sessions[0] for session in adapter.sessions))
        self.assertIs(adapter.sessions[0].connection, replacement)
        self.assertTrue(adapter.sessions[0].closed)
        self.assertTrue(initial.closed)
        self.assertTrue(replacement.closed)
        self.assertEqual(adapter.share_names, ("Data",))
        self.assertEqual(target_events[-1].kind, InspectionEventKind.TERMINAL)
        self.assertEqual(target_events[-1].status, TargetStatus.COMPLETED)
        self.assertTrue(target_events[-1].terminal)

    def test_pattern_findings_include_rule_metadata_without_wordlist_hit(self) -> None:
        share, share_inventory = _connected_share()
        file_entry = _file("configs/service.env")
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (file_entry,)},
            readers={file_entry.relative_path: _Reader(b"client_secret=n0t-a-placeholder-value\n")},
        )
        findings: list[ContentFinding] = []
        connection = _Connection()

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("literal-that-is-not-present",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            on_finding=findings.append,
        )

        self.assertEqual(TargetStatus.COMPLETED, result.status)
        self.assertEqual(1, result.findings)
        self.assertEqual(1, len(findings))
        self.assertEqual(FindingMethod.PATTERN, findings[0].method)
        self.assertEqual("secret-assignment", findings[0].rule_id)
        self.assertEqual("Yapılandırma", findings[0].category)
        self.assertEqual("medium", findings[0].confidence.value)
        self.assertNotIn("n0t-a-placeholder-value", repr(findings[0]))

    def test_docx_is_extracted_over_range_reads_and_scanned(self) -> None:
        output = io.BytesIO()
        with ZipFile(output, "w") as archive:
            archive.writestr(
                "word/document.xml",
                '<w:document xmlns:w="urn:w"><w:p><w:t>password=OfficeSecret</w:t>'
                "</w:p></w:document>",
            )
        connection = _Connection()
        share, share_inventory = _connected_share()
        file_entry = _file("reports/secrets.docx")
        reader = _Reader(output.getvalue())
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (file_entry,)},
            readers={file_entry.relative_path: reader},
        )
        findings: list[ContentFinding] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("password",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            detect_patterns=False,
            on_finding=findings.append,
        )

        self.assertEqual(TargetStatus.COMPLETED, result.status)
        self.assertEqual(1, result.files_scanned)
        self.assertEqual(1, result.findings)
        self.assertEqual("password=OfficeSecret", findings[0].full_line)
        self.assertGreater(len(reader.read_calls), 1)
        self.assertTrue(reader.closed)

    def test_invalid_text_encoding_is_visible_as_inventory_and_target_error(self) -> None:
        connection = _Connection()
        share, share_inventory = _connected_share()
        file_entry = _file("legacy.txt")
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (file_entry,)},
            readers={file_entry.relative_path: _Reader(b"password=one\n\xfflegacy")},
        )
        inventory: list[InventoryEntry] = []
        events: list[InspectionTargetEvent] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("password",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            detect_patterns=False,
            on_inventory=inventory.append,
            on_target=events.append,
        )

        self.assertEqual(TargetStatus.PARTIAL_ACCESS, result.status)
        self.assertEqual(1, result.content_incomplete)
        self.assertEqual(InventoryStatus.READ_ERROR, inventory[-1].status)
        self.assertEqual("TEXT_ENCODING_UNDETERMINED", inventory[-1].error.symbolic_name)
        self.assertTrue(
            any(
                event.error is not None
                and event.error.symbolic_name == "TEXT_ENCODING_UNDETERMINED"
                for event in events
            )
        )

    def test_zip_members_are_inventory_items_and_findings_use_virtual_path(self) -> None:
        output = io.BytesIO()
        with ZipFile(output, "w") as archive:
            archive.writestr("configs/app.env", "client_secret=ArchiveSecret")
            archive.writestr("notes.txt", "no match")
        connection = _Connection()
        share, share_inventory = _connected_share()
        file_entry = _file("archives/configs.zip")
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (file_entry,)},
            readers={file_entry.relative_path: _Reader(output.getvalue())},
        )
        inventory: list[InventoryEntry] = []
        findings: list[ContentFinding] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("client_secret",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            detect_patterns=False,
            on_inventory=inventory.append,
            on_finding=findings.append,
        )

        self.assertEqual(TargetStatus.COMPLETED, result.status)
        self.assertEqual(3, result.files_seen)
        self.assertEqual(2, result.files_scanned)
        self.assertEqual(4, result.inventory_items)
        member_paths = {
            item.relative_path
            for item in inventory
            if "!/" in item.relative_path
        }
        self.assertEqual(
            {
                "archives/configs.zip!/configs/app.env",
                "archives/configs.zip!/notes.txt",
            },
            member_paths,
        )
        self.assertEqual(
            "archives/configs.zip!/configs/app.env",
            findings[0].path,
        )

    def test_tar_and_gzip_members_reach_archive_scan_path(self) -> None:
        tar_output = io.BytesIO()
        with tarfile.open(fileobj=tar_output, mode="w") as archive:
            content = b"password=TarSecret\n"
            info = tarfile.TarInfo("configs/app.env")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))

        gzip_output = io.BytesIO()
        with gzip.GzipFile(fileobj=gzip_output, mode="wb") as archive:
            archive.write(b"password=GzipSecret\n")

        cases = (
            (
                "archives/configs.tar",
                tar_output.getvalue(),
                "archives/configs.tar!/configs/app.env",
            ),
            (
                "archives/config.env.gz",
                gzip_output.getvalue(),
                "archives/config.env.gz!/config.env",
            ),
        )
        for path, raw, expected_member_path in cases:
            with self.subTest(path=path):
                connection = _Connection()
                share, share_inventory = _connected_share()
                file_entry = _file(path)
                adapter = _FileAdapter(
                    probes=(_Probe(share, share_inventory),),
                    entries={"Data": (file_entry,)},
                    readers={file_entry.relative_path: _Reader(raw)},
                )
                inventory: list[InventoryEntry] = []
                findings: list[ContentFinding] = []

                result = inspect_target(
                    target="192.0.2.10",
                    connect_request=_request(),
                    credential=_credential(),
                    kerberos_hostname=None,
                    share_discoverer=_ShareDiscoverer(names=("Data",)),
                    search_terms=("password",),
                    max_depth=8,
                    connector=_Connector((connection,)),
                    authenticator=_Authenticator(session=_Session(connection)),
                    file_adapter=adapter,
                    cancellation=NEVER_CANCELLED,
                    detect_patterns=False,
                    on_inventory=inventory.append,
                    on_finding=findings.append,
                )

                self.assertEqual(TargetStatus.COMPLETED, result.status)
                self.assertEqual(1, result.files_scanned)
                self.assertEqual(expected_member_path, findings[0].path)
                self.assertIn(
                    expected_member_path,
                    {item.relative_path for item in inventory},
                )

    def test_discovered_share_names_are_normalized_before_probing(self) -> None:
        connection = _Connection()
        share, share_inventory = _connected_share("#Archive")
        adapter = _FileAdapter(probes=(_Probe(share, share_inventory),))
        discoverer = _ShareDiscoverer(names=("#Archive", "#archive"))

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            search_terms=("password",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            share_discoverer=discoverer,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(TargetStatus.COMPLETED, result.status)
        self.assertEqual(("#Archive",), adapter.share_names)
        self.assertEqual(AuthMechanism.NTLM, discoverer.calls[0]["mechanism"])
        self.assertEqual(5.0, discoverer.calls[0]["timeout_seconds"])

    def test_share_discovery_failure_is_terminal_and_probes_nothing(self) -> None:
        connection = _Connection()
        share, share_inventory = _connected_share("NeverProbed")
        adapter = _FileAdapter(probes=(_Probe(share, share_inventory),))
        detail = SmbErrorDetail(
            stage=TargetStage.SHARE_ENUMERATION,
            status=TargetStatus.SHARE_ENUM_DENIED,
            operation="srvsvc_netr_share_enum",
            raw_code=0xC0000022,
            safe_message="Share listesi alınamadı.",
            symbolic_name="SHARE_ENUM_ACCESS_DENIED",
        )
        discoverer = _ShareDiscoverer(error=ImpacketShareDiscoveryError(detail))
        events: list[InspectionTargetEvent] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            search_terms=("password",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            share_discoverer=discoverer,
            cancellation=NEVER_CANCELLED,
            on_target=events.append,
        )

        self.assertEqual(TargetStatus.SHARE_ENUM_DENIED, result.status)
        self.assertEqual(TargetStage.SHARE_ENUMERATION, result.stage)
        self.assertFalse(result.completed)
        self.assertIs(result.outcome.error, detail)
        self.assertEqual((), adapter.share_names)
        self.assertEqual(0, result.shares_probed)
        discovery_errors = [
            event
            for event in events
            if event.kind is InspectionEventKind.STAGE_ERROR
            and event.stage is TargetStage.SHARE_ENUMERATION
            and event.error is not None
        ]
        self.assertEqual(1, len(discovery_errors))
        self.assertEqual(TargetStatus.SHARE_ENUM_DENIED, discovery_errors[0].status)
        self.assertEqual(0xC0000022, discovery_errors[0].error.raw_code)
        self.assertEqual(InspectionEventKind.TERMINAL, events[-1].kind)
        self.assertEqual(TargetStatus.SHARE_ENUM_DENIED, events[-1].status)
        self.assertIs(events[-1].error, detail)

    def test_empty_enumeration_is_not_reported_as_an_error(self) -> None:
        connection = _Connection()
        adapter = _FileAdapter()
        events: list[InspectionTargetEvent] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            search_terms=("password",),
            max_depth=8,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=_Session(connection)),
            file_adapter=adapter,
            share_discoverer=_ShareDiscoverer(names=()),
            cancellation=NEVER_CANCELLED,
            on_target=events.append,
        )

        # "This server exposes no shares" must stay distinguishable from
        # "the share list could not be read".
        self.assertEqual(TargetStatus.COMPLETED, result.status)
        self.assertEqual((), adapter.share_names)
        self.assertEqual(0, result.shares_probed)
        self.assertEqual([], [event for event in events if event.error is not None])

    def test_refused_and_timeout_preserve_normalized_terminal_outcome(self) -> None:
        for status, raw_code in (
            (TargetStatus.CONNECTION_REFUSED, errno.ECONNREFUSED),
            (TargetStatus.TIMEOUT_NO_RESPONSE, errno.ETIMEDOUT),
        ):
            with self.subTest(status=status):
                detail = _detail(
                    TargetStage.NETWORK,
                    status,
                    operation="transport_connect",
                    raw_code=raw_code,
                )
                error = SmbProtocolConnectError(
                    TargetOutcome(
                        target="192.0.2.10",
                        stage=TargetStage.NETWORK,
                        status=status,
                        error=detail,
                    )
                )
                events: list[InspectionTargetEvent] = []
                result = inspect_target(
                    target="192.0.2.10",
                    connect_request=_request(),
                    credential=_credential(),
                    kerberos_hostname=None,
                    share_discoverer=_ShareDiscoverer(names=("Data",)),
                    search_terms=("password",),
                    max_depth=1,
                    connector=_Connector(error=error),
                    authenticator=_Authenticator(),
                    file_adapter=_FileAdapter(),
                    cancellation=NEVER_CANCELLED,
                    on_target=events.append,
                )

                self.assertEqual(result.status, status)
                self.assertEqual(result.stage, TargetStage.NETWORK)
                self.assertEqual(result.outcome.error.raw_code, raw_code)
                self.assertEqual(events, [events[-1]])
                self.assertTrue(events[-1].terminal)

    def test_authentication_failure_closes_connection_without_file_access(self) -> None:
        connection = _Connection()
        detail = _detail(
            TargetStage.AUTHENTICATION,
            TargetStatus.AUTH_FAILED,
            operation="authenticate_ntlm",
        )
        failed_history = AuthenticationHistory(
            attempts=(
                AuthAttempt(
                    mechanism=AuthMechanism.NTLM,
                    outcome=AuthAttemptOutcome.FAILED,
                    error=detail,
                ),
            ),
            selected_mechanism=None,
        )
        error = SmbProtocolAuthenticationError(
            history=failed_history,
            detail=detail,
        )
        adapter = _FileAdapter()

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname="filesrv.nordis.local",
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("password",),
            max_depth=1,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(error=error),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(result.status, TargetStatus.AUTH_FAILED)
        self.assertEqual(result.authentication, failed_history)
        self.assertTrue(connection.closed)
        self.assertEqual(adapter.sessions, [])

    def test_inaccessible_share_and_files_are_emitted_and_mark_partial(self) -> None:
        connection = _Connection()
        session = _Session(connection)
        connected, connected_inventory = _connected_share()
        denied_detail = _detail(
            TargetStage.AUTHORIZATION,
            TargetStatus.ACCESS_DENIED,
            operation="known_share_connect",
            raw_code=errno.EACCES,
        )
        denied_share = ShareInfo(
            target="192.0.2.10",
            name="Finance",
            kind=ShareKind.UNKNOWN,
            access_status=ShareAccessStatus.ACCESS_DENIED,
            error=denied_detail,
        )
        denied_inventory = InventoryEntry(
            target="192.0.2.10",
            share_name="Finance",
            kind=InventoryEntryKind.SHARE,
            status=InventoryStatus.SHARE_ACCESS_DENIED,
            share_kind=ShareKind.DISK,
            error=denied_detail,
        )
        visible_denied_detail = _detail(
            TargetStage.FILE_READ,
            TargetStatus.FILE_READ_DENIED,
            operation="file_probe",
            raw_code=errno.EACCES,
        )
        visible_denied = _file(
            "private.txt",
            status=InventoryStatus.FILE_READ_DENIED,
            error=visible_denied_detail,
        )
        race_entry = _file("changed.txt")

        class _SafeReadError(OSError):
            def __init__(self) -> None:
                self.detail = _detail(
                    TargetStage.FILE_READ,
                    TargetStatus.SHARING_VIOLATION,
                    operation="file_open",
                )
                super().__init__(self.detail.raw_code, self.detail.safe_message)

        adapter = _FileAdapter(
            probes=(
                _Probe(denied_share, denied_inventory),
                _Probe(connected, connected_inventory),
            ),
            entries={"Data": (visible_denied, race_entry)},
            readers={"changed.txt": _SafeReadError()},
        )
        inventory: list[InventoryEntry] = []

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname="filesrv.nordis.local",
            share_discoverer=_ShareDiscoverer(names=("Finance", "Data")),
            search_terms=("password",),
            max_depth=3,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=session),
            file_adapter=adapter,
            cancellation=NEVER_CANCELLED,
            on_inventory=inventory.append,
        )

        self.assertEqual(result.status, TargetStatus.PARTIAL_ACCESS)
        self.assertEqual(result.shares_probed, 2)
        self.assertEqual(result.files_seen, 2)
        self.assertEqual(result.unreadable_files, 2)
        self.assertIn(InventoryStatus.SHARE_ACCESS_DENIED, {item.status for item in inventory})
        self.assertIn(InventoryStatus.FILE_READ_DENIED, {item.status for item in inventory})
        self.assertIn(InventoryStatus.SHARING_VIOLATION, {item.status for item in inventory})
        self.assertTrue(session.closed)
        self.assertTrue(connection.closed)

    def test_cancellation_during_remote_stream_closes_every_owned_handle(self) -> None:
        flag = CancellationFlag()
        connection = _Connection()
        session = _Session(connection)
        share, share_inventory = _connected_share()
        entry = _file("cancel.txt")
        reader = _Reader(b"password=secret\n", cancellation_to_trigger=flag)
        adapter = _FileAdapter(
            probes=(_Probe(share, share_inventory),),
            entries={"Data": (entry,)},
            readers={entry.relative_path: reader},
        )

        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname="filesrv.nordis.local",
            share_discoverer=_ShareDiscoverer(names=("Data",)),
            search_terms=("password",),
            max_depth=2,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=session),
            file_adapter=adapter,
            cancellation=flag,
        )

        self.assertEqual(result.status, TargetStatus.CANCELLED)
        self.assertTrue(reader.closed)
        self.assertTrue(session.closed)
        self.assertTrue(connection.closed)

    def test_cleanup_and_unexpected_errors_never_copy_raw_exception_text(self) -> None:
        raw_secret = "password=do-not-copy-this"
        connection = _Connection(close_error=RuntimeError(raw_secret))
        session = _Session(connection, close_error=RuntimeError(raw_secret))
        events: list[InspectionTargetEvent] = []
        result = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname="filesrv.nordis.local",
            share_discoverer=_ShareDiscoverer(names=()),
            search_terms=("password",),
            max_depth=0,
            connector=_Connector((connection,)),
            authenticator=_Authenticator(session=session),
            file_adapter=_FileAdapter(),
            cancellation=NEVER_CANCELLED,
            on_target=events.append,
        )

        self.assertEqual(result.status, TargetStatus.PARTIAL_ACCESS)
        self.assertTrue(result.cleanup_failed)
        self.assertNotIn(raw_secret, repr(result))
        self.assertNotIn(raw_secret, repr(events))

        unexpected_events: list[InspectionTargetEvent] = []
        unexpected = inspect_target(
            target="192.0.2.10",
            connect_request=_request(),
            credential=_credential(),
            kerberos_hostname=None,
            share_discoverer=_ShareDiscoverer(names=()),
            search_terms=("password",),
            max_depth=0,
            connector=_Connector(error=RuntimeError(raw_secret)),
            authenticator=_Authenticator(),
            file_adapter=_FileAdapter(),
            cancellation=NEVER_CANCELLED,
            on_target=unexpected_events.append,
        )
        self.assertEqual(unexpected.status, TargetStatus.NEGOTIATION_FAILED)
        self.assertNotIn(raw_secret, repr(unexpected))
        self.assertNotIn(raw_secret, repr(unexpected_events))


if __name__ == "__main__":
    unittest.main()
