from __future__ import annotations

import logging
import unittest
from datetime import UTC, datetime

from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
    NoMoreFiles,
    SharingViolation,
)
from smbprotocol.file_info import FileDirectoryInformation
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FilePipePrinterAccessMask,
    QueryDirectoryFlags,
    ShareAccess,
)
from smbprotocol.tree import ShareType, SMB2TreeConnectResponse

from nordis_smb_inspector.smb import (
    NEVER_CANCELLED,
    CancellationFlag,
    InventoryStatus,
    OpenFileRequest,
    ScanCancelled,
    ShareAccessStatus,
    ShareInfo,
    ShareKind,
    TargetStatus,
    TreeWalkRequest,
)
from nordis_smb_inspector.smb.smbprotocol_files import (
    InspectableTreeConnect,
    SmbProtocolFileAdapter,
    SmbProtocolFileCloseError,
    SmbProtocolFileOperationError,
)


class _ValueField:
    def __init__(self, value) -> None:
        self.value = value

    def get_value(self):
        return self.value


class _FakeConnection:
    def __init__(self, *, max_read_size: int = 8_388_608) -> None:
        self.max_read_size = max_read_size
        self.dialect = 0x0311
        self.supports_encryption = True


class _NativeSession:
    def __init__(self, *, max_read_size: int = 8_388_608) -> None:
        self.connection = _FakeConnection(max_read_size=max_read_size)
        self.session_id = 17
        self.tree_connect_table = {}


class _SessionHandle:
    def __init__(self, native: _NativeSession | None = None) -> None:
        self.native = native or _NativeSession()
        self.closed = False

    @property
    def _native_session(self) -> _NativeSession:
        if self.closed:
            raise ValueError("session closed")
        return self.native


class _FakeTree:
    def __init__(
        self,
        session: _NativeSession,
        share_name: str,
        *,
        share_type: int = ShareType.SMB2_SHARE_TYPE_DISK,
        connect_error: Exception | None = None,
        disconnect_error: Exception | None = None,
    ) -> None:
        self.session = session
        self.share_name = share_name
        self.share_type = share_type
        self.connect_error = connect_error
        self.disconnect_error = disconnect_error
        self.connect_calls: list[bool] = []
        self.disconnect_calls = 0
        self.connected = False

    def connect(self, require_secure_negotiate: bool = True) -> None:
        self.connect_calls.append(require_secure_negotiate)
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = True

    def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.connected = False
        if self.disconnect_error is not None:
            raise self.disconnect_error


class _TreeFactory:
    def __init__(self, plans: dict[str, dict[str, object]] | None = None) -> None:
        self.plans = plans or {}
        self.trees: list[_FakeTree] = []

    def __call__(self, session: _NativeSession, share_name: str) -> _FakeTree:
        tree = _FakeTree(session, share_name, **self.plans.get(share_name, {}))
        self.trees.append(tree)
        return tree


class _FakeOpen:
    def __init__(
        self,
        tree: _FakeTree,
        name: str,
        *,
        create_error: Exception | None = None,
        queries: tuple[object, ...] = (),
        data: bytes = b"",
        size: int | None = None,
        read_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.tree = tree
        self.name = name
        self.create_error = create_error
        self.queries = list(queries)
        self.data = data
        self.end_of_file = len(data) if size is None else size
        self.read_error = read_error
        self.close_error = close_error
        self.create_calls: list[dict[str, object]] = []
        self.query_calls: list[dict[str, object]] = []
        self.read_calls: list[dict[str, object]] = []
        self.close_calls: list[dict[str, object]] = []

    def create(self, **kwargs):
        self.create_calls.append(dict(kwargs))
        if self.create_error is not None:
            raise self.create_error
        return None

    def query_directory(self, **kwargs):
        self.query_calls.append(dict(kwargs))
        if not self.queries:
            raise NoMoreFiles()
        result = self.queries.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def read(self, **kwargs) -> bytes:
        self.read_calls.append(dict(kwargs))
        if self.read_error is not None:
            raise self.read_error
        offset = kwargs["offset"]
        length = kwargs["length"]
        return self.data[offset : offset + length]

    def close(self, **kwargs):
        self.close_calls.append(dict(kwargs))
        if self.close_error is not None:
            raise self.close_error
        return None


class _OpenFactory:
    def __init__(self, plans: dict[str, dict[str, object]] | None = None) -> None:
        self.plans = plans or {}
        self.opens: list[_FakeOpen] = []

    def __call__(self, tree: _FakeTree, name: str) -> _FakeOpen:
        remote_open = _FakeOpen(tree, name, **self.plans.get(name, {}))
        self.opens.append(remote_open)
        return remote_open

    def named(self, name: str) -> list[_FakeOpen]:
        return [remote_open for remote_open in self.opens if remote_open.name == name]


def _entry(
    name: str,
    *,
    directory: bool = False,
    reparse: bool = False,
    size: int = 0,
    modified: datetime | None = None,
) -> FileDirectoryInformation:
    value = FileDirectoryInformation()
    value["file_name"] = name.encode("utf-16-le")
    value["file_attributes"] = (
        (FileAttributes.FILE_ATTRIBUTE_DIRECTORY if directory else 0)
        | (FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT if reparse else 0)
    )
    value["end_of_file"] = size
    value["last_write_time"] = modified or datetime(2026, 8, 13, tzinfo=UTC)
    return value


def _disk_share(target: str = "10.20.30.40", name: str = "Finance") -> ShareInfo:
    return ShareInfo(
        target=target,
        name=name,
        kind=ShareKind.DISK,
        access_status=ShareAccessStatus.CONNECTED,
    )


class InspectableTreeTests(unittest.TestCase):
    def test_pinned_tree_connect_retains_wire_share_type(self) -> None:
        tree_response = SMB2TreeConnectResponse()
        tree_response["share_type"] = ShareType.SMB2_SHARE_TYPE_PRINT
        tree_response["share_flags"] = 0
        tree_response["capabilities"] = 0
        tree_response["maximal_access"] = 0x1

        class WireConnection(_FakeConnection):
            def __init__(self) -> None:
                super().__init__()
                self.sent = []

            def send(self, request, **kwargs):
                self.sent.append((request, kwargs))
                return object()

            def receive(self, request):
                return {
                    "data": _ValueField(tree_response.pack()),
                    "tree_id": _ValueField(42),
                }

        session = _NativeSession()
        session.connection = WireConnection()
        tree = InspectableTreeConnect(session, r"\\10.20.30.40\Printer")

        tree.connect(require_secure_negotiate=False)

        self.assertEqual(tree.share_type, ShareType.SMB2_SHARE_TYPE_PRINT)
        self.assertEqual(tree.tree_connect_id, 42)
        self.assertIs(session.tree_connect_table[42], tree)
        request, kwargs = session.connection.sent[0]
        self.assertEqual(kwargs, {"sid": 17})
        self.assertEqual(
            request["buffer"].get_value().decode("utf-16-le"),
            r"\\10.20.30.40\Printer",
        )


class KnownShareTests(unittest.TestCase):
    def test_direct_probe_normalizes_connected_denied_not_found_and_error(self) -> None:
        target = "10.20.30.40"
        plans = {
            rf"\\{target}\IPC$": {"share_type": ShareType.SMB2_SHARE_TYPE_PIPE},
            rf"\\{target}\Denied": {"connect_error": AccessDenied()},
            rf"\\{target}\Missing": {"connect_error": BadNetworkName()},
            rf"\\{target}\Broken": {"connect_error": RuntimeError("target secret")},
        }
        trees = _TreeFactory(plans)
        adapter = SmbProtocolFileAdapter(tree_factory=trees, require_secure_negotiate=True)

        results = adapter.probe_known_shares(
            _SessionHandle(),
            target=target,
            share_names=(
                "# comment",
                " Finance ",
                "finance",
                "IPC$",
                "Denied",
                "Missing",
                "Broken",
                "",
            ),
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(
            [result.share.name for result in results],
            ["Finance", "IPC$", "Denied", "Missing", "Broken"],
        )
        self.assertIs(results[0].share.kind, ShareKind.DISK)
        self.assertIs(results[0].inventory.status, InventoryStatus.SHARE_CONNECTED)
        self.assertIs(results[1].share.kind, ShareKind.NAMED_PIPE)
        self.assertIs(results[1].inventory.status, InventoryStatus.NON_FILE_SHARE)
        self.assertIs(results[2].share.access_status, ShareAccessStatus.ACCESS_DENIED)
        self.assertIs(results[2].inventory.status, InventoryStatus.SHARE_ACCESS_DENIED)
        self.assertIs(results[3].share.access_status, ShareAccessStatus.NOT_FOUND)
        self.assertIsNone(results[3].inventory)
        self.assertIs(results[4].share.access_status, ShareAccessStatus.ERROR)
        self.assertIsNone(results[4].inventory)
        self.assertEqual([tree.disconnect_calls for tree in trees.trees], [1] * 5)
        self.assertTrue(all(tree.connect_calls == [True] for tree in trees.trees))
        for result in results:
            self.assertNotIn(target, repr(result.share))
            self.assertNotIn(result.share.name, repr(result.share))

    def test_share_name_path_injection_is_rejected_before_tree_connect(self) -> None:
        factory = _TreeFactory()
        adapter = SmbProtocolFileAdapter(tree_factory=factory)
        for name in (r"Finance\Admin", "../Finance", "Finance\nSecrets"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.probe_known_shares(
                    _SessionHandle(),
                    target="10.20.30.40",
                    share_names=(name,),
                    cancellation=NEVER_CANCELLED,
                )
        self.assertEqual(factory.trees, [])

    def test_cancellation_between_probes_stops_and_disconnects_current_tree(self) -> None:
        cancellation = CancellationFlag()

        class CancellingTree(_FakeTree):
            def connect(self, require_secure_negotiate: bool = True) -> None:
                super().connect(require_secure_negotiate)
                cancellation.cancel()

        class Factory:
            def __init__(self) -> None:
                self.trees = []

            def __call__(self, session, share_name):
                tree = CancellingTree(session, share_name)
                self.trees.append(tree)
                return tree

        factory = Factory()
        with self.assertRaises(ScanCancelled):
            SmbProtocolFileAdapter(tree_factory=factory).probe_known_shares(
                _SessionHandle(),
                target="10.20.30.40",
                share_names=("Finance", "HR"),
                cancellation=cancellation,
            )
        self.assertEqual(len(factory.trees), 1)
        self.assertEqual(factory.trees[0].disconnect_calls, 1)


class TreeWalkTests(unittest.TestCase):
    def _adapter(self):
        root_entries = [
            _entry("."),
            _entry(".."),
            _entry("Reports", directory=True),
            _entry("Private", directory=True),
            _entry("LinkedDir", directory=True, reparse=True),
            _entry("readable.txt", size=12),
            _entry("denied.txt", size=22),
            _entry("busy.txt", size=32),
            _entry("broken.txt", size=42),
            _entry("linked.txt", reparse=True, size=52),
        ]
        reports_entries = [
            _entry("nested.txt", size=62),
            _entry("TooDeep", directory=True),
        ]
        opens = _OpenFactory(
            {
                "": {"queries": (root_entries, NoMoreFiles())},
                "Reports": {"queries": (reports_entries, NoMoreFiles())},
                "Private": {"create_error": AccessDenied()},
                "readable.txt": {"size": 12},
                "denied.txt": {"create_error": AccessDenied(), "size": 22},
                "busy.txt": {"create_error": SharingViolation(), "size": 32},
                "broken.txt": {"create_error": RuntimeError("sensitive path"), "size": 42},
                "Reports\\nested.txt": {"size": 62},
            }
        )
        trees = _TreeFactory()
        adapter = SmbProtocolFileAdapter(
            tree_factory=trees,
            open_factory=opens,
            query_max_output=4096,
        )
        return adapter, trees, opens

    def test_bounded_recursive_walk_inventories_readable_and_unreadable_entries(self) -> None:
        adapter, trees, opens = self._adapter()
        request = TreeWalkRequest(share=_disk_share(), max_depth=1)

        entries = list(
            adapter.walk_tree(
                _SessionHandle(),
                request,
                cancellation=NEVER_CANCELLED,
            )
        )
        by_path = {entry.relative_path: entry for entry in entries}

        self.assertIs(by_path["Reports"].status, InventoryStatus.DIRECTORY_LISTABLE)
        self.assertIs(by_path["Private"].status, InventoryStatus.DIRECTORY_LIST_DENIED)
        self.assertIs(by_path["LinkedDir"].status, InventoryStatus.DEPTH_LIMIT_REACHED)
        self.assertIs(by_path["Reports/TooDeep"].status, InventoryStatus.DEPTH_LIMIT_REACHED)
        self.assertIs(by_path["readable.txt"].status, InventoryStatus.FILE_READABLE)
        self.assertIs(by_path["denied.txt"].status, InventoryStatus.FILE_READ_DENIED)
        self.assertIs(by_path["busy.txt"].status, InventoryStatus.SHARING_VIOLATION)
        self.assertIs(by_path["broken.txt"].status, InventoryStatus.READ_ERROR)
        self.assertIs(by_path["linked.txt"].status, InventoryStatus.READ_ERROR)
        self.assertEqual(
            by_path["linked.txt"].error.symbolic_name,
            "REPARSE_POINT_SKIPPED",
        )
        self.assertIs(by_path["Reports/nested.txt"].status, InventoryStatus.FILE_READABLE)
        self.assertEqual(by_path["Reports/nested.txt"].size, 62)
        self.assertIsInstance(by_path["Reports/nested.txt"].modified_at, datetime)
        self.assertEqual(trees.trees[0].disconnect_calls, 1)

        root = opens.named("")[0]
        self.assertEqual(
            [call["flags"] for call in root.query_calls],
            [QueryDirectoryFlags.SMB2_RESTART_SCANS, 0],
        )
        self.assertTrue(all(call["max_output"] == 4096 for call in root.query_calls))

    def test_every_create_is_file_open_and_contains_no_write_access(self) -> None:
        adapter, _trees, opens = self._adapter()
        list(
            adapter.walk_tree(
                _SessionHandle(),
                TreeWalkRequest(share=_disk_share(), max_depth=1),
                cancellation=NEVER_CANCELLED,
            )
        )
        write_masks = {
            FilePipePrinterAccessMask.FILE_WRITE_DATA,
            FilePipePrinterAccessMask.FILE_APPEND_DATA,
            FilePipePrinterAccessMask.FILE_WRITE_EA,
            FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES,
            FilePipePrinterAccessMask.DELETE,
            DirectoryAccessMask.FILE_ADD_FILE,
            DirectoryAccessMask.FILE_ADD_SUBDIRECTORY,
        }
        for remote_open in opens.opens:
            for call in remote_open.create_calls:
                self.assertEqual(call["create_disposition"], CreateDisposition.FILE_OPEN)
                self.assertEqual(call["file_attributes"], 0)
                self.assertEqual(
                    call["share_access"],
                    ShareAccess.FILE_SHARE_READ
                    | ShareAccess.FILE_SHARE_WRITE
                    | ShareAccess.FILE_SHARE_DELETE,
                )
                desired = call["desired_access"]
                self.assertTrue(all(desired & mask == 0 for mask in write_masks))
                self.assertTrue(
                    call["create_options"] & CreateOptions.FILE_OPEN_REPARSE_POINT
                )
                self.assertNotEqual(
                    call["create_options"] & CreateOptions.FILE_DELETE_ON_CLOSE,
                    CreateOptions.FILE_DELETE_ON_CLOSE,
                )

    def test_unreadable_share_root_is_a_visible_directory_row(self) -> None:
        opens = _OpenFactory({"": {"create_error": AccessDenied()}})
        adapter = SmbProtocolFileAdapter(
            tree_factory=_TreeFactory(),
            open_factory=opens,
        )

        entries = list(
            adapter.walk_tree(
                _SessionHandle(),
                TreeWalkRequest(share=_disk_share(), max_depth=1),
                cancellation=NEVER_CANCELLED,
            )
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].relative_path, "")
        self.assertIs(entries[0].status, InventoryStatus.DIRECTORY_LIST_DENIED)

    def test_tree_connect_failure_is_normalized_without_sensitive_text(self) -> None:
        target = "10.20.30.40"
        share_name = "Finance"
        trees = _TreeFactory(
            {
                rf"\\{target}\{share_name}": {
                    "connect_error": RuntimeError(
                        f"native failure for {target} {share_name} secret-identity"
                    )
                }
            }
        )
        generator = SmbProtocolFileAdapter(tree_factory=trees).walk_tree(
            _SessionHandle(),
            TreeWalkRequest(share=_disk_share(target, share_name), max_depth=1),
            cancellation=NEVER_CANCELLED,
        )

        with self.assertRaises(SmbProtocolFileOperationError) as caught:
            list(generator)

        self.assertIs(caught.exception.detail.status, TargetStatus.SHARE_CONNECT_ERROR)
        for sensitive in (target, share_name, "secret-identity"):
            self.assertNotIn(sensitive, repr(caught.exception))
            self.assertNotIn(sensitive, str(caught.exception))
        self.assertEqual(trees.trees[0].disconnect_calls, 1)

    def test_start_path_is_normalized_and_dot_traversal_rejected(self) -> None:
        opens = _OpenFactory({"Reports\\2026": {"queries": (NoMoreFiles(),)}})
        adapter = SmbProtocolFileAdapter(
            tree_factory=_TreeFactory(),
            open_factory=opens,
        )
        entries = list(
            adapter.walk_tree(
                _SessionHandle(),
                TreeWalkRequest(
                    share=_disk_share(),
                    start_path="Reports/2026",
                    max_depth=1,
                ),
                cancellation=NEVER_CANCELLED,
            )
        )
        self.assertEqual(entries[0].relative_path, "Reports/2026")
        self.assertIs(entries[0].status, InventoryStatus.DIRECTORY_LISTABLE)

        generator = adapter.walk_tree(
            _SessionHandle(),
            TreeWalkRequest(
                share=_disk_share(),
                start_path="../escape",
                max_depth=1,
            ),
            cancellation=NEVER_CANCELLED,
        )
        with self.assertRaisesRegex(ValueError, "dot traversal"):
            next(generator)

    def test_follow_reparse_points_is_rejected_before_tree_connect(self) -> None:
        trees = _TreeFactory()
        adapter = SmbProtocolFileAdapter(tree_factory=trees)
        generator = adapter.walk_tree(
            _SessionHandle(),
            TreeWalkRequest(
                share=_disk_share(),
                max_depth=1,
                follow_reparse_points=True,
            ),
            cancellation=NEVER_CANCELLED,
        )
        with self.assertRaisesRegex(ValueError, "never follows"):
            next(generator)
        self.assertEqual(trees.trees, [])

    def test_cancellation_during_walk_closes_directory_and_tree(self) -> None:
        cancellation = CancellationFlag()

        class CancellingOpen(_FakeOpen):
            def query_directory(self, **kwargs):
                result = super().query_directory(**kwargs)
                cancellation.cancel()
                return result

        class Factory(_OpenFactory):
            def __call__(self, tree, name):
                remote_open = CancellingOpen(
                    tree,
                    name,
                    queries=([_entry("secret.txt")],),
                )
                self.opens.append(remote_open)
                return remote_open

        trees = _TreeFactory()
        opens = Factory()
        generator = SmbProtocolFileAdapter(
            tree_factory=trees,
            open_factory=opens,
        ).walk_tree(
            _SessionHandle(),
            TreeWalkRequest(share=_disk_share(), max_depth=1),
            cancellation=cancellation,
        )

        with self.assertRaises(ScanCancelled):
            list(generator)
        self.assertEqual(opens.opens[0].close_calls, [{"get_attributes": False, "send": True}])
        self.assertEqual(trees.trees[0].disconnect_calls, 1)


class RangeReaderTests(unittest.TestCase):
    def test_reader_uses_actual_remote_size_negotiated_cap_and_offset_reads(self) -> None:
        data = b"abcdefghij"
        opens = _OpenFactory({"Reports\\data.txt": {"data": data}})
        trees = _TreeFactory()
        adapter = SmbProtocolFileAdapter(
            tree_factory=trees,
            open_factory=opens,
            max_range_size=4,
        )

        reader = adapter.open_reader(
            _SessionHandle(_NativeSession(max_read_size=8)),
            OpenFileRequest(
                target="10.20.30.40",
                share_name="Finance",
                relative_path="Reports/data.txt",
                expected_size=999,
            ),
            cancellation=NEVER_CANCELLED,
        )

        self.assertEqual(reader.size, len(data))
        self.assertEqual(reader.max_read_size, 4)
        self.assertEqual(reader.read_range(3, 4, cancellation=NEVER_CANCELLED), b"defg")
        remote_open = opens.opens[0]
        self.assertEqual(
            remote_open.read_calls,
            [
                {
                    "offset": 3,
                    "length": 4,
                    "min_length": 0,
                    "unbuffered": False,
                    "wait": True,
                    "send": True,
                }
            ],
        )
        reader.close()
        self.assertTrue(reader.closed)
        self.assertEqual(len(remote_open.close_calls), 1)
        self.assertEqual(trees.trees[0].disconnect_calls, 1)

    def test_open_reader_uses_read_only_non_directory_create(self) -> None:
        opens = _OpenFactory({"data.txt": {"data": b"data"}})
        reader = SmbProtocolFileAdapter(
            tree_factory=_TreeFactory(),
            open_factory=opens,
        ).open_reader(
            _SessionHandle(),
            OpenFileRequest(
                target="10.20.30.40",
                share_name="Finance",
                relative_path="data.txt",
            ),
            cancellation=NEVER_CANCELLED,
        )
        call = opens.opens[0].create_calls[0]
        self.assertEqual(call["create_disposition"], CreateDisposition.FILE_OPEN)
        self.assertEqual(
            call["desired_access"],
            FilePipePrinterAccessMask.FILE_READ_DATA
            | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES,
        )
        self.assertEqual(
            call["create_options"],
            CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_OPEN_REPARSE_POINT,
        )
        reader.close()

    def test_open_and_read_failures_are_safe_and_preserve_status(self) -> None:
        target = "10.20.30.40"
        opens = _OpenFactory({"secret.txt": {"create_error": AccessDenied()}})
        with self.assertRaises(SmbProtocolFileOperationError) as caught:
            SmbProtocolFileAdapter(
                tree_factory=_TreeFactory(),
                open_factory=opens,
            ).open_reader(
                _SessionHandle(),
                OpenFileRequest(
                    target=target,
                    share_name="Finance",
                    relative_path="secret.txt",
                ),
                cancellation=NEVER_CANCELLED,
            )
        self.assertIs(caught.exception.detail.status, TargetStatus.FILE_READ_DENIED)
        self.assertNotIn(target, repr(caught.exception))
        self.assertNotIn("secret.txt", repr(caught.exception))

        read_opens = _OpenFactory(
            {"busy.txt": {"size": 4, "read_error": SharingViolation()}}
        )
        reader = SmbProtocolFileAdapter(
            tree_factory=_TreeFactory(),
            open_factory=read_opens,
        ).open_reader(
            _SessionHandle(),
            OpenFileRequest(
                target=target,
                share_name="Finance",
                relative_path="busy.txt",
            ),
            cancellation=NEVER_CANCELLED,
        )
        with self.assertRaises(SmbProtocolFileOperationError) as caught_read:
            reader.read_range(0, 4, cancellation=NEVER_CANCELLED)
        self.assertIs(
            caught_read.exception.detail.status,
            TargetStatus.SHARING_VIOLATION,
        )
        reader.close()

    def test_cancellation_and_close_error_release_both_handles(self) -> None:
        cancellation = CancellationFlag()
        cancellation.cancel()
        trees = _TreeFactory()
        opens = _OpenFactory({"data.txt": {"data": b"data"}})
        with self.assertRaises(ScanCancelled):
            SmbProtocolFileAdapter(
                tree_factory=trees,
                open_factory=opens,
            ).open_reader(
                _SessionHandle(),
                OpenFileRequest(
                    target="10.20.30.40",
                    share_name="Finance",
                    relative_path="data.txt",
                ),
                cancellation=cancellation,
            )
        self.assertEqual(opens.opens, [])
        self.assertEqual(trees.trees[0].disconnect_calls, 1)

        close_trees = _TreeFactory(
            {r"\\10.20.30.40\Finance": {"disconnect_error": RuntimeError("secret")}}
        )
        close_opens = _OpenFactory(
            {"data.txt": {"data": b"data", "close_error": RuntimeError("identity")}}
        )
        reader = SmbProtocolFileAdapter(
            tree_factory=close_trees,
            open_factory=close_opens,
        ).open_reader(
            _SessionHandle(),
            OpenFileRequest(
                target="10.20.30.40",
                share_name="Finance",
                relative_path="data.txt",
            ),
            cancellation=NEVER_CANCELLED,
        )
        with self.assertRaises(SmbProtocolFileCloseError) as caught:
            reader.close()
        self.assertTrue(reader.closed)
        self.assertNotIn("secret", repr(caught.exception))
        self.assertNotIn("identity", str(caught.exception))
        self.assertEqual(close_opens.opens[0].close_calls.__len__(), 1)
        self.assertEqual(close_trees.trees[0].disconnect_calls, 1)


class AdapterInvariantTests(unittest.TestCase):
    def test_invalid_resource_limits_are_rejected(self) -> None:
        for kwargs in ({"query_max_output": 0}, {"max_range_size": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SmbProtocolFileAdapter(**kwargs)

    def test_file_and_tree_dependency_logging_is_disabled(self) -> None:
        for name in ("smbprotocol.open", "smbprotocol.tree"):
            logging.getLogger(name).disabled = False
        SmbProtocolFileAdapter()
        self.assertTrue(logging.getLogger("smbprotocol.open").disabled)
        self.assertTrue(logging.getLogger("smbprotocol.tree").disabled)

    def test_wrong_session_object_is_rejected_without_network(self) -> None:
        with self.assertRaises(TypeError):
            SmbProtocolFileAdapter().probe_known_shares(
                object(),
                target="10.20.30.40",
                share_names=("Finance",),
                cancellation=NEVER_CANCELLED,
            )


if __name__ == "__main__":
    unittest.main()
