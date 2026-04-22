"""Read-only known-share, tree-walk, and range-read smbprotocol adapter.

The adapter never creates or mutates remote objects.  Every CREATE request uses
``FILE_OPEN`` with list/read/attribute access only, and every reparse point is
inventoried without being traversed.
"""

from __future__ import annotations

import errno
import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from smbprotocol import Dialects
from smbprotocol.exceptions import (
    AccessDenied,
    BadNetworkName,
    NoMoreFiles,
    ObjectNameNotFound,
    ObjectPathNotFound,
    SharingViolation,
)
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FileInformationClass,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    QueryDirectoryFlags,
    ShareAccess,
)
from smbprotocol.tree import (
    ShareCapabilities,
    ShareFlags,
    ShareType,
    SMB2TreeConnectRequest,
    SMB2TreeConnectResponse,
    TreeConnect,
)

from .cancellation import CancellationToken, ScanCancelled
from .contracts import OpenFileRequest, TreeWalkRequest, ValidatedRangeReader
from .models import (
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
    ShareAccessStatus,
    ShareInfo,
    ShareKind,
    SmbErrorDetail,
    TargetStage,
    TargetStatus,
)
from .smbprotocol_auth_adapter import SmbProtocolSessionHandle

_DEPENDENCY_LOGGERS = (
    "smbprotocol.open",
    "smbprotocol.tree",
)

_DIRECTORY_ACCESS = (
    DirectoryAccessMask.FILE_LIST_DIRECTORY | DirectoryAccessMask.FILE_READ_ATTRIBUTES
)
_FILE_ACCESS = (
    FilePipePrinterAccessMask.FILE_READ_DATA
    | FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES
)
_SHARE_ACCESS = (
    ShareAccess.FILE_SHARE_READ
    | ShareAccess.FILE_SHARE_WRITE
    | ShareAccess.FILE_SHARE_DELETE
)
_DIRECTORY_OPTIONS = (
    CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_OPEN_REPARSE_POINT
)
_FILE_OPTIONS = (
    CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_OPEN_REPARSE_POINT
)

_SHARE_TYPES: dict[int, ShareKind] = {
    ShareType.SMB2_SHARE_TYPE_DISK: ShareKind.DISK,
    ShareType.SMB2_SHARE_TYPE_PIPE: ShareKind.NAMED_PIPE,
    ShareType.SMB2_SHARE_TYPE_PRINT: ShareKind.PRINT_QUEUE,
}

_STATUS_NAMES = {
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
    0xC0000043: "STATUS_SHARING_VIOLATION",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
}


class _NativeSession(Protocol):
    connection: Any
    session_id: int
    tree_connect_table: dict[int, object]


class _NativeTree(Protocol):
    share_type: int | None

    def connect(self, require_secure_negotiate: bool = True) -> None: ...

    def disconnect(self) -> None: ...


class _TreeFactory(Protocol):
    def __call__(self, session: _NativeSession, share_name: str) -> _NativeTree: ...


class _NativeOpen(Protocol):
    end_of_file: int | None

    def create(
        self,
        impersonation_level: int,
        desired_access: int,
        file_attributes: int,
        share_access: int,
        create_disposition: int,
        create_options: int,
        create_contexts: object = None,
        oplock_level: int = 0,
        send: bool = True,
    ) -> object: ...

    def query_directory(
        self,
        pattern: str,
        file_information_class: int,
        flags: int | None = None,
        file_index: int = 0,
        max_output: int = 65_536,
        send: bool = True,
    ) -> list[object]: ...

    def read(
        self,
        offset: int,
        length: int,
        min_length: int = 0,
        unbuffered: bool = False,
        wait: bool = True,
        send: bool = True,
    ) -> bytes: ...

    def close(self, get_attributes: bool = False, send: bool = True) -> object: ...


class _OpenFactory(Protocol):
    def __call__(self, tree: _NativeTree, name: str) -> _NativeOpen: ...


class InspectableTreeConnect(TreeConnect):
    """Pinned 1.17 TreeConnect variant retaining the negotiated share type."""

    share_type: int | None

    def __init__(self, session: _NativeSession, share_name: str) -> None:
        super().__init__(session, share_name)
        self.share_type = None

    def connect(self, require_secure_negotiate: bool = True) -> None:
        request_message = SMB2TreeConnectRequest()
        request_message["buffer"] = self.share_name.encode("utf-16-le")
        request = self.session.connection.send(
            request_message,
            sid=self.session.session_id,
        )
        response = self.session.connection.receive(request)
        tree_response = SMB2TreeConnectResponse()
        tree_response.unpack(response["data"].get_value())

        self.tree_connect_id = response["tree_id"].get_value()
        self._connected = True
        self.session.tree_connect_table[self.tree_connect_id] = self
        self.share_type = tree_response["share_type"].get_value()

        capabilities = tree_response["capabilities"]
        self.is_dfs_share = capabilities.has_flag(ShareCapabilities.SMB2_SHARE_CAP_DFS)
        self.is_ca_share = capabilities.has_flag(
            ShareCapabilities.SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY
        )
        dialect = self.session.connection.dialect
        if dialect >= Dialects.SMB_3_0_0 and self.session.connection.supports_encryption:
            self.encrypt_data = tree_response["share_flags"].has_flag(
                ShareFlags.SMB2_SHAREFLAG_ENCRYPT_DATA
            )
            self.is_scaleout_share = capabilities.has_flag(
                ShareCapabilities.SMB2_SHARE_CAP_SCALEOUT
            )
        if require_secure_negotiate:
            self._verify_dialect_negotiate()


@dataclass(frozen=True, slots=True)
class KnownShareProbe:
    """A direct known-name TreeConnect result and optional inventory row."""

    share: ShareInfo
    inventory: InventoryEntry | None

    def __post_init__(self) -> None:
        if self.inventory is not None:
            if self.inventory.kind is not InventoryEntryKind.SHARE:
                raise ValueError("Known-share inventory must contain a share entry.")
            if self.inventory.target != self.share.target:
                raise ValueError("Share and inventory targets must agree.")
            if self.inventory.share_name != self.share.name:
                raise ValueError("Share and inventory names must agree.")


class SmbProtocolFileOperationError(OSError):
    """Safe file-operation error preserving normalized numeric metadata."""

    def __init__(self, detail: SmbErrorDetail) -> None:
        self.detail = detail
        super().__init__(detail.raw_code, detail.safe_message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(detail={self.detail!r})"


class SmbProtocolFileCloseError(OSError):
    def __init__(self) -> None:
        super().__init__(errno.EIO, "Remote SMB file handles could not be closed cleanly.")


class SmbProtocolRangeReader(ValidatedRangeReader):
    """Offset reader owning one read-only Open and its TreeConnect."""

    __slots__ = ("_open", "_tree")

    def __init__(
        self,
        *,
        remote_open: _NativeOpen,
        tree: _NativeTree,
        size: int,
        max_read_size: int,
    ) -> None:
        super().__init__(size=size, max_read_size=max_read_size)
        self._open = remote_open
        self._tree = tree

    def _read_remote_range(
        self,
        offset: int,
        length: int,
        *,
        cancellation: CancellationToken,
    ) -> bytes:
        cancellation.raise_if_cancelled()
        try:
            data = self._open.read(
                offset=offset,
                length=length,
                min_length=0,
                unbuffered=False,
                wait=True,
                send=True,
            )
        except Exception as exception:
            detail = _file_error(exception, target=None, path=None)
            raise SmbProtocolFileOperationError(detail) from None
        cancellation.raise_if_cancelled()
        return data

    def _close_remote(self) -> None:
        failed = _try_close_open(self._open)
        failed = _try_disconnect_tree(self._tree) or failed
        if failed:
            raise SmbProtocolFileCloseError() from None


class SmbProtocolFileAdapter:
    """Known-share probe, bounded tree walk, and file range-reader facade."""

    __slots__ = (
        "_max_range_size",
        "_open_factory",
        "_query_max_output",
        "_require_secure_negotiate",
        "_tree_factory",
    )

    def __init__(
        self,
        *,
        tree_factory: _TreeFactory = InspectableTreeConnect,
        open_factory: _OpenFactory = Open,
        require_secure_negotiate: bool = True,
        query_max_output: int = 65_536,
        max_range_size: int = 1_048_576,
    ) -> None:
        if not isinstance(require_secure_negotiate, bool):
            raise TypeError("require_secure_negotiate must be a boolean.")
        for name, value in (
            ("query_max_output", query_max_output),
            ("max_range_size", max_range_size),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer.")
            if value < 1:
                raise ValueError(f"{name} must be at least one byte.")
        for logger_name in _DEPENDENCY_LOGGERS:
            logging.getLogger(logger_name).disabled = True
        self._tree_factory = tree_factory
        self._open_factory = open_factory
        self._require_secure_negotiate = require_secure_negotiate
        self._query_max_output = query_max_output
        self._max_range_size = max_range_size

    def probe_known_shares(
        self,
        session: SmbProtocolSessionHandle,
        *,
        target: str,
        share_names: Iterable[str],
        cancellation: CancellationToken,
    ) -> tuple[KnownShareProbe, ...]:
        """Try caller-provided names using one read-only TreeConnect each."""

        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be non-empty text.")
        names = _normalize_share_names(share_names)
        native_session = _native_session(session)
        results: list[KnownShareProbe] = []
        for name in names:
            cancellation.raise_if_cancelled()
            tree = self._tree_factory(native_session, _unc(target, name))
            try:
                tree.connect(require_secure_negotiate=self._require_secure_negotiate)
                cancellation.raise_if_cancelled()
            except ScanCancelled:
                _try_disconnect_tree(tree)
                raise
            except Exception as exception:
                _try_disconnect_tree(tree)
                results.append(_share_failure(target, name, exception))
                continue

            kind = _SHARE_TYPES.get(tree.share_type, ShareKind.UNKNOWN)
            share = ShareInfo(
                target=target,
                name=name,
                kind=kind,
                access_status=ShareAccessStatus.CONNECTED,
            )
            inventory = InventoryEntry(
                target=target,
                share_name=name,
                kind=InventoryEntryKind.SHARE,
                status=(
                    InventoryStatus.SHARE_CONNECTED
                    if kind is ShareKind.DISK
                    else InventoryStatus.NON_FILE_SHARE
                ),
                share_kind=kind,
            )
            results.append(KnownShareProbe(share=share, inventory=inventory))
            _try_disconnect_tree(tree)
        return tuple(results)

    def walk_tree(
        self,
        session: SmbProtocolSessionHandle,
        request: TreeWalkRequest,
        *,
        cancellation: CancellationToken,
    ) -> Iterator[InventoryEntry]:
        """Walk a connected disk share to ``max_depth`` without reparse traversal."""

        if request.follow_reparse_points:
            raise ValueError("This adapter never follows reparse points.")
        native_session = _native_session(session)
        native_start, display_start = _normalize_relative_path(request.start_path)
        tree = self._tree_factory(
            native_session,
            _unc(request.share.target, request.share.name),
        )
        try:
            cancellation.raise_if_cancelled()
            try:
                tree.connect(require_secure_negotiate=self._require_secure_negotiate)
            except ScanCancelled:
                raise
            except Exception as exception:
                failure = _share_failure(
                    request.share.target,
                    request.share.name,
                    exception,
                )
                if failure.share.error is None:  # pragma: no cover - model invariant
                    raise RuntimeError(
                        "Share failure did not contain error detail."
                    ) from None
                raise SmbProtocolFileOperationError(failure.share.error) from None
            cancellation.raise_if_cancelled()
            if _SHARE_TYPES.get(tree.share_type, ShareKind.UNKNOWN) is not ShareKind.DISK:
                raise ValueError("The connected share is not a disk/file share.")
            yield from self._walk_directory(
                tree=tree,
                target=request.share.target,
                share_name=request.share.name,
                native_path=native_start,
                display_path=display_start,
                depth=0,
                max_depth=request.max_depth,
                include_self=bool(display_start),
                cancellation=cancellation,
            )
        finally:
            _try_disconnect_tree(tree)

    def open_reader(
        self,
        session: SmbProtocolSessionHandle,
        request: OpenFileRequest,
        *,
        cancellation: CancellationToken,
    ) -> SmbProtocolRangeReader:
        """Open one existing non-reparse file and return an owning range reader."""

        native_path, _display_path = _normalize_relative_path(request.relative_path)
        if not native_path:
            raise ValueError("A file path cannot refer to the share root.")
        native_session = _native_session(session)
        tree = self._tree_factory(
            native_session,
            _unc(request.target, request.share_name),
        )
        remote_open: _NativeOpen | None = None
        try:
            cancellation.raise_if_cancelled()
            tree.connect(require_secure_negotiate=self._require_secure_negotiate)
            cancellation.raise_if_cancelled()
            if _SHARE_TYPES.get(tree.share_type, ShareKind.UNKNOWN) is not ShareKind.DISK:
                raise ValueError("The connected share is not a disk/file share.")
            remote_open = self._open_factory(tree, native_path)
            _open_file(remote_open)
            cancellation.raise_if_cancelled()
            actual_size = _non_negative_integer(remote_open.end_of_file, "remote file size")
            negotiated_max = _non_negative_integer(
                native_session.connection.max_read_size,
                "negotiated max read size",
                allow_zero=False,
            )
            return SmbProtocolRangeReader(
                remote_open=remote_open,
                tree=tree,
                size=actual_size,
                max_read_size=min(negotiated_max, self._max_range_size),
            )
        except ScanCancelled:
            if remote_open is not None:
                _try_close_open(remote_open)
            _try_disconnect_tree(tree)
            raise
        except Exception as exception:
            if remote_open is not None:
                _try_close_open(remote_open)
            _try_disconnect_tree(tree)
            if isinstance(exception, (TypeError, ValueError)):
                raise
            detail = _file_error(
                exception,
                target=request.target,
                path=request.relative_path,
            )
            raise SmbProtocolFileOperationError(detail) from None

    def _walk_directory(
        self,
        *,
        tree: _NativeTree,
        target: str,
        share_name: str,
        native_path: str,
        display_path: str,
        depth: int,
        max_depth: int,
        include_self: bool,
        cancellation: CancellationToken,
    ) -> Iterator[InventoryEntry]:
        directory = self._open_factory(tree, native_path)
        try:
            cancellation.raise_if_cancelled()
            _open_directory(directory)
            first_batch = _query_directory(
                directory,
                flags=QueryDirectoryFlags.SMB2_RESTART_SCANS,
                max_output=self._query_max_output,
            )
            cancellation.raise_if_cancelled()
        except NoMoreFiles:
            first_batch = []
        except ScanCancelled:
            _try_close_open(directory)
            raise
        except Exception as exception:
            _try_close_open(directory)
            yield _directory_denied(
                target,
                share_name,
                display_path,
                exception,
            )
            return

        try:
            if include_self:
                yield InventoryEntry(
                    target=target,
                    share_name=share_name,
                    relative_path=display_path,
                    kind=InventoryEntryKind.DIRECTORY,
                    status=InventoryStatus.DIRECTORY_LISTABLE,
                )
            batch = first_batch
            while True:
                for raw_entry in batch:
                    cancellation.raise_if_cancelled()
                    name = _entry_name(raw_entry)
                    if name in {".", ".."}:
                        continue
                    attributes = _field_value(raw_entry, "file_attributes")
                    child_native = _join_native(native_path, name)
                    child_display = _join_display(display_path, name)
                    is_directory = bool(attributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
                    is_reparse = bool(attributes & FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT)
                    if is_directory:
                        child_depth = depth + 1
                        if is_reparse or child_depth > max_depth:
                            yield InventoryEntry(
                                target=target,
                                share_name=share_name,
                                relative_path=child_display,
                                kind=InventoryEntryKind.DIRECTORY,
                                status=InventoryStatus.DEPTH_LIMIT_REACHED,
                            )
                        else:
                            yield from self._walk_directory(
                                tree=tree,
                                target=target,
                                share_name=share_name,
                                native_path=child_native,
                                display_path=child_display,
                                depth=child_depth,
                                max_depth=max_depth,
                                include_self=True,
                                cancellation=cancellation,
                            )
                    else:
                        yield self._file_inventory(
                            tree=tree,
                            target=target,
                            share_name=share_name,
                            native_path=child_native,
                            display_path=child_display,
                            raw_entry=raw_entry,
                            is_reparse=is_reparse,
                            cancellation=cancellation,
                        )

                if not batch:
                    break
                try:
                    batch = _query_directory(
                        directory,
                        flags=0,
                        max_output=self._query_max_output,
                    )
                    cancellation.raise_if_cancelled()
                except NoMoreFiles:
                    break
                except ScanCancelled:
                    raise
                except Exception as exception:
                    yield _directory_denied(
                        target,
                        share_name,
                        display_path,
                        exception,
                    )
                    break
        finally:
            _try_close_open(directory)

    def _file_inventory(
        self,
        *,
        tree: _NativeTree,
        target: str,
        share_name: str,
        native_path: str,
        display_path: str,
        raw_entry: object,
        is_reparse: bool,
        cancellation: CancellationToken,
    ) -> InventoryEntry:
        size = _non_negative_integer(_field_value(raw_entry, "end_of_file"), "file size")
        modified_at = _field_value(raw_entry, "last_write_time")
        if not isinstance(modified_at, datetime):
            modified_at = None
        if is_reparse:
            detail = SmbErrorDetail(
                stage=TargetStage.FILE_READ,
                status=TargetStatus.FILE_READ_ERROR,
                operation="file_probe",
                raw_code=errno.ELOOP,
                symbolic_name="REPARSE_POINT_SKIPPED",
                safe_message="The file is a reparse point and was not followed.",
                target=target,
                path=display_path,
            )
            return InventoryEntry(
                target=target,
                share_name=share_name,
                relative_path=display_path,
                kind=InventoryEntryKind.FILE,
                status=InventoryStatus.READ_ERROR,
                size=size,
                modified_at=modified_at,
                error=detail,
            )

        remote_open = self._open_factory(tree, native_path)
        try:
            cancellation.raise_if_cancelled()
            _open_file(remote_open)
            cancellation.raise_if_cancelled()
        except ScanCancelled:
            _try_close_open(remote_open)
            raise
        except Exception as exception:
            _try_close_open(remote_open)
            status, detail = _inventory_file_failure(
                exception,
                target=target,
                path=display_path,
            )
            return InventoryEntry(
                target=target,
                share_name=share_name,
                relative_path=display_path,
                kind=InventoryEntryKind.FILE,
                status=status,
                size=size,
                modified_at=modified_at,
                error=detail,
            )
        close_failed = _try_close_open(remote_open)
        if close_failed:
            detail = SmbErrorDetail(
                stage=TargetStage.FILE_READ,
                status=TargetStatus.FILE_READ_ERROR,
                operation="file_probe_close",
                raw_code=errno.EIO,
                symbolic_name="FILE_HANDLE_CLOSE_FAILED",
                safe_message="The read-only file probe could not close its remote handle.",
                target=target,
                path=display_path,
            )
            return InventoryEntry(
                target=target,
                share_name=share_name,
                relative_path=display_path,
                kind=InventoryEntryKind.FILE,
                status=InventoryStatus.READ_ERROR,
                size=size,
                modified_at=modified_at,
                error=detail,
            )
        return InventoryEntry(
            target=target,
            share_name=share_name,
            relative_path=display_path,
            kind=InventoryEntryKind.FILE,
            status=InventoryStatus.FILE_READABLE,
            size=size,
            modified_at=modified_at,
        )


def _open_directory(remote_open: _NativeOpen) -> None:
    remote_open.create(
        impersonation_level=ImpersonationLevel.Impersonation,
        desired_access=_DIRECTORY_ACCESS,
        file_attributes=0,
        share_access=_SHARE_ACCESS,
        create_disposition=CreateDisposition.FILE_OPEN,
        create_options=_DIRECTORY_OPTIONS,
        create_contexts=None,
        send=True,
    )


def _open_file(remote_open: _NativeOpen) -> None:
    remote_open.create(
        impersonation_level=ImpersonationLevel.Impersonation,
        desired_access=_FILE_ACCESS,
        file_attributes=0,
        share_access=_SHARE_ACCESS,
        create_disposition=CreateDisposition.FILE_OPEN,
        create_options=_FILE_OPTIONS,
        create_contexts=None,
        send=True,
    )


def _query_directory(
    remote_open: _NativeOpen,
    *,
    flags: int,
    max_output: int,
) -> list[object]:
    return remote_open.query_directory(
        pattern="*",
        file_information_class=FileInformationClass.FILE_DIRECTORY_INFORMATION,
        flags=flags,
        file_index=0,
        max_output=max_output,
        send=True,
    )


def _normalize_share_names(values: Iterable[str]) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("Share names must be strings.")
        candidate = value.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if any(character in candidate for character in ("/", "\\", "\x00", "\r", "\n")):
            raise ValueError("Share names cannot contain path separators or control bytes.")
        if candidate in {".", ".."}:
            raise ValueError("Share name is invalid.")
        folded = candidate.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        names.append(candidate)
    return tuple(names)


def _normalize_relative_path(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise TypeError("Relative path must be text.")
    candidate = value.strip().replace("\\", "/")
    if candidate.startswith("/") or "\x00" in candidate:
        raise ValueError("Path must be relative to the selected share.")
    parts = tuple(part for part in candidate.split("/") if part)
    if any(part in {".", ".."} for part in parts):
        raise ValueError("Path cannot contain dot traversal components.")
    display = "/".join(parts)
    return "\\".join(parts), display


def _unc(target: str, share_name: str) -> str:
    return f"\\\\{target}\\{share_name}"


def _join_native(parent: str, name: str) -> str:
    return f"{parent}\\{name}" if parent else name


def _join_display(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _entry_name(entry: object) -> str:
    raw = _field_value(entry, "file_name")
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("Directory entry filename must be bytes.")
    try:
        name = bytes(raw).decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exception:
        raise ValueError("Directory entry filename was not valid UTF-16LE.") from exception
    if not name or any(character in name for character in ("/", "\\", "\x00")):
        raise ValueError("Directory entry filename was invalid.")
    return name


def _field_value(entry: object, name: str) -> object:
    return entry[name].get_value()


def _native_session(session: SmbProtocolSessionHandle) -> _NativeSession:
    if not isinstance(session, SmbProtocolSessionHandle) and not hasattr(
        session,
        "_native_session",
    ):
        raise TypeError("session must provide an authenticated smbprotocol session.")
    return session._native_session


def _share_failure(target: str, name: str, exception: BaseException) -> KnownShareProbe:
    raw_code = _raw_code(exception)
    if isinstance(exception, AccessDenied) or raw_code == 0xC0000022:
        access_status = ShareAccessStatus.ACCESS_DENIED
        target_status = TargetStatus.ACCESS_DENIED
        symbolic_name = "STATUS_ACCESS_DENIED"
        safe_message = "The account cannot connect to this share."
    elif isinstance(exception, (BadNetworkName, ObjectNameNotFound, ObjectPathNotFound)) or (
        raw_code in {0xC0000034, 0xC000003A, 0xC00000CC}
    ):
        access_status = ShareAccessStatus.NOT_FOUND
        target_status = TargetStatus.SHARE_NOT_FOUND
        symbolic_name = _STATUS_NAMES.get(raw_code, "SHARE_NOT_FOUND")
        safe_message = "The named share was not found."
    else:
        access_status = ShareAccessStatus.ERROR
        target_status = TargetStatus.SHARE_CONNECT_ERROR
        symbolic_name = _STATUS_NAMES.get(raw_code, "SHARE_CONNECT_ERROR")
        safe_message = "The share connection could not be completed."
    detail = SmbErrorDetail(
        stage=TargetStage.AUTHORIZATION,
        status=target_status,
        operation="known_share_connect",
        raw_code=raw_code,
        symbolic_name=symbolic_name,
        safe_message=safe_message,
        target=target,
        path=name,
    )
    share = ShareInfo(
        target=target,
        name=name,
        kind=ShareKind.UNKNOWN,
        access_status=access_status,
        error=detail,
    )
    inventory = None
    if access_status is ShareAccessStatus.ACCESS_DENIED:
        inventory = InventoryEntry(
            target=target,
            share_name=name,
            kind=InventoryEntryKind.SHARE,
            status=InventoryStatus.SHARE_ACCESS_DENIED,
            share_kind=ShareKind.DISK,
            error=detail,
        )
    return KnownShareProbe(share=share, inventory=inventory)


def _directory_denied(
    target: str,
    share_name: str,
    display_path: str,
    exception: BaseException,
) -> InventoryEntry:
    detail = SmbErrorDetail(
        stage=TargetStage.TREE_WALK,
        status=TargetStatus.DIRECTORY_LIST_DENIED,
        operation="directory_list",
        raw_code=_raw_code(exception),
        symbolic_name=_STATUS_NAMES.get(_raw_code(exception), "DIRECTORY_LIST_ERROR"),
        safe_message="The directory could not be listed.",
        target=target,
        path=display_path,
    )
    return InventoryEntry(
        target=target,
        share_name=share_name,
        relative_path=display_path,
        kind=InventoryEntryKind.DIRECTORY,
        status=InventoryStatus.DIRECTORY_LIST_DENIED,
        error=detail,
    )


def _inventory_file_failure(
    exception: BaseException,
    *,
    target: str,
    path: str,
) -> tuple[InventoryStatus, SmbErrorDetail]:
    raw_code = _raw_code(exception)
    if isinstance(exception, AccessDenied) or raw_code == 0xC0000022:
        status = InventoryStatus.FILE_READ_DENIED
        target_status = TargetStatus.FILE_READ_DENIED
        safe_message = "The file is visible but read access was denied."
    elif isinstance(exception, SharingViolation) or raw_code == 0xC0000043:
        status = InventoryStatus.SHARING_VIOLATION
        target_status = TargetStatus.SHARING_VIOLATION
        safe_message = "The file could not be opened because of a sharing violation."
    else:
        status = InventoryStatus.READ_ERROR
        target_status = TargetStatus.FILE_READ_ERROR
        safe_message = "The visible file could not be opened for reading."
    detail = SmbErrorDetail(
        stage=TargetStage.FILE_READ,
        status=target_status,
        operation="file_probe",
        raw_code=raw_code,
        symbolic_name=_STATUS_NAMES.get(raw_code, target_status.value.upper()),
        safe_message=safe_message,
        target=target,
        path=path,
    )
    return status, detail


def _file_error(
    exception: BaseException,
    *,
    target: str | None,
    path: str | None,
) -> SmbErrorDetail:
    _status, detail = _inventory_file_failure(
        exception,
        target=target or "<remote>",
        path=path or "<open-file>",
    )
    return detail


def _raw_code(exception: BaseException) -> int:
    for current in _exception_chain(exception):
        status = getattr(current, "status", None)
        if not isinstance(status, bool) and isinstance(status, int):
            return status & 0xFFFFFFFF
        error_number = getattr(current, "errno", None)
        if not isinstance(error_number, bool) and isinstance(error_number, int):
            return error_number
    return errno.EIO


def _exception_chain(exception: BaseException) -> Iterator[BaseException]:
    current: BaseException | None = exception
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _non_negative_integer(
    value: object,
    name: str,
    *,
    allow_zero: bool = True,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer.")
    if value < 0 or (not allow_zero and value == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{name} must be {qualifier}.")
    return value


def _try_close_open(remote_open: _NativeOpen) -> bool:
    try:
        remote_open.close(get_attributes=False, send=True)
    except Exception:
        return True
    return False


def _try_disconnect_tree(tree: _NativeTree) -> bool:
    try:
        tree.disconnect()
    except Exception:
        return True
    return False
