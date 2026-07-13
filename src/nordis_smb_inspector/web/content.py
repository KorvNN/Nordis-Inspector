"""RAM-only content catalog and read-only access to inventoried SMB files."""

from __future__ import annotations

import codecs
from collections.abc import Iterator
from contextlib import suppress
from dataclasses import dataclass, field, replace
from enum import StrEnum
from io import BytesIO
from pathlib import PureWindowsPath
from threading import RLock
from uuid import uuid4

from nordis_smb_inspector.core.credentials import Credential
from nordis_smb_inspector.core.documents import (
    DocumentExtractionError,
    DocumentKind,
    DocumentLimits,
    document_kind,
    iter_document_lines,
)
from nordis_smb_inspector.identity_access.models import DirectoryTextEntry
from nordis_smb_inspector.smb.cancellation import NEVER_CANCELLED
from nordis_smb_inspector.smb.contracts import (
    ConnectionHandle,
    ConnectRequest,
    OpenFileRequest,
    SessionHandle,
    ValidatedRangeReader,
)
from nordis_smb_inspector.smb.models import (
    InventoryEntry,
    InventoryEntryKind,
    InventoryStatus,
)

_PREVIEW_BYTE_LIMIT = 512 * 1024
_STRUCTURED_PREVIEW_FILE_LIMIT = 32 * 1024 * 1024
_PREVIEW_CHAR_LIMIT = 512 * 1024
_STREAM_CHUNK_SIZE = 64 * 1024
_NON_PREVIEWABLE_DOCUMENT_KINDS = frozenset(
    {
        DocumentKind.ZIP_ARCHIVE,
        DocumentKind.TAR_ARCHIVE,
        DocumentKind.GZIP_ARCHIVE,
    }
)


class ContentSource(StrEnum):
    SMB = "smb"
    LDAP = "ldap"


@dataclass(frozen=True, slots=True)
class ContentSignal:
    title: str
    rule_id: str | None = None
    category: str | None = None
    confidence: str | None = None
    line_number: int | None = None

    def public_payload(self) -> dict[str, object]:
        return {
            "title": self.title,
            "rule_id": self.rule_id,
            "category": self.category,
            "confidence": self.confidence,
            "line_number": self.line_number,
        }


class ContentAccessError(RuntimeError):
    """A normalized error safe to display in the local panel."""

    __slots__ = ("code", "safe_message", "status_code")

    def __init__(self, code: str, safe_message: str, status_code: int = 409) -> None:
        self.code = code
        self.safe_message = safe_message
        self.status_code = status_code
        super().__init__(safe_message)

    def public_payload(self) -> dict[str, dict[str, str]]:
        return {"error": {"code": self.code, "message": self.safe_message}}

    def __repr__(self) -> str:
        return (
            f"ContentAccessError(code={self.code!r}, "
            f"status_code={self.status_code!r}, detail=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SmbContentReference:
    content_id: str
    target: str = field(repr=False)
    share: str = field(repr=False)
    path: str = field(repr=False)
    size: int | None
    kerberos_hostname: str | None = field(default=None, repr=False)
    flagged: bool = False
    signals: tuple[ContentSignal, ...] = ()

    def public_payload(self) -> dict[str, object]:
        return {
            "id": self.content_id,
            "source": ContentSource.SMB.value,
            "title": PureWindowsPath(self.path).name or self.path,
            "target": self.target,
            "share": self.share,
            "path": self.path,
            "size": self.size,
            "flagged": self.flagged,
            "signals": [signal.public_payload() for signal in self.signals],
            "preview_available": smb_preview_available(self.path),
            "download_available": True,
        }

    def __repr__(self) -> str:
        return (
            f"SmbContentReference(content_id={self.content_id!r}, "
            f"size={self.size!r}, flagged={self.flagged!r}, location=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class LdapContentReference:
    content_id: str
    entry: DirectoryTextEntry = field(repr=False)

    def public_payload(self) -> dict[str, object]:
        return {
            "id": self.content_id,
            "source": ContentSource.LDAP.value,
            "title": self.entry.subject,
            **self.entry.metadata_payload(),
            "preview_available": True,
            "download_available": True,
        }

    def __repr__(self) -> str:
        return (
            f"LdapContentReference(content_id={self.content_id!r}, "
            f"entry={self.entry!r})"
        )


ContentReference = SmbContentReference | LdapContentReference


def smb_preview_available(path: str) -> bool:
    """Return whether the live panel can render a bounded SMB file preview."""

    return document_kind(path) not in _NON_PREVIEWABLE_DOCUMENT_KINDS


class ContentCatalog:
    """Own current-generation content references and the live SMB credential."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._generation = 0
        self._credential: Credential | None = None
        self._items: dict[str, ContentReference] = {}
        self._smb_keys: dict[tuple[str, str, str], str] = {}

    def reset(self, generation: int, credential: Credential) -> None:
        with self._lock:
            self._generation = generation
            self._credential = credential
            self._items.clear()
            self._smb_keys.clear()

    def register_smb(
        self,
        generation: int,
        entry: InventoryEntry,
        *,
        kerberos_hostname: str | None,
    ) -> str | None:
        if entry.kind is not InventoryEntryKind.FILE or "!/" in entry.relative_path:
            return None
        key = (entry.target, entry.share_name, entry.relative_path)
        with self._lock:
            if generation != self._generation:
                return None
            existing_id = self._smb_keys.get(key)
            if entry.status is not InventoryStatus.FILE_READABLE:
                if existing_id is not None:
                    self._items.pop(existing_id, None)
                    self._smb_keys.pop(key, None)
                return None
            if existing_id is not None:
                current = self._items.get(existing_id)
                if isinstance(current, SmbContentReference):
                    self._items[existing_id] = replace(
                        current,
                        size=entry.size,
                        kerberos_hostname=kerberos_hostname,
                    )
                    return existing_id
            content_id = uuid4().hex
            self._smb_keys[key] = content_id
            self._items[content_id] = SmbContentReference(
                content_id=content_id,
                target=entry.target,
                share=entry.share_name,
                path=entry.relative_path,
                size=entry.size,
                kerberos_hostname=kerberos_hostname,
            )
            return content_id

    def flag_smb(
        self,
        generation: int,
        *,
        target: str,
        share: str,
        path: str,
        signal: ContentSignal | None = None,
    ) -> str | None:
        remote_path = path.split("!/", 1)[0]
        key = (target, share, remote_path)
        with self._lock:
            if generation != self._generation:
                return None
            content_id = self._smb_keys.get(key)
            current = self._items.get(content_id) if content_id is not None else None
            if isinstance(current, SmbContentReference):
                signals = current.signals
                if signal is not None and signal not in signals:
                    signals = (*signals, signal)
                if not current.flagged or signals != current.signals:
                    self._items[content_id] = replace(
                        current,
                        flagged=True,
                        signals=signals,
                    )
                return content_id
            return None

    def register_directory(
        self,
        generation: int,
        entries: tuple[DirectoryTextEntry, ...],
    ) -> None:
        with self._lock:
            if generation != self._generation:
                return
            stale_ids = [
                content_id
                for content_id, item in self._items.items()
                if isinstance(item, LdapContentReference)
            ]
            for content_id in stale_ids:
                self._items.pop(content_id, None)
            for entry in entries:
                content_id = uuid4().hex
                self._items[content_id] = LdapContentReference(content_id, entry)

    def snapshot(
        self,
        generation: int,
        *,
        query: str | None = None,
    ) -> tuple[dict[str, object], ...]:
        with self._lock:
            if generation != self._generation:
                return ()
            terms = tuple(part for part in (query or "").casefold().split() if part)
            payloads: list[dict[str, object]] = []
            for item in self._items.values():
                payload = item.public_payload()
                if terms and not _content_matches_terms(item, payload, terms):
                    continue
                payloads.append(payload)
            return tuple(payloads)

    def directory_entries(
        self,
        generation: int,
    ) -> tuple[tuple[str, DirectoryTextEntry], ...]:
        """Return current LDAP references for internal finding projection."""

        with self._lock:
            if generation != self._generation:
                return ()
            return tuple(
                (content_id, item.entry)
                for content_id, item in self._items.items()
                if isinstance(item, LdapContentReference)
            )

    def resolve(
        self,
        generation: int,
        content_id: str,
    ) -> tuple[ContentReference, Credential | None]:
        with self._lock:
            if generation != self._generation:
                raise ContentAccessError(
                    "CONTENT_GENERATION_EXPIRED",
                    "Bu içerik artık etkin taramaya ait değil.",
                )
            item = self._items.get(content_id)
            if item is None:
                raise ContentAccessError(
                    "CONTENT_NOT_FOUND",
                    "İçerik kaydı bulunamadı.",
                    404,
                )
            return item, self._credential

    def count(self, generation: int) -> int:
        with self._lock:
            return len(self._items) if generation == self._generation else 0


def _content_matches_terms(
    reference: ContentReference,
    payload: dict[str, object],
    terms: tuple[str, ...],
) -> bool:
    values: list[str] = []

    def collect(value: object) -> None:
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                collect(nested)

    collect(payload)
    if isinstance(reference, LdapContentReference):
        values.append(reference.entry.value)
    haystack = "\n".join(values).casefold()
    return all(term in haystack for term in terms)


@dataclass(slots=True, repr=False)
class SmbReaderLease:
    reader: ValidatedRangeReader = field(repr=False)
    session: SessionHandle = field(repr=False)
    connections: tuple[ConnectionHandle, ...] = field(repr=False)

    def iter_bytes(self) -> Iterator[bytes]:
        try:
            chunk_size = min(_STREAM_CHUNK_SIZE, self.reader.max_read_size)
            yield from self.reader.iter_chunks(
                chunk_size=chunk_size,
                cancellation=NEVER_CANCELLED,
            )
        finally:
            self.close()

    def close(self) -> None:
        with suppress(Exception):
            self.reader.close()
        with suppress(Exception):
            self.session.close()
        for connection in reversed(self.connections):
            with suppress(Exception):
                connection.close()

    def __repr__(self) -> str:
        return "SmbReaderLease(reader=<redacted>, session=<redacted>)"


def open_smb_reader(
    reference: SmbContentReference,
    credential: Credential | None,
    *,
    connector: object,
    authenticator: object,
    file_adapter: object,
) -> SmbReaderLease:
    if credential is None:
        raise ContentAccessError(
            "CONTENT_CREDENTIAL_EXPIRED",
            "Dosyayı yeniden açacak kimlik bilgisi artık bellekte değil.",
        )
    connections: list[ConnectionHandle] = []
    session: SessionHandle | None = None
    reader: ValidatedRangeReader | None = None

    def reconnect_for_ntlm(*, cancellation: object) -> ConnectionHandle:
        del cancellation
        replacement = connector.connect(  # type: ignore[attr-defined]
            ConnectRequest(target=reference.target),
            cancellation=NEVER_CANCELLED,
        )
        connections.append(replacement)
        return replacement

    try:
        connection = connector.connect(  # type: ignore[attr-defined]
            ConnectRequest(target=reference.target),
            cancellation=NEVER_CANCELLED,
        )
        connections.append(connection)
        session = authenticator.authenticate_credential(  # type: ignore[attr-defined]
            connection,
            credential,
            kerberos_hostname=reference.kerberos_hostname,
            cancellation=NEVER_CANCELLED,
            reconnect_for_ntlm=reconnect_for_ntlm,
        )
        active_connection = getattr(session, "connection", None)
        if active_connection is not None and all(
            active_connection is not known for known in connections
        ):
            connections.append(active_connection)
        reader = file_adapter.open_reader(  # type: ignore[attr-defined]
            session,
            OpenFileRequest(
                target=reference.target,
                share_name=reference.share,
                relative_path=reference.path,
                expected_size=reference.size,
            ),
            cancellation=NEVER_CANCELLED,
        )
        return SmbReaderLease(reader, session, tuple(connections))
    except ContentAccessError:
        raise
    except Exception:
        if reader is not None:
            with suppress(Exception):
                reader.close()
        if session is not None:
            with suppress(Exception):
                session.close()
        for connection in reversed(connections):
            with suppress(Exception):
                connection.close()
        raise ContentAccessError(
            "SMB_CONTENT_OPEN_FAILED",
            "SMB dosyası yeniden açılamadı.",
        ) from None


def smb_text_preview(lease: SmbReaderLease, path: str) -> dict[str, object]:
    kind = document_kind(path)
    try:
        if kind in {
            DocumentKind.ZIP_ARCHIVE,
            DocumentKind.TAR_ARCHIVE,
            DocumentKind.GZIP_ARCHIVE,
        }:
            raise ContentAccessError(
                "CONTENT_PREVIEW_UNSUPPORTED",
                "Arşiv içeriği panelde önizlenmiyor; dosyayı indirebilirsin.",
                415,
            )
        if kind in {DocumentKind.PDF, DocumentKind.OFFICE_ZIP}:
            return _structured_preview(lease, path)
        length = min(lease.reader.size, _PREVIEW_BYTE_LIMIT)
        raw = lease.reader.read_range(0, length, cancellation=NEVER_CANCELLED)
        text, encoding = _decode_preview(raw)
        return {
            "text": text,
            "encoding": encoding,
            "truncated": lease.reader.size > len(raw),
            "size": lease.reader.size,
        }
    finally:
        lease.close()


def _structured_preview(lease: SmbReaderLease, path: str) -> dict[str, object]:
    if lease.reader.size > _STRUCTURED_PREVIEW_FILE_LIMIT:
        raise ContentAccessError(
            "CONTENT_PREVIEW_TOO_LARGE",
            "Belge panel önizleme sınırını aşıyor; dosyayı indirebilirsin.",
            413,
        )
    raw = b"".join(
        lease.reader.iter_chunks(
            chunk_size=min(_STREAM_CHUNK_SIZE, lease.reader.max_read_size),
            cancellation=NEVER_CANCELLED,
        )
    )
    parts: list[str] = []
    length = 0
    truncated = False
    try:
        lines = iter_document_lines(
            BytesIO(raw),
            path,
            limits=DocumentLimits(
                max_entries=2_000,
                max_expanded_bytes=8 * 1024 * 1024,
                max_line_chars=256 * 1024,
                max_pdf_pages=500,
                max_archive_depth=1,
            ),
        )
        for line in lines:
            addition = line + "\n"
            remaining = _PREVIEW_CHAR_LIMIT - length
            if len(addition) > remaining:
                parts.append(addition[:remaining])
                truncated = True
                break
            parts.append(addition)
            length += len(addition)
    except DocumentExtractionError as error:
        raise ContentAccessError(
            "CONTENT_PREVIEW_FAILED",
            error.safe_message,
            422,
        ) from None
    return {
        "text": "".join(parts),
        "encoding": "extracted-text",
        "truncated": truncated,
        "size": lease.reader.size,
    }


def _decode_preview(raw: bytes) -> tuple[str, str]:
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig", errors="replace"), "utf-8"
    for bom, encoding in (
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if raw.startswith(bom):
            return raw[len(bom) :].decode(encoding, errors="replace"), encoding
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    if b"\x00" in raw:
        raise ContentAccessError(
            "CONTENT_PREVIEW_BINARY",
            "Dosya metin olarak önizlenemiyor; indirebilirsin.",
            415,
        )
    try:
        from charset_normalizer import from_bytes

        match = from_bytes(raw).best()
    except Exception:
        match = None
    if match is None or match.encoding is None or match.chaos > 0.1:
        raise ContentAccessError(
            "CONTENT_PREVIEW_ENCODING_UNKNOWN",
            "Dosyanın metin kodlaması güvenle belirlenemedi; indirebilirsin.",
            415,
        )
    return str(match), match.encoding
