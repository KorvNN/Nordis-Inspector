"""Bounded text extraction from PDF and ZIP-based office documents."""

from __future__ import annotations

import gzip
import logging
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import BinaryIO
from xml.etree.ElementTree import XMLPullParser
from zipfile import BadZipFile, ZipFile, ZipInfo

_XML_CHUNK_SIZE = 64 * 1024
_OFFICE_SUFFIXES = frozenset(
    {
        ".docx",
        ".docm",
        ".dotx",
        ".dotm",
        ".xlsx",
        ".xlsm",
        ".xltx",
        ".xltm",
        ".pptx",
        ".pptm",
        ".potx",
        ".potm",
        ".ppsx",
        ".ppsm",
        ".odt",
        ".ods",
        ".odp",
    }
)
_WORD_SUFFIXES = frozenset({".docx", ".docm", ".dotx", ".dotm"})
_SHEET_SUFFIXES = frozenset({".xlsx", ".xlsm", ".xltx", ".xltm"})
_SLIDE_SUFFIXES = frozenset({".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"})
_ODF_SUFFIXES = frozenset({".odt", ".ods", ".odp"})
_ZIP_SUFFIXES = frozenset({".zip", ".jar", ".war", ".ear"})
_TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")


class DocumentKind(StrEnum):
    PLAIN = "plain"
    PDF = "pdf"
    OFFICE_ZIP = "office_zip"
    ZIP_ARCHIVE = "zip_archive"
    TAR_ARCHIVE = "tar_archive"
    GZIP_ARCHIVE = "gzip_archive"


_ARCHIVE_KINDS = frozenset(
    {
        DocumentKind.ZIP_ARCHIVE,
        DocumentKind.TAR_ARCHIVE,
        DocumentKind.GZIP_ARCHIVE,
    }
)


class DocumentExtractionCode(StrEnum):
    INVALID_CONTAINER = "invalid_container"
    ENCRYPTED_CONTAINER = "encrypted_container"
    ENTRY_LIMIT = "entry_limit"
    EXPANDED_SIZE_LIMIT = "expanded_size_limit"
    TEXT_LIMIT = "text_limit"
    PARSER_READ_LIMIT = "parser_read_limit"
    PDF_PAGE_LIMIT = "pdf_page_limit"
    PARSE_ERROR = "parse_error"


class DocumentExtractionError(ValueError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: DocumentExtractionCode, safe_message: str) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code.value!r}, message=<redacted>)"


@dataclass(frozen=True, slots=True)
class DocumentLimits:
    max_entries: int = 10_000
    max_expanded_bytes: int = 500 * 1024 * 1024
    max_line_chars: int = 1_048_576
    max_pdf_pages: int = 10_000
    max_archive_depth: int = 3

    def __post_init__(self) -> None:
        for name in (
            "max_entries",
            "max_expanded_bytes",
            "max_line_chars",
            "max_pdf_pages",
            "max_archive_depth",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer.")
            if value < 1:
                raise ValueError(f"{name} must be at least one.")


@dataclass(slots=True)
class _ExpansionBudget:
    limit: int
    consumed: int = 0

    def add(self, amount: int) -> None:
        self.consumed += amount
        if self.consumed > self.limit:
            raise DocumentExtractionError(
                DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
                "Açılan Office/ODF içeriği güvenli tarama sınırını aşıyor.",
            )


@dataclass(frozen=True, slots=True, repr=False)
class ArchiveMember:
    path: str = field(repr=False)
    size: int | None
    kind: DocumentKind
    stream: BinaryIO = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(path=<redacted>, size={self.size!r}, "
            f"kind={self.kind.value!r}, stream=<redacted>)"
        )


@dataclass(slots=True)
class _ArchiveBudget:
    limits: DocumentLimits
    entries: int = 0
    expanded_bytes: int = 0

    def add_entries(self, sizes: tuple[int, ...]) -> None:
        self.entries += len(sizes)
        self.expanded_bytes += sum(sizes)
        if self.entries > self.limits.max_entries:
            raise DocumentExtractionError(
                DocumentExtractionCode.ENTRY_LIMIT,
                "Arşiv öğe sayısı güvenli tarama sınırını aşıyor.",
            )
        if self.expanded_bytes > self.limits.max_expanded_bytes:
            raise DocumentExtractionError(
                DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
                "Arşivin açılmış içerik boyutu güvenli tarama sınırını aşıyor.",
            )

    def add_expanded(self, amount: int) -> None:
        self.expanded_bytes += amount
        if self.expanded_bytes > self.limits.max_expanded_bytes:
            raise DocumentExtractionError(
                DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
                "Arşivin açılmış içerik boyutu güvenli tarama sınırını aşıyor.",
            )


class _BudgetedBinaryStream:
    def __init__(self, source: BinaryIO, budget: _ArchiveBudget) -> None:
        self._source = source
        self._budget = budget

    def read(self, size: int = -1) -> bytes:
        data = self._source.read(size)
        if not isinstance(data, bytes):
            raise TypeError("Archive reads must return bytes.")
        self._budget.add_expanded(len(data))
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._source.seek(offset, whence)

    def tell(self) -> int:
        return self._source.tell()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return self._source.seekable()


def document_kind(path: str) -> DocumentKind:
    if not isinstance(path, str):
        raise TypeError("path must be text.")
    normalized_path = path.replace("\\", "/").casefold()
    suffix = PurePosixPath(normalized_path).suffix
    if suffix == ".pdf":
        return DocumentKind.PDF
    if suffix in _OFFICE_SUFFIXES:
        return DocumentKind.OFFICE_ZIP
    if suffix in _ZIP_SUFFIXES:
        return DocumentKind.ZIP_ARCHIVE
    if normalized_path.endswith(_TAR_SUFFIXES):
        return DocumentKind.TAR_ARCHIVE
    if suffix == ".gz":
        return DocumentKind.GZIP_ARCHIVE
    return DocumentKind.PLAIN


def iter_document_lines(
    stream: BinaryIO,
    path: str,
    *,
    limits: DocumentLimits | None = None,
) -> Iterator[str]:
    effective_limits = limits or DocumentLimits()
    kind = document_kind(path)
    if kind is DocumentKind.PDF:
        yield from _pdf_lines(stream, effective_limits)
        return
    if kind is DocumentKind.OFFICE_ZIP:
        yield from _office_lines(stream, path, effective_limits)
        return
    raise ValueError("Plain documents do not require structured extraction.")


def iter_archive_members(
    stream: BinaryIO,
    path: str,
    *,
    limits: DocumentLimits | None = None,
) -> Iterator[ArchiveMember]:
    effective_limits = limits or DocumentLimits()
    if document_kind(path) not in _ARCHIVE_KINDS:
        raise ValueError("Archive extraction requires a supported archive suffix.")
    budget = _ArchiveBudget(effective_limits)
    try:
        yield from _archive_members(
            stream,
            path,
            depth=1,
            budget=budget,
        )
    except DocumentExtractionError:
        raise
    except (BadZipFile, OSError, ValueError, tarfile.TarError):
        raise DocumentExtractionError(
            DocumentExtractionCode.INVALID_CONTAINER,
            "ZIP arşivi geçerli veya desteklenen bir kapsayıcı değil.",
        ) from None


def encoded_document_lines(lines: Iterator[str]) -> Iterator[bytes]:
    for line in lines:
        yield line.encode("utf-8") + b"\n"


def _pdf_lines(stream: BinaryIO, limits: DocumentLimits) -> Iterator[str]:
    logging.getLogger("pypdf").disabled = True
    try:
        from pypdf import PdfReader

        reader = PdfReader(stream, strict=False)
        if reader.is_encrypted and reader.decrypt("") == 0:
            raise DocumentExtractionError(
                DocumentExtractionCode.ENCRYPTED_CONTAINER,
                "Parolalı PDF içeriği taranamadı.",
            )
        if len(reader.pages) > limits.max_pdf_pages:
            raise DocumentExtractionError(
                DocumentExtractionCode.PDF_PAGE_LIMIT,
                "PDF sayfa sayısı güvenli tarama sınırını aşıyor.",
            )
        consumed_chars = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            consumed_chars += len(text)
            if consumed_chars > limits.max_expanded_bytes:
                raise DocumentExtractionError(
                    DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
                    "PDF'den çıkarılan metin güvenli içerik sınırını aşıyor.",
                )
            for line in text.splitlines():
                yield _bounded_line(line, limits)
    except DocumentExtractionError:
        raise
    except OSError as error:
        if type(error).__name__ == "RangeIoReadLimitError":
            raise DocumentExtractionError(
                DocumentExtractionCode.PARSER_READ_LIMIT,
                "PDF ayrıştırıcısı tek seferde güvenli sınırın üzerinde veri istedi.",
            ) from None
        raise DocumentExtractionError(
            DocumentExtractionCode.PARSE_ERROR,
            "PDF içeriği ayrıştırılamadı.",
        ) from None
    except Exception:
        raise DocumentExtractionError(
            DocumentExtractionCode.PARSE_ERROR,
            "PDF içeriği ayrıştırılamadı.",
        ) from None


def _archive_members(
    stream: BinaryIO,
    container_path: str,
    *,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[ArchiveMember]:
    kind = document_kind(container_path)
    if kind is DocumentKind.ZIP_ARCHIVE:
        yield from _zip_members(stream, container_path, depth=depth, budget=budget)
        return
    if kind is DocumentKind.TAR_ARCHIVE:
        yield from _tar_members(stream, container_path, depth=depth, budget=budget)
        return
    if kind is DocumentKind.GZIP_ARCHIVE:
        yield from _gzip_member(stream, container_path, depth=depth, budget=budget)
        return
    raise DocumentExtractionError(
        DocumentExtractionCode.INVALID_CONTAINER,
        "Arşiv biçimi desteklenmiyor.",
    )


def _zip_members(
    stream: BinaryIO,
    container_path: str,
    *,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[ArchiveMember]:
    with ZipFile(stream) as archive:
        infos = tuple(info for info in archive.infolist() if not info.is_dir())
        budget.add_entries(tuple(info.file_size for info in infos))
        for info in infos:
            member_name = _safe_member_name(info.filename)
            if member_name is None:
                continue
            if info.flag_bits & 0x1:
                raise DocumentExtractionError(
                    DocumentExtractionCode.ENCRYPTED_CONTAINER,
                    "Parolalı ZIP arşiv öğesi taranamadı.",
                )
            virtual_path = f"{container_path}!/{member_name}"
            kind = document_kind(member_name)
            with archive.open(info) as source:
                if kind in _ARCHIVE_KINDS:
                    if depth >= budget.limits.max_archive_depth:
                        raise DocumentExtractionError(
                            DocumentExtractionCode.ENTRY_LIMIT,
                            "İç içe arşiv derinliği güvenli tarama sınırını aşıyor.",
                        )
                    yield from _archive_members(
                        source,
                        virtual_path,
                        depth=depth + 1,
                        budget=budget,
                    )
                    continue
                yield ArchiveMember(
                    path=virtual_path,
                    size=info.file_size,
                    kind=kind,
                    stream=source,
                )


def _tar_members(
    stream: BinaryIO,
    container_path: str,
    *,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[ArchiveMember]:
    with tarfile.open(fileobj=stream, mode="r:*") as archive:
        members = tuple(member for member in archive.getmembers() if member.isfile())
        budget.add_entries(tuple(member.size for member in members))
        for member in members:
            member_name = _safe_member_name(member.name)
            if member_name is None:
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            with source:
                virtual_path = f"{container_path}!/{member_name}"
                kind = document_kind(member_name)
                if kind in _ARCHIVE_KINDS:
                    if depth >= budget.limits.max_archive_depth:
                        raise DocumentExtractionError(
                            DocumentExtractionCode.ENTRY_LIMIT,
                            "İç içe arşiv derinliği güvenli tarama sınırını aşıyor.",
                        )
                    yield from _archive_members(
                        source,
                        virtual_path,
                        depth=depth + 1,
                        budget=budget,
                    )
                    continue
                yield ArchiveMember(
                    path=virtual_path,
                    size=member.size,
                    kind=kind,
                    stream=source,
                )


def _gzip_member(
    stream: BinaryIO,
    container_path: str,
    *,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[ArchiveMember]:
    member_name = PurePosixPath(container_path.replace("\\", "/")).name
    member_name = member_name[:-3] if member_name.casefold().endswith(".gz") else "content"
    budget.add_entries((0,))
    with gzip.GzipFile(fileobj=stream, mode="rb") as source:
        budgeted = _BudgetedBinaryStream(source, budget)
        kind = document_kind(member_name)
        if kind in _ARCHIVE_KINDS:
            if depth >= budget.limits.max_archive_depth:
                raise DocumentExtractionError(
                    DocumentExtractionCode.ENTRY_LIMIT,
                    "İç içe arşiv derinliği güvenli tarama sınırını aşıyor.",
                )
            yield from _archive_members(
                budgeted,  # type: ignore[arg-type]
                f"{container_path}!/{member_name}",
                depth=depth + 1,
                budget=budget,
            )
            return
        yield ArchiveMember(
            path=f"{container_path}!/{member_name or 'content'}",
            size=None,
            kind=kind,
            stream=budgeted,  # type: ignore[arg-type]
        )


def _safe_member_name(value: str) -> str | None:
    if not isinstance(value, str) or "\x00" in value:
        return None
    normalized = value.replace("\\", "/").strip("/")
    parts = tuple(part for part in normalized.split("/") if part)
    if not parts or any(part in {".", ".."} for part in parts):
        return None
    return "/".join(parts)


def _office_lines(stream: BinaryIO, path: str, limits: DocumentLimits) -> Iterator[str]:
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.casefold()
    try:
        with ZipFile(stream) as archive:
            infos = tuple(info for info in archive.infolist() if _office_member(info, suffix))
            _validate_zip_infos(infos, limits)
            budget = _ExpansionBudget(limits.max_expanded_bytes)
            for info in infos:
                if info.flag_bits & 0x1:
                    raise DocumentExtractionError(
                        DocumentExtractionCode.ENCRYPTED_CONTAINER,
                        "Parolalı Office/ODF içeriği taranamadı.",
                    )
                with archive.open(info) as source:
                    yield from _xml_lines(source, suffix, limits, budget)
    except DocumentExtractionError:
        raise
    except (BadZipFile, OSError, ValueError):
        raise DocumentExtractionError(
            DocumentExtractionCode.INVALID_CONTAINER,
            "Office/ODF kapsayıcısı geçerli bir ZIP belgesi değil.",
        ) from None


def _office_member(info: ZipInfo, suffix: str) -> bool:
    name = info.filename.replace("\\", "/")
    folded = name.casefold()
    if info.is_dir() or not folded.endswith(".xml"):
        return False
    if suffix in _WORD_SUFFIXES:
        return folded.startswith("word/") or folded.startswith("docprops/")
    if suffix in _SHEET_SUFFIXES:
        return folded.startswith("xl/") or folded.startswith("docprops/")
    if suffix in _SLIDE_SUFFIXES:
        return folded.startswith("ppt/") or folded.startswith("docprops/")
    if suffix in _ODF_SUFFIXES:
        return folded in {"content.xml", "styles.xml", "meta.xml", "settings.xml"}
    return False


def _validate_zip_infos(infos: tuple[ZipInfo, ...], limits: DocumentLimits) -> None:
    if len(infos) > limits.max_entries:
        raise DocumentExtractionError(
            DocumentExtractionCode.ENTRY_LIMIT,
            "Office/ODF öğe sayısı güvenli tarama sınırını aşıyor.",
        )
    if sum(info.file_size for info in infos) > limits.max_expanded_bytes:
        raise DocumentExtractionError(
            DocumentExtractionCode.EXPANDED_SIZE_LIMIT,
            "Office/ODF açılmış içerik boyutu güvenli tarama sınırını aşıyor.",
        )


def _xml_lines(
    source: BinaryIO,
    suffix: str,
    limits: DocumentLimits,
    budget: _ExpansionBudget,
) -> Iterator[str]:
    parser = XMLPullParser(events=("start", "end"))
    boundary_names = _boundary_names(suffix)
    boundary_stack: list[bool] = []
    active_boundaries = 0
    while True:
        chunk = source.read(_XML_CHUNK_SIZE)
        if not chunk:
            break
        budget.add(len(chunk))
        try:
            parser.feed(chunk)
            events = tuple(parser.read_events())
        except Exception:
            raise DocumentExtractionError(
                DocumentExtractionCode.PARSE_ERROR,
                "Office/ODF XML içeriği ayrıştırılamadı.",
            ) from None
        for event, element in events:
            local_name = _local_name(element.tag)
            if event == "start":
                boundary = local_name in boundary_names
                boundary_stack.append(boundary)
                if boundary:
                    active_boundaries += 1
                if element.attrib:
                    attributes = " ".join(
                        f"{_local_name(name)}={value}" for name, value in element.attrib.items()
                    )
                    yield _bounded_line(f"{local_name} {attributes}", limits)
                continue

            boundary = boundary_stack.pop()
            if boundary:
                text = " ".join(part.strip() for part in element.itertext() if part.strip())
                active_boundaries -= 1
                if text:
                    yield _bounded_line(text, limits)
                element.clear()
            elif active_boundaries == 0:
                text = (element.text or "").strip()
                if text:
                    yield _bounded_line(text, limits)
                element.clear()
    try:
        parser.close()
    except Exception:
        raise DocumentExtractionError(
            DocumentExtractionCode.PARSE_ERROR,
            "Office/ODF XML içeriği tamamlanamadı.",
        ) from None


def _boundary_names(suffix: str) -> frozenset[str]:
    if suffix in _WORD_SUFFIXES or suffix in _SLIDE_SUFFIXES:
        return frozenset({"p", "comment", "footnote", "endnote"})
    if suffix in _SHEET_SUFFIXES:
        return frozenset({"row", "si", "comment", "definedName", "connection"})
    return frozenset({"p", "h", "table-cell", "list-item"})


def _local_name(value: object) -> str:
    if not isinstance(value, str):
        return "element"
    return value.rsplit("}", 1)[-1]


def _bounded_line(line: str, limits: DocumentLimits) -> str:
    if len(line) > limits.max_line_chars:
        raise DocumentExtractionError(
            DocumentExtractionCode.TEXT_LIMIT,
            "Belgeden çıkarılan tek bir metin satırı güvenli sınırı aşıyor.",
        )
    return line
