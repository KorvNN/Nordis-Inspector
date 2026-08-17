"""Thread-safe viewing and editing of the default content term list."""

from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from os import PathLike
from pathlib import Path
from threading import RLock

from nordis_smb_inspector.core.scan_config import ScanConfigError, editable_wordlist_path

MAX_WORDLIST_BYTES = 1024 * 1024


class WordlistStoreError(ValueError):
    """A content-free wordlist validation or storage error."""


class WordlistKind(StrEnum):
    """A wordlist exposed by the local editor."""

    CONTENT = "content"


@dataclass(frozen=True, slots=True, repr=False)
class WordlistDocument:
    """Editable source text and its effective entry count."""

    kind: WordlistKind
    text: str
    entry_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, WordlistKind):
            raise WordlistStoreError("Wordlist kind is invalid.")
        if not isinstance(self.text, str):
            raise WordlistStoreError("Wordlist must be UTF-8 text.")
        if (
            isinstance(self.entry_count, bool)
            or not isinstance(self.entry_count, int)
            or self.entry_count < 1
        ):
            raise WordlistStoreError("Wordlist entry count is invalid.")

    def __repr__(self) -> str:
        return (
            f"WordlistDocument(kind={self.kind.value!r}, text=<redacted>, "
            f"entry_count={self.entry_count!r})"
        )


class WordlistStore:
    """Read and atomically replace the editable default term list."""

    def __init__(self, *, content_path: str | PathLike[str] | None = None) -> None:
        if content_path is None:
            try:
                content = editable_wordlist_path()
            except ScanConfigError:
                raise WordlistStoreError("Wordlist is unavailable.") from None
        else:
            try:
                content = Path(content_path)
            except (TypeError, ValueError):
                raise WordlistStoreError("Wordlist path is invalid.") from None
        self._content_path = content
        self._lock = RLock()

    @property
    def content_path(self) -> Path:
        return self._content_path

    def __repr__(self) -> str:
        return "WordlistStore(content_path=<redacted>)"

    def read(self) -> WordlistDocument:
        with self._lock:
            return self._read_unlocked()

    def save(self, text: str) -> WordlistDocument:
        normalized_text, encoded, entry_count = _prepare_text(text)
        with self._lock:
            self._replace_unlocked(encoded)
            return WordlistDocument(
                kind=WordlistKind.CONTENT,
                text=normalized_text,
                entry_count=entry_count,
            )

    def _read_unlocked(self) -> WordlistDocument:
        try:
            encoded = self._content_path.read_bytes()
        except OSError:
            raise WordlistStoreError("Wordlist is unavailable.") from None
        if len(encoded) > MAX_WORDLIST_BYTES:
            raise WordlistStoreError("Wordlist must not exceed 1 MiB.")
        try:
            text = encoded.decode("utf-8")
        except UnicodeError:
            raise WordlistStoreError("Wordlist must be UTF-8 text.") from None
        _, _, entry_count = _prepare_text(text, add_final_newline=False)
        return WordlistDocument(WordlistKind.CONTENT, text, entry_count)

    def _replace_unlocked(self, encoded: bytes) -> None:
        temporary_path: Path | None = None
        descriptor: int | None = None
        try:
            mode = stat.S_IMODE(self._content_path.stat().st_mode)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self._content_path.name}.",
                suffix=".tmp",
                dir=self._content_path.parent,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as temporary_file:
                descriptor = None
                temporary_file.write(encoded)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self._content_path)
            temporary_path = None
        except OSError:
            raise WordlistStoreError("Wordlist could not be saved.") from None
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink()


def _prepare_text(
    text: str,
    *,
    add_final_newline: bool = True,
) -> tuple[str, bytes, int]:
    if not isinstance(text, str):
        raise WordlistStoreError("Wordlist must be UTF-8 text.")
    normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
    if any(
        character not in {"\n", "\t"} and unicodedata.category(character) == "Cc"
        for character in normalized_text
    ):
        raise WordlistStoreError("Wordlist contains invalid control characters.")
    if add_final_newline and not normalized_text.endswith("\n"):
        normalized_text += "\n"
    encoded = normalized_text.encode("utf-8")
    if len(encoded) > MAX_WORDLIST_BYTES:
        raise WordlistStoreError("Wordlist must not exceed 1 MiB.")
    entries = _effective_entries(normalized_text)
    if not entries:
        raise WordlistStoreError("Wordlist must contain at least one entry.")
    return normalized_text, encoded, len(entries)


def _effective_entries(text: str) -> tuple[str, ...]:
    entries: list[str] = []
    seen: set[str] = set()
    for index, line in enumerate(text.splitlines()):
        if index == 0:
            line = line.removeprefix("\ufeff")
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        comparison_key = entry.casefold()
        if comparison_key in seen:
            continue
        seen.add(comparison_key)
        entries.append(entry)
    return tuple(entries)
