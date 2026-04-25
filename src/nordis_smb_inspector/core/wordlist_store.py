"""Thread-safe editing of the repository-backed scan wordlists.

The store exposes the source text so a local web editor can round-trip comments
and formatting.  Effective entry counts use the same basic rules as scan
configuration: blank and comment lines are ignored and entries are compared
case-insensitively after trimming whitespace.
"""

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

from nordis_smb_inspector.core.scan_config import (
    ScanConfigError,
    repository_wordlist_paths,
)

MAX_WORDLIST_BYTES = 1024 * 1024


class WordlistStoreError(ValueError):
    """A content-free wordlist validation or storage error."""


class WordlistKind(StrEnum):
    """The repository wordlists that may be viewed or edited."""

    CONTENT = "content"
    SHARE = "share"


@dataclass(frozen=True, slots=True, repr=False)
class WordlistDocument:
    """One wordlist's editable source and effective entry count."""

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
    """Read and atomically replace the two repository wordlists."""

    def __init__(
        self,
        *,
        content_path: str | PathLike[str] | None = None,
        share_path: str | PathLike[str] | None = None,
    ) -> None:
        if content_path is None and share_path is None:
            try:
                content, share = repository_wordlist_paths()
            except ScanConfigError:
                raise WordlistStoreError("Repository wordlists are unavailable.") from None
        elif content_path is None or share_path is None:
            raise WordlistStoreError("Both wordlist paths are required.")
        else:
            try:
                content = Path(content_path)
                share = Path(share_path)
            except (TypeError, ValueError):
                raise WordlistStoreError("Wordlist paths are invalid.") from None

        self._paths = {
            WordlistKind.CONTENT: content,
            WordlistKind.SHARE: share,
        }
        self._lock = RLock()

    def __repr__(self) -> str:
        return "WordlistStore(content_path=<redacted>, share_path=<redacted>)"

    def snapshot(self) -> dict[WordlistKind, WordlistDocument]:
        """Return a coherent in-process view of both wordlists."""

        with self._lock:
            return {
                kind: self._read_unlocked(kind)
                for kind in (WordlistKind.CONTENT, WordlistKind.SHARE)
            }

    def read(self, kind: WordlistKind | str) -> WordlistDocument:
        """Read one wordlist without normalizing its source text."""

        normalized_kind = _coerce_kind(kind)
        with self._lock:
            return self._read_unlocked(normalized_kind)

    def save(self, kind: WordlistKind | str, text: str) -> WordlistDocument:
        """Validate and atomically save one wordlist.

        A missing final line feed is added.  Comments, entry order, blank lines,
        and harmless duplicate entries are otherwise retained exactly.
        """

        normalized_kind = _coerce_kind(kind)
        normalized_text, encoded, entry_count = _prepare_text(normalized_kind, text)

        with self._lock:
            self._replace_unlocked(self._paths[normalized_kind], encoded)
            return WordlistDocument(
                kind=normalized_kind,
                text=normalized_text,
                entry_count=entry_count,
            )

    def _read_unlocked(self, kind: WordlistKind) -> WordlistDocument:
        try:
            encoded = self._paths[kind].read_bytes()
        except OSError:
            raise WordlistStoreError("Wordlist is unavailable.") from None

        if len(encoded) > MAX_WORDLIST_BYTES:
            raise WordlistStoreError("Wordlist must not exceed 1 MiB.")
        try:
            text = encoded.decode("utf-8")
        except UnicodeError:
            raise WordlistStoreError("Wordlist must be UTF-8 text.") from None

        _, _, entry_count = _prepare_text(kind, text, add_final_newline=False)
        return WordlistDocument(kind=kind, text=text, entry_count=entry_count)

    @staticmethod
    def _replace_unlocked(path: Path, encoded: bytes) -> None:
        temporary_path: Path | None = None
        descriptor: int | None = None
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as temporary_file:
                descriptor = None
                temporary_file.write(encoded)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, path)
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


def _coerce_kind(kind: WordlistKind | str) -> WordlistKind:
    if isinstance(kind, WordlistKind):
        return kind
    if not isinstance(kind, str):
        raise WordlistStoreError("Wordlist kind is invalid.")
    try:
        return WordlistKind(kind)
    except ValueError:
        raise WordlistStoreError("Wordlist kind is invalid.") from None


def _prepare_text(
    kind: WordlistKind,
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
    try:
        encoded = normalized_text.encode("utf-8")
    except UnicodeError:
        raise WordlistStoreError("Wordlist must be UTF-8 text.") from None
    if len(encoded) > MAX_WORDLIST_BYTES:
        raise WordlistStoreError("Wordlist must not exceed 1 MiB.")

    entries = _effective_entries(normalized_text)
    if not entries:
        raise WordlistStoreError("Wordlist must contain at least one entry.")
    if kind is WordlistKind.SHARE and any(
        entry in {".", ".."} or "/" in entry or "\\" in entry for entry in entries
    ):
        raise WordlistStoreError("Share wordlist entries must be share names.")
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
