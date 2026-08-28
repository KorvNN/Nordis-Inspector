"""Thread-safe viewing and editing of the default content term list."""

from __future__ import annotations

import os
import stat
import tempfile
import unicodedata
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from os import PathLike
from pathlib import Path
from threading import RLock

from nordis_smb_inspector.core.scan_config import (
    ScanConfigError,
    ScanProfile,
    editable_wordlist_path,
)

MAX_WORDLIST_BYTES = 1024 * 1024


class WordlistStoreError(ValueError):
    """A content-free wordlist validation or storage error."""


class WordlistKind(StrEnum):
    """A wordlist exposed by the local editor."""

    BASIC = "basic"
    BALANCED = "balanced"
    THOROUGH = "thorough"


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
    """Read and atomically replace the three editable default term lists."""

    def __init__(
        self,
        *,
        content_path: str | PathLike[str] | None = None,
        content_paths: Mapping[WordlistKind | str, str | PathLike[str]] | None = None,
    ) -> None:
        if content_path is not None and content_paths is not None:
            raise WordlistStoreError("Wordlist paths are invalid.")
        if content_paths is not None:
            paths = {
                kind: _path_from_mapping(content_paths, kind)
                for kind in WordlistKind
            }
        elif content_path is not None:
            content = _coerce_path(content_path)
            paths = {kind: content for kind in WordlistKind}
        else:
            try:
                paths = {
                    kind: editable_wordlist_path(profile=ScanProfile(kind.value))
                    for kind in WordlistKind
                }
            except ScanConfigError:
                raise WordlistStoreError("Wordlist is unavailable.") from None
        self._content_paths = paths
        self._lock = RLock()

    @property
    def content_path(self) -> Path:
        """Compatibility alias for the thorough list path."""

        return self._content_paths[WordlistKind.THOROUGH]

    @property
    def content_paths(self) -> dict[ScanProfile, Path]:
        return {
            ScanProfile(kind.value): path
            for kind, path in self._content_paths.items()
        }

    def __repr__(self) -> str:
        return "WordlistStore(content_paths=<redacted 3 entries>)"

    def read(self, kind: WordlistKind = WordlistKind.THOROUGH) -> WordlistDocument:
        if not isinstance(kind, WordlistKind):
            raise WordlistStoreError("Wordlist kind is invalid.")
        with self._lock:
            return self._read_unlocked(kind)

    def read_all(self) -> tuple[WordlistDocument, ...]:
        with self._lock:
            return tuple(self._read_unlocked(kind) for kind in WordlistKind)

    def save(
        self,
        text: str,
        kind: WordlistKind = WordlistKind.THOROUGH,
    ) -> WordlistDocument:
        if not isinstance(kind, WordlistKind):
            raise WordlistStoreError("Wordlist kind is invalid.")
        normalized_text, encoded, entry_count = _prepare_text(text)
        with self._lock:
            self._replace_unlocked(kind, encoded)
            return WordlistDocument(
                kind=kind,
                text=normalized_text,
                entry_count=entry_count,
            )

    def _read_unlocked(self, kind: WordlistKind) -> WordlistDocument:
        try:
            encoded = self._content_paths[kind].read_bytes()
        except OSError:
            raise WordlistStoreError("Wordlist is unavailable.") from None
        if len(encoded) > MAX_WORDLIST_BYTES:
            raise WordlistStoreError("Wordlist must not exceed 1 MiB.")
        try:
            text = encoded.decode("utf-8")
        except UnicodeError:
            raise WordlistStoreError("Wordlist must be UTF-8 text.") from None
        _, _, entry_count = _prepare_text(text, add_final_newline=False)
        return WordlistDocument(kind, text, entry_count)

    def _replace_unlocked(self, kind: WordlistKind, encoded: bytes) -> None:
        destination = self._content_paths[kind]
        temporary_path: Path | None = None
        descriptor: int | None = None
        try:
            mode = stat.S_IMODE(destination.stat().st_mode)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            temporary_path = Path(temporary_name)
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as temporary_file:
                descriptor = None
                temporary_file.write(encoded)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, destination)
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


def _coerce_path(value: str | PathLike[str]) -> Path:
    try:
        return Path(value)
    except (TypeError, ValueError):
        raise WordlistStoreError("Wordlist path is invalid.") from None


def _path_from_mapping(
    values: Mapping[WordlistKind | str, str | PathLike[str]],
    kind: WordlistKind,
) -> Path:
    if not isinstance(values, Mapping):
        raise WordlistStoreError("Wordlist paths are invalid.")
    value = values.get(kind)
    if value is None:
        value = values.get(kind.value)
    if value is None:
        raise WordlistStoreError("Wordlist path is missing.")
    return _coerce_path(value)


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
