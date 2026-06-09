"""Validated, immutable scan options built from the web request.

Source checkouts use the repository wordlist. Installed wheels initialize an
editable user copy from the packaged default on first use. The selected file is
read only when a scan starts and is never modified by this module.
"""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from os import PathLike
from pathlib import Path
from typing import Any

MIN_MAX_DEPTH = 1
MAX_MAX_DEPTH = 256

_CONTENT_WORDLIST = Path("wordlists/default-sensitive.txt")
_DISTRIBUTION_NAME = "nordis-smb-inspector"
_PACKAGED_WORDLIST_SUFFIX = "share/nordis-smb-inspector/wordlists/default-sensitive.txt"
_USER_WORDLIST = Path("nordis-smb-inspector/wordlists/default-sensitive.txt")


class ScanConfigError(ValueError):
    """A content-free validation or configuration error."""


@dataclass(frozen=True, slots=True, repr=False)
class ScanOptions:
    """All non-credential options needed by one scan.

    ``repr`` intentionally exposes only entry counts.  Search terms can
    themselves be sensitive and should not be copied into incidental logs.
    """

    terms: tuple[str, ...]
    max_depth: int
    detect_patterns: bool = True

    def __post_init__(self) -> None:
        terms = _normalize_values(self.terms, "Search terms must be text.")
        if not terms:
            raise ScanConfigError("At least one search term is required.")
        _validate_max_depth(self.max_depth)
        if not isinstance(self.detect_patterns, bool):
            raise ScanConfigError("Pattern detection selection must be a boolean.")
        object.__setattr__(self, "terms", terms)

    def __repr__(self) -> str:
        return (
            f"ScanOptions(terms=<redacted {len(self.terms)} entries>, "
            f"max_depth={self.max_depth!r}, detect_patterns={self.detect_patterns!r})"
        )


def parse_scan_options(
    search: object,
    max_depth: object,
    *,
    content_wordlist_path: str | PathLike[str] | None = None,
) -> ScanOptions:
    """Parse web request values and load the selected repository default.

    The path is injectable so callers and tests do not need to change the
    process working directory. When omitted, editable installs use the source
    checkout and wheel installs use the initialized per-user copy.
    """

    if not isinstance(search, Mapping):
        raise ScanConfigError("Search settings must be an object.")

    use_default = search.get("use_default")
    if not isinstance(use_default, bool):
        raise ScanConfigError("Search default selection must be a boolean.")

    additional_terms = search.get("additional_terms")
    if not isinstance(additional_terms, list):
        raise ScanConfigError("Additional search terms must be an array.")
    if not all(isinstance(term, str) for term in additional_terms):
        raise ScanConfigError("Each additional search term must be text.")
    detect_patterns = search.get("detect_patterns", True)
    if not isinstance(detect_patterns, bool):
        raise ScanConfigError("Pattern detection selection must be a boolean.")

    depth = _validate_max_depth(max_depth)

    terms: tuple[str, ...] = ()
    if use_default:
        content_path = _coerce_path(content_wordlist_path, "Content wordlist path is invalid.")
        if content_path is None:
            content_path = editable_wordlist_path()
        terms = _load_wordlist(content_path)

    terms = _normalize_values((*terms, *additional_terms), "Search terms must be text.")
    if not terms:
        raise ScanConfigError("At least one search term is required.")

    return ScanOptions(
        terms=terms,
        max_depth=depth,
        detect_patterns=detect_patterns,
    )


def editable_wordlist_path(
    *,
    repository_start: str | PathLike[str] | None = None,
    config_home: str | PathLike[str] | None = None,
) -> Path:
    """Return the editable content wordlist for this installation.

    Editable source checkouts keep using the tracked repository file. A wheel
    installation has no such parent tree, so its packaged default is copied once
    to the user's XDG configuration directory. Existing user content is never
    overwritten during initialization.
    """

    try:
        return repository_wordlist_path(repository_start)
    except ScanConfigError:
        return _initialize_user_wordlist(config_home)


def repository_wordlist_path(
    start: str | PathLike[str] | None = None,
) -> Path:
    """Return the content wordlist in the checkout containing ``start``.

    ``start`` is primarily useful to embedders and tests.  Failure messages do
    not include filesystem paths.
    """

    anchor = _coerce_path(start, "Wordlist lookup path is invalid.")
    if anchor is None:
        anchor = Path(__file__)
    try:
        resolved = anchor.resolve()
    except OSError as exc:
        raise ScanConfigError("Repository wordlist is unavailable.") from exc

    directory = resolved if resolved.is_dir() else resolved.parent
    for candidate in (directory, *directory.parents):
        content_path = candidate / _CONTENT_WORDLIST
        if content_path.is_file():
            return content_path
    raise ScanConfigError("Repository wordlist is unavailable.")


def _initialize_user_wordlist(
    config_home: str | PathLike[str] | None,
) -> Path:
    base = _config_home(config_home)
    destination = base / _USER_WORDLIST
    if destination.is_file():
        return destination

    unavailable = "Content wordlist is unavailable."
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        default_bytes = _packaged_wordlist_bytes()
    except (OSError, ScanConfigError):
        raise ScanConfigError(unavailable) from None

    temporary_path: Path | None = None
    descriptor: int | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "wb") as temporary_file:
            descriptor = None
            temporary_file.write(default_bytes)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        try:
            os.link(temporary_path, destination)
        except FileExistsError:
            if not destination.is_file():
                raise ScanConfigError(unavailable) from None
        return destination
    except ScanConfigError:
        raise
    except OSError:
        raise ScanConfigError(unavailable) from None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink()


def _packaged_wordlist_bytes() -> bytes:
    """Read the canonical wordlist installed as distribution data."""

    try:
        installed = distribution(_DISTRIBUTION_NAME)
        matches = [
            entry
            for entry in installed.files or ()
            if str(entry).replace("\\", "/").endswith(_PACKAGED_WORDLIST_SUFFIX)
        ]
        if len(matches) != 1:
            raise ScanConfigError("Content wordlist is unavailable.")
        return Path(installed.locate_file(matches[0])).read_bytes()
    except PackageNotFoundError:
        raise ScanConfigError("Content wordlist is unavailable.") from None
    except (OSError, TypeError, ValueError):
        raise ScanConfigError("Content wordlist is unavailable.") from None


def _config_home(value: str | PathLike[str] | None) -> Path:
    unavailable = "Content wordlist is unavailable."
    if value is None:
        configured = os.environ.get("XDG_CONFIG_HOME")
        try:
            base = Path(configured) if configured else Path.home() / ".config"
        except (RuntimeError, TypeError, ValueError):
            raise ScanConfigError(unavailable) from None
    else:
        base = _coerce_path(value, unavailable)
        if base is None:
            raise ScanConfigError(unavailable)
    if not base.is_absolute():
        raise ScanConfigError(unavailable)
    return base


def _load_wordlist(path: Path) -> tuple[str, ...]:
    unavailable = "Content wordlist is unavailable."
    invalid_text = "Content wordlist must be UTF-8 text."
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise ScanConfigError(invalid_text) from exc
    except OSError as exc:
        raise ScanConfigError(unavailable) from exc

    values = (
        stripped
        for line in raw.splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    )
    return _normalize_values(values, invalid_text)


def _normalize_values(values: Iterable[Any], item_error: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray, memoryview)):
        raise ScanConfigError(item_error)
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ScanConfigError(item_error) from exc

    result: list[str] = []
    seen: set[str] = set()
    for value in iterator:
        if not isinstance(value, str):
            raise ScanConfigError(item_error)
        cleaned = value.strip()
        if not cleaned:
            continue
        comparison_key = cleaned.casefold()
        if comparison_key in seen:
            continue
        seen.add(comparison_key)
        result.append(cleaned)
    return tuple(result)


def _validate_max_depth(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ScanConfigError("Maximum depth must be an integer.")
    if not MIN_MAX_DEPTH <= value <= MAX_MAX_DEPTH:
        raise ScanConfigError("Maximum depth must be between 1 and 256.")
    return value


def _coerce_path(
    value: str | PathLike[str] | None,
    error_message: str,
) -> Path | None:
    if value is None:
        return None
    try:
        return Path(value)
    except (TypeError, ValueError) as exc:
        raise ScanConfigError(error_message) from exc
