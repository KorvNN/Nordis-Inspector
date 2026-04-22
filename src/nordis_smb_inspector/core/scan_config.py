"""Validated, immutable scan options built from the web request.

The repository wordlists are configuration inputs.  They are read only when a
scan starts and are never modified by this module.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

MIN_MAX_DEPTH = 1
MAX_MAX_DEPTH = 256

_CONTENT_WORDLIST = Path("wordlists/content/default-sensitive.txt")
_SHARE_WORDLIST = Path("wordlists/shares/default-shares.txt")


class ScanConfigError(ValueError):
    """A content-free validation or configuration error."""


@dataclass(frozen=True, slots=True, repr=False)
class ScanOptions:
    """All non-credential options needed by one scan.

    ``repr`` intentionally exposes only entry counts.  Search terms can
    themselves be sensitive and should not be copied into incidental logs.
    """

    terms: tuple[str, ...]
    share_names: tuple[str, ...]
    max_depth: int

    def __post_init__(self) -> None:
        terms = _normalize_values(self.terms, "Search terms must be text.")
        share_names = _normalize_values(self.share_names, "Share names must be text.")
        if not terms:
            raise ScanConfigError("At least one search term is required.")
        if not share_names:
            raise ScanConfigError("The share wordlist must contain at least one entry.")
        _validate_max_depth(self.max_depth)
        object.__setattr__(self, "terms", terms)
        object.__setattr__(self, "share_names", share_names)

    def __repr__(self) -> str:
        return (
            f"ScanOptions(terms=<redacted {len(self.terms)} entries>, "
            f"share_names=<redacted {len(self.share_names)} entries>, "
            f"max_depth={self.max_depth!r})"
        )


def parse_scan_options(
    search: object,
    max_depth: object,
    *,
    content_wordlist_path: str | PathLike[str] | None = None,
    share_wordlist_path: str | PathLike[str] | None = None,
) -> ScanOptions:
    """Parse web request values and load the selected repository defaults.

    Paths are injectable so callers and tests do not need to change the
    process working directory.  When omitted, the source checkout containing
    this module is located by walking upward to its ``wordlists`` directory;
    this also works with an editable installation.
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

    depth = _validate_max_depth(max_depth)
    repository_paths: tuple[Path, Path] | None = None

    def defaults() -> tuple[Path, Path]:
        nonlocal repository_paths
        if repository_paths is None:
            repository_paths = repository_wordlist_paths()
        return repository_paths

    terms: tuple[str, ...] = ()
    if use_default:
        content_path = _coerce_path(content_wordlist_path, "Content wordlist path is invalid.")
        if content_path is None:
            content_path = defaults()[0]
        terms = _load_wordlist(content_path, kind="content")

    terms = _normalize_values((*terms, *additional_terms), "Search terms must be text.")
    if not terms:
        raise ScanConfigError("At least one search term is required.")

    share_path = _coerce_path(share_wordlist_path, "Share wordlist path is invalid.")
    if share_path is None:
        share_path = defaults()[1]
    share_names = _load_wordlist(share_path, kind="share")

    return ScanOptions(terms=terms, share_names=share_names, max_depth=depth)


def repository_wordlist_paths(
    start: str | PathLike[str] | None = None,
) -> tuple[Path, Path]:
    """Return the two wordlists in the checkout containing ``start``.

    ``start`` is primarily useful to embedders and tests.  Failure messages do
    not include filesystem paths.
    """

    anchor = _coerce_path(start, "Wordlist lookup path is invalid.")
    if anchor is None:
        anchor = Path(__file__)
    try:
        resolved = anchor.resolve()
    except OSError as exc:
        raise ScanConfigError("Repository wordlists are unavailable.") from exc

    directory = resolved if resolved.is_dir() else resolved.parent
    for candidate in (directory, *directory.parents):
        content_path = candidate / _CONTENT_WORDLIST
        share_path = candidate / _SHARE_WORDLIST
        if content_path.is_file() and share_path.is_file():
            return content_path, share_path
    raise ScanConfigError("Repository wordlists are unavailable.")


def _load_wordlist(path: Path, *, kind: str) -> tuple[str, ...]:
    unavailable = (
        "Content wordlist is unavailable."
        if kind == "content"
        else "Share wordlist is unavailable."
    )
    invalid_text = (
        "Content wordlist must be UTF-8 text."
        if kind == "content"
        else "Share wordlist must be UTF-8 text."
    )
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
