"""Validated, immutable scan options built from the web request."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from enum import StrEnum
from fnmatch import fnmatchcase
from importlib.metadata import PackageNotFoundError, distribution
from os import PathLike
from pathlib import Path, PureWindowsPath
from typing import Any

from nordis_smb_inspector.core.detection import (
    DEFAULT_DETECTION_RULE_PACKS,
    DetectionRulePack,
)

MIN_MAX_DEPTH = 1
MAX_MAX_DEPTH = 256

_DISTRIBUTION_NAME = "nordis-smb-inspector"

_DEFAULT_MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024
_DEFAULT_MAX_FILES_PER_SHARE = 2_500


class ScanConfigError(ValueError):
    """A content-free validation or configuration error."""


class ScanProfile(StrEnum):
    """Independent default term list selected by the operator."""

    BASIC = "basic"
    BALANCED = "balanced"
    THOROUGH = "thorough"


_CONTENT_WORDLISTS = {
    ScanProfile.BASIC: Path("wordlists/basic-sensitive.txt"),
    ScanProfile.BALANCED: Path("wordlists/balanced-sensitive.txt"),
    ScanProfile.THOROUGH: Path("wordlists/default-sensitive.txt"),
}
_PACKAGED_WORDLIST_SUFFIXES = {
    profile: Path("share/nordis-smb-inspector") / relative_path
    for profile, relative_path in _CONTENT_WORDLISTS.items()
}
_USER_WORDLISTS = {
    profile: Path("nordis-smb-inspector") / relative_path
    for profile, relative_path in _CONTENT_WORDLISTS.items()
}


@dataclass(frozen=True, slots=True, repr=False)
class FileScanFilter:
    """Bound which remote files are inventoried and opened for content scanning."""

    path_patterns: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    max_file_size_bytes: int | None = None
    max_files_per_share: int | None = None

    def __post_init__(self) -> None:
        patterns = _normalize_values(
            self.path_patterns,
            "File path patterns must be text.",
        )
        if len(patterns) > 50 or any(len(pattern) > 160 for pattern in patterns):
            raise ScanConfigError("At most 50 file path patterns of 160 characters are allowed.")
        extensions = _normalize_extensions(self.extensions)
        _validate_optional_limit(
            self.max_file_size_bytes,
            name="Maximum file size",
            maximum=1024 * 1024 * 1024,
        )
        _validate_optional_limit(
            self.max_files_per_share,
            name="Maximum files per share",
            maximum=100_000,
        )
        object.__setattr__(self, "path_patterns", patterns)
        object.__setattr__(self, "extensions", extensions)

    def matches(self, relative_path: str, size: int | None) -> bool:
        """Return whether a normalized SMB file is inside the selected scope."""

        normalized_path = relative_path.replace("/", "\\").casefold()
        basename = PureWindowsPath(relative_path).name.casefold()
        if self.path_patterns and not any(
            fnmatchcase(normalized_path, pattern.replace("/", "\\").casefold())
            or fnmatchcase(basename, pattern.casefold())
            for pattern in self.path_patterns
        ):
            return False
        if self.extensions and not any(
            basename.endswith(extension) for extension in self.extensions
        ):
            return False
        return not (
            size is not None
            and self.max_file_size_bytes is not None
            and size > self.max_file_size_bytes
        )

    def __repr__(self) -> str:
        return (
            "FileScanFilter("
            f"path_patterns=<redacted {len(self.path_patterns)} entries>, "
            f"extensions={len(self.extensions)} selected, "
            f"max_file_size_bytes={self.max_file_size_bytes!r}, "
            f"max_files_per_share={self.max_files_per_share!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ScanOptions:
    """All non-credential options needed by one scan.

    ``repr`` intentionally exposes only entry counts. Search terms can
    themselves be sensitive and should not be copied into incidental logs.
    """

    terms: tuple[str, ...]
    max_depth: int
    detect_patterns: bool = True
    rule_packs: tuple[DetectionRulePack, ...] = DEFAULT_DETECTION_RULE_PACKS
    use_default: bool = False
    additional_terms: tuple[str, ...] = ()
    profile: ScanProfile = ScanProfile.THOROUGH
    file_filter: FileScanFilter = field(default_factory=FileScanFilter)

    def __post_init__(self) -> None:
        terms = _normalize_values(self.terms, "Search terms must be text.")
        _validate_max_depth(self.max_depth)
        if not isinstance(self.detect_patterns, bool):
            raise ScanConfigError("Pattern detection selection must be a boolean.")
        if not isinstance(self.use_default, bool):
            raise ScanConfigError("Default search selection must be a boolean.")
        if not isinstance(self.profile, ScanProfile):
            raise ScanConfigError("Scan profile is invalid.")
        if not isinstance(self.file_filter, FileScanFilter):
            raise ScanConfigError("File scan filter is invalid.")
        rule_packs = _validate_rule_packs(self.rule_packs)
        additional_terms = _normalize_values(
            self.additional_terms,
            "Additional search terms must be text.",
        )
        if self.detect_patterns and not rule_packs:
            raise ScanConfigError("At least one detection rule pack is required.")
        if not terms and not self.detect_patterns:
            raise ScanConfigError(
                "Enable pattern detection or provide at least one search term."
            )
        object.__setattr__(self, "terms", terms)
        object.__setattr__(self, "rule_packs", rule_packs)
        object.__setattr__(self, "additional_terms", additional_terms)

    def __repr__(self) -> str:
        return (
            f"ScanOptions(terms=<redacted {len(self.terms)} entries>, "
            f"max_depth={self.max_depth!r}, detect_patterns={self.detect_patterns!r}, "
            f"rule_packs={len(self.rule_packs)} selected, "
            f"use_default={self.use_default!r}, "
            f"additional_terms=<redacted {len(self.additional_terms)} entries>, "
            f"profile={self.profile.value!r}, file_filter={self.file_filter!r})"
        )


def parse_scan_options(
    search: object,
    max_depth: object,
    *,
    content_wordlist_path: str | PathLike[str] | None = None,
    content_wordlist_paths: Mapping[
        ScanProfile | str,
        str | PathLike[str],
    ]
    | None = None,
) -> ScanOptions:
    """Parse literal terms and built-in pattern selections.

    The default sensitive-term list is enabled when ``use_default`` is omitted,
    preserving broad detection for older clients while allowing an operator to
    disable literal matching explicitly.
    """

    if not isinstance(search, Mapping):
        raise ScanConfigError("Search settings must be an object.")

    raw_profile = search.get("profile", ScanProfile.THOROUGH.value)
    if not isinstance(raw_profile, str):
        raise ScanConfigError("Scan profile must be text.")
    try:
        profile = ScanProfile(raw_profile)
    except ValueError:
        raise ScanConfigError("Scan profile is unknown.") from None
    use_default = search.get("use_default", True)
    if not isinstance(use_default, bool):
        raise ScanConfigError("Default search selection must be a boolean.")

    additional_terms = search.get("additional_terms")
    if not isinstance(additional_terms, list):
        raise ScanConfigError("Additional search terms must be an array.")
    if not all(isinstance(term, str) for term in additional_terms):
        raise ScanConfigError("Each additional search term must be text.")

    detect_patterns = search.get("detect_patterns", True)
    if not isinstance(detect_patterns, bool):
        raise ScanConfigError("Pattern detection selection must be a boolean.")
    raw_rule_packs = search.get(
        "rule_packs",
        [pack.value for pack in DEFAULT_DETECTION_RULE_PACKS],
    )
    if not isinstance(raw_rule_packs, list):
        raise ScanConfigError("Detection rule packs must be an array.")
    if not all(isinstance(pack, str) for pack in raw_rule_packs):
        raise ScanConfigError("Each detection rule pack must be text.")
    try:
        rule_packs = tuple(dict.fromkeys(DetectionRulePack(pack) for pack in raw_rule_packs))
    except ValueError:
        raise ScanConfigError("Detection rule pack is unknown.") from None
    normalized_additional_terms = _normalize_values(
        additional_terms,
        "Search terms must be text.",
    )
    default_terms = (
        _load_default_sensitive_terms(
            _selected_wordlist_path(
                profile,
                content_wordlist_path=content_wordlist_path,
                content_wordlist_paths=content_wordlist_paths,
            )
        )
        if use_default
        else ()
    )

    path_patterns = _parse_text_array(
        search.get("file_path_patterns", []),
        array_error="File path patterns must be an array.",
        item_error="Each file path pattern must be text.",
    )
    requested_extensions = _parse_text_array(
        search.get("file_extensions", []),
        array_error="File extensions must be an array.",
        item_error="Each file extension must be text.",
    )
    raw_max_size_mb = search.get("max_file_size_mb")
    if raw_max_size_mb is None:
        max_file_size_bytes = _DEFAULT_MAX_FILE_SIZE_BYTES
    elif isinstance(raw_max_size_mb, bool) or not isinstance(raw_max_size_mb, int):
        raise ScanConfigError("Maximum file size must be an integer MiB value.")
    elif not 1 <= raw_max_size_mb <= 1024:
        raise ScanConfigError("Maximum file size must be between 1 and 1024 MiB.")
    else:
        max_file_size_bytes = raw_max_size_mb * 1024 * 1024

    file_filter = FileScanFilter(
        path_patterns=path_patterns,
        extensions=requested_extensions,
        max_file_size_bytes=max_file_size_bytes,
        max_files_per_share=_DEFAULT_MAX_FILES_PER_SHARE,
    )

    return ScanOptions(
        terms=_normalize_values(
            (*default_terms, *normalized_additional_terms),
            "Search terms must be text.",
        ),
        max_depth=_validate_max_depth(max_depth),
        detect_patterns=detect_patterns,
        rule_packs=rule_packs,
        use_default=use_default,
        additional_terms=normalized_additional_terms,
        profile=profile,
        file_filter=file_filter,
    )


def _parse_text_array(
    value: object,
    *,
    array_error: str,
    item_error: str,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ScanConfigError(array_error)
    if not all(isinstance(item, str) for item in value):
        raise ScanConfigError(item_error)
    return _normalize_values(value, item_error)


def _normalize_extensions(values: Iterable[Any]) -> tuple[str, ...]:
    normalized = _normalize_values(values, "File extensions must be text.")
    result: list[str] = []
    for value in normalized:
        extension = value.casefold()
        if not extension.startswith("."):
            extension = f".{extension}"
        if (
            len(extension) > 24
            or len(extension) < 2
            or any(character in extension for character in "\\/*?[]")
        ):
            raise ScanConfigError("File extension filter is invalid.")
        result.append(extension)
    if len(result) > 64:
        raise ScanConfigError("At most 64 file extensions are allowed.")
    return tuple(dict.fromkeys(result))


def _validate_optional_limit(value: int | None, *, name: str, maximum: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ScanConfigError(f"{name} is outside the supported range.")


def _load_default_sensitive_terms(
    path: str | PathLike[str],
) -> tuple[str, ...]:
    wordlist_path = _coerce_wordlist_path(path)
    if wordlist_path is None:  # pragma: no cover - caller always supplies a path
        raise ScanConfigError("Default content wordlist path is invalid.")
    try:
        raw = wordlist_path.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise ScanConfigError("Default content wordlist must be UTF-8 text.") from exc
    except OSError as exc:
        raise ScanConfigError("Default content wordlist is unavailable.") from exc
    values = (
        entry
        for line in raw.splitlines()
        if (entry := line.strip()) and not entry.startswith("#")
    )
    terms = _normalize_values(
        values,
        "Default content wordlist must be UTF-8 text.",
    )
    if not terms:
        raise ScanConfigError("Default content wordlist must contain at least one term.")
    return terms


def _selected_wordlist_path(
    profile: ScanProfile,
    *,
    content_wordlist_path: str | PathLike[str] | None,
    content_wordlist_paths: Mapping[ScanProfile | str, str | PathLike[str]] | None,
) -> Path:
    if content_wordlist_path is not None:
        selected = _coerce_wordlist_path(content_wordlist_path)
        if selected is None:  # pragma: no cover - non-None input cannot coerce to None
            raise ScanConfigError("Default content wordlist path is invalid.")
        return selected
    if content_wordlist_paths is not None:
        if not isinstance(content_wordlist_paths, Mapping):
            raise ScanConfigError("Default content wordlist paths are invalid.")
        selected_value = content_wordlist_paths.get(profile)
        if selected_value is None:
            selected_value = content_wordlist_paths.get(profile.value)
        selected = _coerce_wordlist_path(selected_value)
        if selected is None:
            raise ScanConfigError("Selected content wordlist is unavailable.")
        return selected
    return editable_wordlist_path(profile=profile)


def _coerce_wordlist_path(value: str | PathLike[str] | None) -> Path | None:
    if value is None:
        return None
    try:
        return Path(value)
    except (TypeError, ValueError):
        raise ScanConfigError("Default content wordlist path is invalid.") from None


def editable_wordlist_path(
    *,
    profile: ScanProfile = ScanProfile.THOROUGH,
    repository_start: str | PathLike[str] | None = None,
    config_home: str | PathLike[str] | None = None,
) -> Path:
    """Return the repository list or an editable per-user installed copy."""

    if not isinstance(profile, ScanProfile):
        raise ScanConfigError("Scan profile is invalid.")
    repository_path = _repository_wordlist_path(repository_start, profile=profile)
    if repository_path is not None:
        return repository_path
    return _initialize_user_wordlist(config_home, profile=profile)


def _repository_wordlist_path(
    start: str | PathLike[str] | None = None,
    *,
    profile: ScanProfile = ScanProfile.THOROUGH,
) -> Path | None:
    try:
        anchor = Path(__file__) if start is None else Path(start)
        resolved = anchor.resolve()
    except (OSError, TypeError, ValueError):
        return None
    directory = resolved if resolved.is_dir() else resolved.parent
    for candidate in (directory, *directory.parents):
        wordlist_path = candidate / _CONTENT_WORDLISTS[profile]
        if wordlist_path.is_file():
            return wordlist_path
    return None


def _initialize_user_wordlist(
    config_home: str | PathLike[str] | None,
    *,
    profile: ScanProfile,
) -> Path:
    destination = _config_home(config_home) / _USER_WORDLISTS[profile]
    if destination.is_file():
        return destination

    unavailable = "Default content wordlist is unavailable."
    try:
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        default_bytes = _installed_wordlist_path(profile).read_bytes()
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


def _config_home(value: str | PathLike[str] | None) -> Path:
    unavailable = "Default content wordlist is unavailable."
    if value is None:
        configured = os.environ.get("XDG_CONFIG_HOME")
        try:
            base = Path(configured) if configured else Path.home() / ".config"
        except (RuntimeError, TypeError, ValueError):
            raise ScanConfigError(unavailable) from None
    else:
        base = _coerce_wordlist_path(value)
        if base is None:
            raise ScanConfigError(unavailable)
    if not base.is_absolute():
        raise ScanConfigError(unavailable)
    return base


def _installed_wordlist_path(profile: ScanProfile = ScanProfile.THOROUGH) -> Path:
    try:
        installed = distribution(_DISTRIBUTION_NAME)
        installation_root = Path(installed.locate_file("")).resolve()
        relative_path = _PACKAGED_WORDLIST_SUFFIXES[profile]
        for candidate_root in (installation_root, *installation_root.parents):
            candidate = candidate_root / relative_path
            if candidate.is_file():
                return candidate
        raise ScanConfigError("Default content wordlist is unavailable.")
    except PackageNotFoundError:
        raise ScanConfigError("Default content wordlist is unavailable.") from None
    except (OSError, TypeError, ValueError):
        raise ScanConfigError("Default content wordlist is unavailable.") from None


def _validate_rule_packs(
    values: tuple[DetectionRulePack, ...],
) -> tuple[DetectionRulePack, ...]:
    if not isinstance(values, tuple) or not all(
        isinstance(value, DetectionRulePack) for value in values
    ):
        raise ScanConfigError("Detection rule packs are invalid.")
    if len(values) != len(set(values)):
        raise ScanConfigError("Detection rule packs must be unique.")
    return values


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
