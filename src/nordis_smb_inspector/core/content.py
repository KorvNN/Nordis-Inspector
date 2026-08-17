"""Streaming, framework-neutral text content matching.

The scanner intentionally supports only encodings that can be selected without
rewinding the source: BOM-declared UTF-16/32 and strict UTF-8 (with or without a
BOM).  It never tries a locale-dependent legacy encoding after consuming part
of a stream.
"""

from __future__ import annotations

import codecs
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from itertools import chain

_DECODE_BLOCK_BYTES = 64 * 1024
_MAX_LEGACY_SAMPLE_BYTES = 1024 * 1024
_LEGACY_ENCODINGS = frozenset(
    {
        "cp1250",
        "cp1251",
        "cp1252",
        "cp1253",
        "cp1254",
        "cp1257",
        "iso8859_1",
        "iso8859_2",
        "iso8859_3",
        "iso8859_4",
        "iso8859_5",
        "iso8859_7",
        "iso8859_9",
        "iso8859_15",
        "mac_roman",
    }
)


class ContentScanStatus(StrEnum):
    COMPLETE = "complete"
    ENCODING_UNDETERMINED = "encoding_undetermined"
    DECODING_ERROR = "decoding_error"
    LINE_TOO_LONG = "line_too_long"


@dataclass(frozen=True, slots=True)
class MatchSpan:
    """A half-open character range in the original, decoded line."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("A match span must be a non-empty, forward range.")


@dataclass(frozen=True, slots=True, repr=False)
class LineMatch:
    """All occurrences of one search term on one physical line."""

    line_number: int
    line: str
    term: str
    spans: tuple[MatchSpan, ...]

    def __repr__(self) -> str:
        # File contents can contain credentials.  A casual repr must not copy
        # those values into logs, tracebacks, or debugger summaries.
        return (
            f"{type(self).__name__}(line_number={self.line_number!r}, "
            f"line=<redacted {len(self.line)} chars>, term={self.term!r}, "
            f"spans={self.spans!r})"
        )


@dataclass(frozen=True, slots=True)
class ContentDiagnostic:
    """Content-free explanation for an incomplete scan."""

    message: str
    line_number: int | None = None
    limit: int | None = None


@dataclass(frozen=True, slots=True)
class ContentScanResult:
    status: ContentScanStatus
    encoding: str | None
    matches: tuple[LineMatch, ...]
    lines_processed: int
    bytes_consumed: int
    diagnostic: ContentDiagnostic | None = None

    @property
    def complete(self) -> bool:
        return self.status is ContentScanStatus.COMPLETE


@dataclass(frozen=True, slots=True)
class MatchOptions:
    case_sensitive: bool = False
    whole_word: bool = False
    flexible_formats: bool = False
    reverse_terms: bool = False
    max_line_chars: int = 1_048_576

    def __post_init__(self) -> None:
        if not isinstance(self.flexible_formats, bool):
            raise TypeError("flexible_formats must be a boolean.")
        if not isinstance(self.reverse_terms, bool):
            raise TypeError("reverse_terms must be a boolean.")
        if self.max_line_chars < 1:
            raise ValueError("max_line_chars must be at least 1.")


@dataclass(frozen=True, slots=True)
class _PreparedTerm:
    original: str
    needle: str
    flexible: bool = False


def scan_text(
    chunks: Iterable[bytes | bytearray | memoryview],
    terms: Iterable[str],
    *,
    options: MatchOptions | None = None,
    on_line: Callable[[int, str], None] | None = None,
    on_match: Callable[[LineMatch], None] | None = None,
    retain_matches: bool = True,
    legacy_detection_sample_bytes: int = 0,
) -> ContentScanResult:
    """Scan byte chunks once and return matches without retaining the file.

    Match offsets are zero-based, half-open character offsets into ``line``;
    line numbers are one-based.  Duplicate terms under the selected comparison
    mode are collapsed, preserving the first spelling supplied by the caller.
    """

    effective_options = options or MatchOptions()
    if not isinstance(retain_matches, bool):
        raise TypeError("retain_matches must be a boolean.")
    if (
        isinstance(legacy_detection_sample_bytes, bool)
        or not isinstance(legacy_detection_sample_bytes, int)
    ):
        raise TypeError("legacy_detection_sample_bytes must be an integer.")
    if not 0 <= legacy_detection_sample_bytes <= _MAX_LEGACY_SAMPLE_BYTES:
        raise ValueError("legacy_detection_sample_bytes is outside the safe range.")
    prepared_terms = _prepare_terms(terms, effective_options)
    iterator = iter(chunks)
    prefix = bytearray()
    exhausted = False

    while len(prefix) < 4:
        try:
            chunk = next(iterator)
        except StopIteration:
            exhausted = True
            break
        raw = _as_bytes_view(chunk)
        if raw:
            needed = 4 - len(prefix)
            prefix.extend(raw[:needed])
            remainder = raw[needed:]
            if remainder:
                iterator = iter(chain((remainder,), iterator))
                break

    encoding, bom_length, bom_declared = _detect_encoding(prefix)
    initial: bytes | bytearray | memoryview = memoryview(prefix)[bom_length:]
    legacy_detected = False
    if not bom_declared and legacy_detection_sample_bytes:
        sample = bytearray(initial)
        while len(sample) < legacy_detection_sample_bytes and not exhausted:
            try:
                chunk = next(iterator)
            except StopIteration:
                exhausted = True
                break
            raw = _as_bytes_view(chunk)
            needed = legacy_detection_sample_bytes - len(sample)
            sample.extend(raw[:needed])
            remainder = raw[needed:]
            if remainder:
                iterator = iter(chain((remainder,), iterator))
                break
        detected = _detect_legacy_encoding(bytes(sample))
        if detected is not None:
            encoding = detected
            legacy_detected = True
        initial = sample
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    state = _LineState(
        effective_options.max_line_chars,
        prepared_terms,
        effective_options,
        on_line,
        on_match,
        retain_matches,
    )
    bytes_consumed = bom_length

    def consume(raw_chunk: bytes | bytearray | memoryview) -> ContentScanResult | None:
        nonlocal bytes_consumed
        view = _as_bytes_view(raw_chunk)
        for offset in range(0, len(view), _DECODE_BLOCK_BYTES):
            block = view[offset : offset + _DECODE_BLOCK_BYTES]
            bytes_consumed += len(block)
            try:
                decoded = decoder.decode(block, final=False)
            except UnicodeDecodeError:
                return _decode_failure(
                    encoding=encoding,
                    bom_declared=bom_declared,
                    encoding_detected=legacy_detected,
                    state=state,
                    bytes_consumed=bytes_consumed,
                )
            diagnostic = state.feed(decoded)
            if diagnostic is not None:
                return ContentScanResult(
                    status=ContentScanStatus.LINE_TOO_LONG,
                    encoding=encoding,
                    matches=tuple(state.matches),
                    lines_processed=state.lines_processed,
                    bytes_consumed=bytes_consumed,
                    diagnostic=diagnostic,
                )
        return None

    if initial:
        failure = consume(initial)
        if failure is not None:
            return failure

    if not exhausted:
        for chunk in iterator:
            failure = consume(chunk)
            if failure is not None:
                return failure

    try:
        tail = decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return _decode_failure(
            encoding=encoding,
            bom_declared=bom_declared,
            encoding_detected=legacy_detected,
            state=state,
            bytes_consumed=bytes_consumed,
        )
    diagnostic = state.feed(tail)
    if diagnostic is not None:
        return ContentScanResult(
            status=ContentScanStatus.LINE_TOO_LONG,
            encoding=encoding,
            matches=tuple(state.matches),
            lines_processed=state.lines_processed,
            bytes_consumed=bytes_consumed,
            diagnostic=diagnostic,
        )
    state.finish()
    return ContentScanResult(
        status=ContentScanStatus.COMPLETE,
        encoding=encoding,
        matches=tuple(state.matches),
        lines_processed=state.lines_processed,
        bytes_consumed=bytes_consumed,
    )


class _LineState:
    def __init__(
        self,
        max_line_chars: int,
        terms: tuple[_PreparedTerm, ...],
        options: MatchOptions,
        on_line: Callable[[int, str], None] | None,
        on_match: Callable[[LineMatch], None] | None,
        retain_matches: bool,
    ) -> None:
        self.max_line_chars = max_line_chars
        self.terms = terms
        self.options = options
        self.on_line = on_line
        self.on_match = on_match
        self.retain_matches = retain_matches
        self.parts: list[str] = []
        self.current_length = 0
        self.next_line_number = 1
        self.lines_processed = 0
        self.pending_cr = False
        self.matches: list[LineMatch] = []

    def feed(self, text: str) -> ContentDiagnostic | None:
        if not text:
            return None
        position = 0
        if self.pending_cr:
            if text.startswith("\n"):
                position = 1
            self.pending_cr = False

        while position < len(text):
            cr_at = text.find("\r", position)
            lf_at = text.find("\n", position)
            delimiter_at = _first_delimiter(cr_at, lf_at)
            if delimiter_at < 0:
                return self._append(text[position:])

            diagnostic = self._append(text[position:delimiter_at])
            if diagnostic is not None:
                return diagnostic
            self._finish_line()

            if text[delimiter_at] == "\r":
                if delimiter_at + 1 < len(text) and text[delimiter_at + 1] == "\n":
                    position = delimiter_at + 2
                else:
                    self.pending_cr = delimiter_at + 1 == len(text)
                    position = delimiter_at + 1
            else:
                position = delimiter_at + 1
        return None

    def finish(self) -> None:
        if self.current_length:
            self._finish_line()

    def _append(self, value: str) -> ContentDiagnostic | None:
        if not value:
            return None
        prospective_length = self.current_length + len(value)
        if prospective_length > self.max_line_chars:
            return ContentDiagnostic(
                message=(
                    "Physical line exceeds the configured in-memory character limit; "
                    "the file scan stopped without truncating that line."
                ),
                line_number=self.next_line_number,
                limit=self.max_line_chars,
            )
        self.parts.append(value)
        self.current_length = prospective_length
        return None

    def _finish_line(self) -> None:
        line = "".join(self.parts)
        line_matches = _match_line(line, self.next_line_number, self.terms, self.options)
        if self.on_match is not None:
            for match in line_matches:
                self.on_match(match)
        if self.retain_matches:
            self.matches.extend(line_matches)
        if self.on_line is not None:
            self.on_line(self.next_line_number, line)
        self.parts.clear()
        self.current_length = 0
        self.lines_processed += 1
        self.next_line_number += 1


def _prepare_terms(
    terms: Iterable[str],
    options: MatchOptions,
) -> tuple[_PreparedTerm, ...]:
    prepared: list[_PreparedTerm] = []
    seen: set[tuple[bool, str]] = set()
    for term in terms:
        if not isinstance(term, str):
            raise TypeError("Search terms must be strings.")
        if not term:
            raise ValueError("Search terms cannot be empty.")
        variants = [term]
        words = _format_words(term)
        if options.reverse_terms and len(words) > 1:
            reversed_term = " ".join(reversed(words))
            if reversed_term != term:
                variants.append(reversed_term)
        for variant in variants:
            variant_words = _format_words(variant)
            flexible = options.flexible_formats and len(variant_words) > 1
            candidate = "".join(variant_words) if flexible else variant
            needle = candidate if options.case_sensitive else _comparison_fold(candidate)
            key = (flexible, needle)
            if key in seen:
                continue
            seen.add(key)
            prepared.append(
                _PreparedTerm(
                    original=variant,
                    needle=needle,
                    flexible=flexible,
                )
            )
    return tuple(prepared)


def _match_line(
    line: str,
    line_number: int,
    terms: tuple[_PreparedTerm, ...],
    options: MatchOptions,
) -> tuple[LineMatch, ...]:
    if options.case_sensitive:
        haystack = line
        index_map: tuple[int, ...] | None = None
    else:
        haystack, index_map = _casefold_with_index_map(line)
    if any(term.flexible for term in terms):
        compact_haystack, compact_index_map = _compact_with_index_map(
            line,
            case_sensitive=options.case_sensitive,
        )
    else:
        compact_haystack, compact_index_map = "", ()

    matches: list[LineMatch] = []
    claimed_spans: set[tuple[int, int]] = set()
    for term in terms:
        term_haystack = compact_haystack if term.flexible else haystack
        term_index_map = compact_index_map if term.flexible else index_map
        spans: list[MatchSpan] = []
        seen_spans: set[tuple[int, int]] = set()
        start_at = 0
        while True:
            found = term_haystack.find(term.needle, start_at)
            if found < 0:
                break
            folded_end = found + len(term.needle)
            if term_index_map is None:
                start, end = found, folded_end
            else:
                start = term_index_map[found]
                end = term_index_map[folded_end - 1] + 1
            span_key = (start, end)
            if span_key not in seen_spans and span_key not in claimed_spans and (
                not options.whole_word or _has_word_boundaries(line, start, end)
            ):
                seen_spans.add(span_key)
                spans.append(MatchSpan(start=start, end=end))
            start_at = found + 1
        if spans:
            claimed_spans.update((span.start, span.end) for span in spans)
            matches.append(
                LineMatch(
                    line_number=line_number,
                    line=line,
                    term=term.original,
                    spans=tuple(spans),
                )
            )
    return tuple(matches)


def _casefold_with_index_map(value: str) -> tuple[str, tuple[int, ...]]:
    folded_parts: list[str] = []
    indices: list[int] = []
    for index, character in enumerate(value):
        folded = _comparison_fold(character)
        folded_parts.append(folded)
        indices.extend((index,) * len(folded))
    return "".join(folded_parts), tuple(indices)


def _compact_with_index_map(
    value: str,
    *,
    case_sensitive: bool,
) -> tuple[str, tuple[int, ...]]:
    compact_parts: list[str] = []
    indices: list[int] = []
    for index, character in enumerate(value):
        if not character.isalnum():
            continue
        normalized = character if case_sensitive else _comparison_fold(character)
        compact_parts.append(normalized)
        indices.extend((index,) * len(normalized))
    return "".join(compact_parts), tuple(indices)


def _format_words(value: str) -> tuple[str, ...]:
    if not value or not value[0].isalnum() or not value[-1].isalnum():
        return ()

    separated: list[str] = []
    current: list[str] = []
    for character in value:
        if character.isalnum():
            current.append(character)
        elif current:
            separated.append("".join(current))
            current.clear()
    if current:
        separated.append("".join(current))
    if len(separated) > 1:
        return tuple(separated)

    camel_boundaries = [0]
    for index in range(1, len(value)):
        previous = value[index - 1]
        character = value[index]
        following = value[index + 1] if index + 1 < len(value) else ""
        if character.isupper() and (
            previous.islower()
            or previous.isdigit()
            or (previous.isupper() and following.islower())
        ):
            camel_boundaries.append(index)
    if len(camel_boundaries) == 1:
        return ()
    camel_boundaries.append(len(value))
    return tuple(
        value[start:end]
        for start, end in zip(camel_boundaries, camel_boundaries[1:], strict=False)
    )


def _comparison_fold(value: str) -> str:
    """Case-fold text while treating the four Turkish I forms alike.

    Unicode's locale-independent casefold maps ``İ`` to ``i`` plus a combining
    dot and leaves ``ı`` distinct.  Search terms such as ``şifre`` therefore
    miss common all-caps Turkish labels without this comparison-only
    canonicalization.  Original text and reported match offsets stay intact.
    """

    return value.casefold().replace("\u0307", "").replace("ı", "i")


def _has_word_boundaries(line: str, start: int, end: int) -> bool:
    before_is_word = start > 0 and _is_word_character(line[start - 1])
    after_is_word = end < len(line) and _is_word_character(line[end])
    return not before_is_word and not after_is_word


def _is_word_character(character: str) -> bool:
    return character == "_" or character.isalnum()


def _first_delimiter(cr_at: int, lf_at: int) -> int:
    if cr_at < 0:
        return lf_at
    if lf_at < 0:
        return cr_at
    return min(cr_at, lf_at)


def _detect_encoding(prefix: bytearray) -> tuple[str, int, bool]:
    raw = bytes(prefix)
    if raw.startswith(codecs.BOM_UTF32_LE):
        return "utf-32-le", len(codecs.BOM_UTF32_LE), True
    if raw.startswith(codecs.BOM_UTF32_BE):
        return "utf-32-be", len(codecs.BOM_UTF32_BE), True
    if raw.startswith(codecs.BOM_UTF8):
        return "utf-8", len(codecs.BOM_UTF8), True
    if raw.startswith(codecs.BOM_UTF16_LE):
        return "utf-16-le", len(codecs.BOM_UTF16_LE), True
    if raw.startswith(codecs.BOM_UTF16_BE):
        return "utf-16-be", len(codecs.BOM_UTF16_BE), True
    return "utf-8", 0, False


def _detect_legacy_encoding(sample: bytes) -> str | None:
    try:
        sample.decode("utf-8", errors="strict")
        return None
    except UnicodeDecodeError:
        pass
    try:
        from charset_normalizer import from_bytes

        match = from_bytes(sample).best()
    except Exception:
        return None
    if match is None or match.encoding is None:
        return None
    encoding = match.encoding.casefold().replace("-", "_")
    if encoding not in _LEGACY_ENCODINGS:
        return None
    if match.chaos > 0.1 or match.coherence < 0.2:
        return None
    return encoding


def _decode_failure(
    *,
    encoding: str,
    bom_declared: bool,
    encoding_detected: bool,
    state: _LineState,
    bytes_consumed: int,
) -> ContentScanResult:
    if bom_declared or encoding_detected:
        status = ContentScanStatus.DECODING_ERROR
        message = "The byte stream is invalid for its selected text encoding."
    else:
        status = ContentScanStatus.ENCODING_UNDETERMINED
        message = (
            "The BOM-less stream is not valid UTF-8; a safe streaming fallback encoding "
            "cannot be selected without guessing."
        )
    return ContentScanResult(
        status=status,
        encoding=encoding if bom_declared or encoding_detected else None,
        matches=(),
        lines_processed=state.lines_processed,
        bytes_consumed=bytes_consumed,
        diagnostic=ContentDiagnostic(message=message, line_number=state.next_line_number),
    )


def _as_bytes_view(chunk: bytes | bytearray | memoryview) -> memoryview:
    if not isinstance(chunk, (bytes, bytearray, memoryview)):
        raise TypeError("Content chunks must be bytes-like objects.")
    view = memoryview(chunk)
    if view.ndim != 1 or view.itemsize != 1:
        try:
            return view.cast("B")
        except TypeError as error:
            raise TypeError("Content chunks must be contiguous byte data.") from error
    return view.cast("B") if view.format != "B" else view
