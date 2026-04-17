from __future__ import annotations

import codecs
import unittest

from nordis_smb_inspector.core.content import (
    ContentScanStatus,
    MatchOptions,
    MatchSpan,
    scan_text,
)


def every_byte(value: bytes):
    for byte in value:
        yield bytes((byte,))


class ContentScanTests(unittest.TestCase):
    def test_utf8_bom_and_crlf_across_single_byte_chunks(self) -> None:
        content = codecs.BOM_UTF8 + "ilk\r\nPassword=bir\r\nson".encode()

        result = scan_text(every_byte(content), ["password"])

        self.assertEqual(ContentScanStatus.COMPLETE, result.status)
        self.assertEqual("utf-8", result.encoding)
        self.assertEqual(3, result.lines_processed)
        self.assertEqual(1, len(result.matches))
        match = result.matches[0]
        self.assertEqual(2, match.line_number)
        self.assertEqual("Password=bir", match.line)
        self.assertEqual("password", match.term)
        self.assertEqual((MatchSpan(0, 8),), match.spans)

    def test_all_bom_declared_utf_encodings_work_at_arbitrary_boundaries(self) -> None:
        cases = (
            (codecs.BOM_UTF16_LE, "utf-16-le"),
            (codecs.BOM_UTF16_BE, "utf-16-be"),
            (codecs.BOM_UTF32_LE, "utf-32-le"),
            (codecs.BOM_UTF32_BE, "utf-32-be"),
        )
        for bom, encoding in cases:
            with self.subTest(encoding=encoding):
                content = bom + "önce\nŞİFRE burada".encode(encoding)
                result = scan_text(every_byte(content), ["şİfre"])

                self.assertEqual(ContentScanStatus.COMPLETE, result.status)
                self.assertEqual(encoding, result.encoding)
                self.assertEqual(2, result.lines_processed)
                self.assertEqual("ŞİFRE burada", result.matches[0].line)
                self.assertEqual((MatchSpan(0, 5),), result.matches[0].spans)

    def test_casefold_maps_expanding_characters_back_to_original_offsets(self) -> None:
        result = scan_text(["Straße STRASSE".encode()], ["strasse"])

        self.assertEqual(1, len(result.matches))
        self.assertEqual((MatchSpan(0, 6), MatchSpan(7, 14)), result.matches[0].spans)

    def test_duplicate_terms_are_collapsed_and_multiple_terms_are_reported(self) -> None:
        result = scan_text(
            [b"password Password token password"],
            ["password", "PASSWORD", "token", "token"],
        )

        self.assertEqual(2, len(result.matches))
        self.assertEqual("password", result.matches[0].term)
        self.assertEqual(
            (MatchSpan(0, 8), MatchSpan(9, 17), MatchSpan(24, 32)),
            result.matches[0].spans,
        )
        self.assertEqual("token", result.matches[1].term)
        self.assertEqual((MatchSpan(18, 23),), result.matches[1].spans)

    def test_case_sensitive_mode(self) -> None:
        result = scan_text(
            [b"Password password"],
            ["password"],
            options=MatchOptions(case_sensitive=True),
        )

        self.assertEqual((MatchSpan(9, 17),), result.matches[0].spans)

    def test_whole_word_mode_uses_unicode_word_characters_and_underscore(self) -> None:
        result = scan_text(
            ["parola parolalar _parola parola-şifre".encode()],
            ["parola"],
            options=MatchOptions(whole_word=True),
        )

        self.assertEqual((MatchSpan(0, 6), MatchSpan(25, 31)), result.matches[0].spans)

    def test_overlapping_matches_are_reported(self) -> None:
        result = scan_text([b"banana"], ["ana"])

        self.assertEqual((MatchSpan(1, 4), MatchSpan(3, 6)), result.matches[0].spans)

    def test_final_line_and_empty_physical_lines_are_counted(self) -> None:
        result = scan_text([b"\nneedle\n\nlast"], ["needle", "last"])

        self.assertEqual(ContentScanStatus.COMPLETE, result.status)
        self.assertEqual(4, result.lines_processed)
        self.assertEqual([2, 4], [match.line_number for match in result.matches])

    def test_line_limit_stops_without_truncating_or_exposing_partial_line(self) -> None:
        result = scan_text(
            [b"password ok\n", b"secret", b"-tail-without-newline"],
            ["password", "secret"],
            options=MatchOptions(max_line_chars=12),
        )

        self.assertEqual(ContentScanStatus.LINE_TOO_LONG, result.status)
        self.assertEqual(1, result.lines_processed)
        self.assertEqual(1, len(result.matches))
        self.assertEqual("password ok", result.matches[0].line)
        self.assertEqual(2, result.diagnostic.line_number)
        self.assertEqual(12, result.diagnostic.limit)

    def test_bomless_invalid_utf8_has_no_guessed_fallback_or_partial_matches(self) -> None:
        result = scan_text([b"password\n", b"\xfflegacy"], ["password"])

        self.assertEqual(ContentScanStatus.ENCODING_UNDETERMINED, result.status)
        self.assertIsNone(result.encoding)
        self.assertEqual((), result.matches)
        self.assertIn("without guessing", result.diagnostic.message)

    def test_invalid_bom_declared_stream_is_a_decoding_error(self) -> None:
        result = scan_text([codecs.BOM_UTF16_LE + b"a"], ["a"])

        self.assertEqual(ContentScanStatus.DECODING_ERROR, result.status)
        self.assertEqual("utf-16-le", result.encoding)

    def test_match_repr_redacts_the_line(self) -> None:
        result = scan_text([b"password=super-secret"], ["password"])

        rendered = repr(result.matches[0])
        self.assertIn("redacted", rendered)
        self.assertNotIn("super-secret", rendered)

    def test_empty_and_non_string_terms_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scan_text([b"text"], [""])
        with self.assertRaises(TypeError):
            scan_text([b"text"], [b"text"])  # type: ignore[list-item]

    def test_invalid_chunk_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            scan_text(["not bytes"], ["term"])  # type: ignore[list-item]


if __name__ == "__main__":
    unittest.main()
