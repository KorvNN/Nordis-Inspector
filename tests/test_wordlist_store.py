from __future__ import annotations

import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from nordis_smb_inspector.core.wordlist_store import (
    MAX_WORDLIST_BYTES,
    WordlistDocument,
    WordlistKind,
    WordlistStore,
    WordlistStoreError,
)


class WordlistStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.content_path = root / "content.txt"
        self.content_path.write_text(
            "# Search terms\n Password \npassword\nşifre kalıbı\n\n",
            encoding="utf-8",
        )
        self.store = WordlistStore(content_path=self.content_path)

    def test_snapshot_returns_raw_text_and_normalized_unique_counts(self) -> None:
        snapshot = self.store.snapshot()

        self.assertEqual(
            snapshot[WordlistKind.CONTENT].text,
            "# Search terms\n Password \npassword\nşifre kalıbı\n\n",
        )
        self.assertEqual(snapshot[WordlistKind.CONTENT].entry_count, 2)

    def test_save_preserves_source_and_adds_final_newline(self) -> None:
        source = "# keep this comment\n token phrase \nTOKEN PHRASE\n\napi_key"

        document = self.store.save(WordlistKind.CONTENT, source)

        expected = f"{source}\n"
        self.assertEqual(document.text, expected)
        self.assertEqual(document.entry_count, 2)
        self.assertEqual(self.content_path.read_text(encoding="utf-8"), expected)

    def test_save_uses_a_temporary_sibling_and_atomic_replace(self) -> None:
        with patch(
            "nordis_smb_inspector.core.wordlist_store.os.replace",
            wraps=os.replace,
        ) as replace:
            self.store.save("content", "Public\nFinance\n")

        temporary, destination = (Path(value) for value in replace.call_args.args)
        self.assertEqual(temporary.parent, self.content_path.parent)
        self.assertEqual(destination, self.content_path)
        self.assertFalse(temporary.exists())

    def test_content_entries_may_be_phrases_and_paths(self) -> None:
        document = self.store.save("content", "BEGIN PRIVATE KEY\nşifre burada\n")
        self.assertEqual(document.entry_count, 2)

        document = self.store.save("content", "../Finance\nDomain\\SYSVOL\n")
        self.assertEqual(document.entry_count, 2)

    def test_empty_effective_wordlist_is_rejected_without_changing_file(self) -> None:
        original = self.content_path.read_bytes()

        with self.assertRaisesRegex(
            WordlistStoreError,
            r"^Wordlist must contain at least one entry\.$",
        ):
            self.store.save("content", "# only a comment\n\n")

        self.assertEqual(self.content_path.read_bytes(), original)

    def test_common_text_line_endings_are_normalized_and_invalid_controls_rejected(self) -> None:
        document = self.store.save("content", "password\r\napi\tkey\roauth\n")
        self.assertEqual(document.text, "password\napi\tkey\noauth\n")

        for invalid in ("token\x00value", "token\x07value"):
            with self.subTest(invalid=repr(invalid)), self.assertRaisesRegex(
                WordlistStoreError,
                r"^Wordlist contains invalid control characters\.$",
            ):
                self.store.save("content", invalid)

    def test_size_limit_applies_after_final_newline_is_added(self) -> None:
        accepted = "a" * (MAX_WORDLIST_BYTES - 1)
        document = self.store.save("content", accepted)
        self.assertEqual(len(document.text.encode("utf-8")), MAX_WORDLIST_BYTES)

        with self.assertRaisesRegex(
            WordlistStoreError,
            r"^Wordlist must not exceed 1 MiB\.$",
        ):
            self.store.save("content", "a" * MAX_WORDLIST_BYTES)

    def test_invalid_utf8_and_storage_errors_have_fixed_safe_messages(self) -> None:
        secret_path = self.content_path.parent / "DoNotLeakPath.txt"
        secret_path.write_bytes(b"\xffDoNotLeakContent")
        store = WordlistStore(content_path=secret_path)

        with self.assertRaises(WordlistStoreError) as caught:
            store.read("content")

        self.assertEqual(str(caught.exception), "Wordlist must be UTF-8 text.")
        self.assertNotIn("DoNotLeak", str(caught.exception))

        missing_store = WordlistStore(
            content_path=self.content_path.parent / "DoNotLeakMissing.txt",
        )
        with self.assertRaises(WordlistStoreError) as missing:
            missing_store.read("content")
        self.assertEqual(str(missing.exception), "Wordlist is unavailable.")
        self.assertNotIn("DoNotLeak", str(missing.exception))

    def test_repr_redacts_text_and_paths_and_documents_are_immutable(self) -> None:
        document = self.store.read("content")

        self.assertNotIn("Password", repr(document))
        self.assertNotIn(str(self.content_path), repr(self.store))
        self.assertIn("<redacted>", repr(document))
        with self.assertRaises(FrozenInstanceError):
            document.text = "changed"  # type: ignore[misc]

    def test_parallel_reads_and_saves_never_return_partial_text(self) -> None:
        variants = ("alpha\n", "beta\n", "gamma\n")

        def save_and_read(index: int) -> str:
            self.store.save("content", variants[index % len(variants)])
            return self.store.read("content").text

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = tuple(executor.map(save_and_read, range(40)))

        self.assertTrue(set(results).issubset(set(variants)))

    def test_invalid_kind_is_safe(self) -> None:
        for invalid in ("DoNotLeakKind", "share", "shares"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                WordlistStoreError,
                r"^Wordlist kind is invalid\.$",
            ):
                self.store.read(invalid)

    def test_document_rejects_invalid_direct_construction_without_exposing_text(self) -> None:
        with self.assertRaisesRegex(
            WordlistStoreError,
            r"^Wordlist entry count is invalid\.$",
        ):
            WordlistDocument(
                kind=WordlistKind.CONTENT,
                text="DoNotLeakContent",
                entry_count=0,
            )


if __name__ == "__main__":
    unittest.main()
