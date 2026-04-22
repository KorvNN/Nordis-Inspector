from __future__ import annotations

import re
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from nordis_smb_inspector.core.scan_config import (
    ScanConfigError,
    ScanOptions,
    parse_scan_options,
    repository_wordlist_paths,
)


class ScanConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.content_path = root / "content.txt"
        self.share_path = root / "shares.txt"
        self.content_path.write_text(
            "\ufeff# defaults\n Password \npassword\nşifre\n\n",
            encoding="utf-8",
        )
        self.share_path.write_text(
            "# shares\nPublic\n public \nC$\n",
            encoding="utf-8",
        )

    def parse(self, search: object, max_depth: object = 32) -> ScanOptions:
        return parse_scan_options(
            search,
            max_depth,
            content_wordlist_path=self.content_path,
            share_wordlist_path=self.share_path,
        )

    def test_loads_defaults_and_casefold_deduplicates_all_terms(self) -> None:
        options = self.parse(
            {
                "use_default": True,
                "additional_terms": [" PASSWORD ", "API_KEY", "api_key", ""],
            },
            max_depth=64,
        )

        self.assertEqual(options.terms, ("Password", "şifre", "API_KEY"))
        self.assertEqual(options.share_names, ("Public", "C$"))
        self.assertEqual(options.max_depth, 64)

    def test_defaults_can_be_disabled_without_reading_content_file(self) -> None:
        self.content_path.unlink()

        options = self.parse(
            {"use_default": False, "additional_terms": ["token", "TOKEN"]}
        )

        self.assertEqual(options.terms, ("token",))
        self.assertEqual(options.share_names, ("Public", "C$"))

    def test_repository_defaults_are_found_from_the_editable_source_tree(self) -> None:
        content_path, share_path = repository_wordlist_paths()

        self.assertEqual(content_path.name, "default-sensitive.txt")
        self.assertEqual(share_path.name, "default-shares.txt")
        options = parse_scan_options(
            {"use_default": True, "additional_terms": []},
            32,
        )
        self.assertIn("password", (term.casefold() for term in options.terms))
        self.assertIn("sysvol", (share.casefold() for share in options.share_names))

    def test_requires_at_least_one_search_term(self) -> None:
        with self.assertRaisesRegex(
            ScanConfigError,
            r"^At least one search term is required\.$",
        ):
            self.parse({"use_default": False, "additional_terms": [" ", ""]})

    def test_web_value_types_are_strictly_validated(self) -> None:
        cases = (
            (None, 32, "Search settings must be an object."),
            ({}, 32, "Search default selection must be a boolean."),
            (
                {"use_default": 1, "additional_terms": []},
                32,
                "Search default selection must be a boolean.",
            ),
            (
                {"use_default": False, "additional_terms": "token"},
                32,
                "Additional search terms must be an array.",
            ),
            (
                {"use_default": False, "additional_terms": ["token", 7]},
                32,
                "Each additional search term must be text.",
            ),
            (
                {"use_default": False, "additional_terms": ["token"]},
                True,
                "Maximum depth must be an integer.",
            ),
            (
                {"use_default": False, "additional_terms": ["token"]},
                32.0,
                "Maximum depth must be an integer.",
            ),
        )
        for search, depth, message in cases:
            with self.subTest(search=search, depth=depth), self.assertRaisesRegex(
                ScanConfigError, f"^{re.escape(message)}$"
            ):
                self.parse(search, depth)

    def test_maximum_depth_is_bounded(self) -> None:
        for depth in (0, 257, -1):
            with self.subTest(depth=depth), self.assertRaisesRegex(
                ScanConfigError,
                r"^Maximum depth must be between 1 and 256\.$",
            ):
                self.parse(
                    {"use_default": False, "additional_terms": ["token"]},
                    depth,
                )

    def test_scan_options_are_immutable_and_repr_hides_values(self) -> None:
        options = self.parse(
            {
                "use_default": False,
                "additional_terms": ["DoNotLeakSearchTerm"],
            }
        )

        rendered = repr(options)
        self.assertNotIn("DoNotLeakSearchTerm", rendered)
        self.assertNotIn("Public", rendered)
        self.assertIn("<redacted 1 entries>", rendered)
        self.assertIn("<redacted 2 entries>", rendered)
        with self.assertRaises(FrozenInstanceError):
            options.max_depth = 1  # type: ignore[misc]

    def test_direct_construction_normalizes_to_immutable_tuples(self) -> None:
        terms = [" token ", "TOKEN"]
        shares = [" Public ", "public"]

        options = ScanOptions(  # type: ignore[arg-type]
            terms=terms,
            share_names=shares,
            max_depth=1,
        )
        terms.append("later")
        shares.append("later")

        self.assertEqual(options.terms, ("token",))
        self.assertEqual(options.share_names, ("Public",))

    def test_file_errors_are_stable_and_do_not_expose_paths_or_contents(self) -> None:
        secret_path = Path(self.temporary_directory.name) / "DoNotLeakPath.txt"
        secret_path.write_bytes(b"\xffDoNotLeakContent")

        with self.assertRaises(ScanConfigError) as caught:
            parse_scan_options(
                {"use_default": True, "additional_terms": []},
                32,
                content_wordlist_path=secret_path,
                share_wordlist_path=self.share_path,
            )

        rendered = str(caught.exception)
        self.assertEqual(rendered, "Content wordlist must be UTF-8 text.")
        self.assertNotIn("DoNotLeak", rendered)

    def test_empty_share_wordlist_is_rejected(self) -> None:
        self.share_path.write_text("# none\n\n", encoding="utf-8")

        with self.assertRaisesRegex(
            ScanConfigError,
            r"^The share wordlist must contain at least one entry\.$",
        ):
            self.parse({"use_default": False, "additional_terms": ["token"]})


if __name__ == "__main__":
    unittest.main()
