from __future__ import annotations

import re
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from nordis_smb_inspector.core.scan_config import (
    ScanConfigError,
    ScanOptions,
    editable_wordlist_path,
    parse_scan_options,
    repository_wordlist_path,
)


class ScanConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        root = Path(self.temporary_directory.name)
        self.content_path = root / "content.txt"
        self.content_path.write_text(
            "\ufeff# defaults\n Password \npassword\nşifre\n\n",
            encoding="utf-8",
        )

    def parse(self, search: object, max_depth: object = 32) -> ScanOptions:
        return parse_scan_options(
            search,
            max_depth,
            content_wordlist_path=self.content_path,
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
        self.assertEqual(options.max_depth, 64)
        self.assertTrue(options.detect_patterns)

    def test_pattern_detection_can_be_disabled(self) -> None:
        options = self.parse(
            {
                "use_default": True,
                "additional_terms": [],
                "detect_patterns": False,
            }
        )

        self.assertFalse(options.detect_patterns)

    def test_defaults_can_be_disabled_without_reading_content_file(self) -> None:
        self.content_path.unlink()

        options = self.parse(
            {"use_default": False, "additional_terms": ["token", "TOKEN"]}
        )

        self.assertEqual(options.terms, ("token",))

    def test_repository_default_is_found_from_the_editable_source_tree(self) -> None:
        content_path = repository_wordlist_path()

        self.assertEqual(content_path.name, "default-sensitive.txt")
        options = parse_scan_options(
            {"use_default": True, "additional_terms": []},
            32,
        )
        self.assertIn("password", (term.casefold() for term in options.terms))

    def test_packaged_default_matches_the_repository_source(self) -> None:
        source = repository_wordlist_path().read_bytes()
        packaged = (
            files("nordis_smb_inspector.wordlists")
            .joinpath("default-sensitive.txt")
            .read_bytes()
        )

        self.assertEqual(packaged, source)
        terms = tuple(
            line.strip()
            for line in source.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertEqual(len(terms), len({term.casefold() for term in terms}))

    def test_wheel_fallback_initializes_private_editable_user_copy(self) -> None:
        config_home = Path(self.temporary_directory.name) / "xdg-config"
        unavailable = ScanConfigError("Repository wordlist is unavailable.")

        with patch(
            "nordis_smb_inspector.core.scan_config.repository_wordlist_path",
            side_effect=unavailable,
        ):
            content_path = editable_wordlist_path(config_home=config_home)

        self.assertEqual(
            content_path,
            config_home
            / "nordis-smb-inspector"
            / "wordlists"
            / "default-sensitive.txt",
        )
        self.assertEqual(
            content_path.read_bytes(),
            files("nordis_smb_inspector.wordlists")
            .joinpath("default-sensitive.txt")
            .read_bytes(),
        )
        self.assertEqual(stat.S_IMODE(content_path.stat().st_mode), 0o600)

        content_path.write_text("custom-term\n", encoding="utf-8")
        with patch(
            "nordis_smb_inspector.core.scan_config.repository_wordlist_path",
            side_effect=unavailable,
        ):
            existing_path = editable_wordlist_path(config_home=config_home)
        self.assertEqual(existing_path, content_path)
        self.assertEqual(existing_path.read_text(encoding="utf-8"), "custom-term\n")

    def test_wheel_fallback_rejects_relative_config_home(self) -> None:
        unavailable = ScanConfigError("Repository wordlist is unavailable.")
        with patch(
            "nordis_smb_inspector.core.scan_config.repository_wordlist_path",
            side_effect=unavailable,
        ), self.assertRaisesRegex(
            ScanConfigError,
            r"^Content wordlist is unavailable\.$",
        ):
            editable_wordlist_path(config_home="relative/config")

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
                {
                    "use_default": False,
                    "additional_terms": ["token"],
                    "detect_patterns": "yes",
                },
                32,
                "Pattern detection selection must be a boolean.",
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
        self.assertIn("<redacted 1 entries>", rendered)
        with self.assertRaises(FrozenInstanceError):
            options.max_depth = 1  # type: ignore[misc]

    def test_direct_construction_normalizes_to_immutable_tuples(self) -> None:
        terms = [" token ", "TOKEN"]

        options = ScanOptions(  # type: ignore[arg-type]
            terms=terms,
            max_depth=1,
        )
        terms.append("later")

        self.assertEqual(options.terms, ("token",))

    def test_file_errors_are_stable_and_do_not_expose_paths_or_contents(self) -> None:
        secret_path = Path(self.temporary_directory.name) / "DoNotLeakPath.txt"
        secret_path.write_bytes(b"\xffDoNotLeakContent")

        with self.assertRaises(ScanConfigError) as caught:
            parse_scan_options(
                {"use_default": True, "additional_terms": []},
                32,
                content_wordlist_path=secret_path,
            )

        rendered = str(caught.exception)
        self.assertEqual(rendered, "Content wordlist must be UTF-8 text.")
        self.assertNotIn("DoNotLeak", rendered)


if __name__ == "__main__":
    unittest.main()
