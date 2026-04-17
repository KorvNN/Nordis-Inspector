from __future__ import annotations

import ipaddress
import socket
import unittest

from nordis_smb_inspector.core.targets import (
    ExpandedTarget,
    ResolutionFailure,
    TargetKind,
    TargetParseError,
    parse_targets,
)


class TargetParserTests(unittest.TestCase):
    def test_parses_mixed_comma_and_newline_input(self) -> None:
        plan = parse_targets("10.0.0.4, 10.0.1.0/30\nFILE01.NORDIS.LOCAL")

        self.assertEqual([spec.kind for spec in plan.specs], [
            TargetKind.IP,
            TargetKind.CIDR,
            TargetKind.HOSTNAME,
        ])
        self.assertEqual(plan.known_address_count, 3)
        self.assertEqual(plan.hostname_count, 1)
        self.assertEqual(plan.specs[2].value, "file01.nordis.local")

    def test_cidr_expands_usable_hosts_and_preserves_source(self) -> None:
        plan = parse_targets("192.0.2.0/30")

        rows = list(plan.iter_expanded())

        self.assertEqual(
            [row.address for row in rows if isinstance(row, ExpandedTarget)],
            [ipaddress.ip_address("192.0.2.1"), ipaddress.ip_address("192.0.2.2")],
        )
        self.assertTrue(all(row.source == "192.0.2.0/30" for row in rows))

    def test_hostname_returns_every_unique_resolved_address(self) -> None:
        plan = parse_targets("files.nordis.local")

        rows = list(
            plan.iter_expanded(
                resolver=lambda _hostname: ["10.0.0.10", "10.0.0.10", "10.0.0.11"]
            )
        )

        self.assertEqual([str(row.address) for row in rows], ["10.0.0.10", "10.0.0.11"])
        self.assertTrue(all(row.source_hostname == "files.nordis.local" for row in rows))

    def test_resolution_error_is_a_visible_row(self) -> None:
        plan = parse_targets("missing.nordis.local")

        def fail(_hostname: str) -> list[str]:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        rows = list(plan.iter_expanded(resolver=fail))

        self.assertEqual(len(rows), 1)
        self.assertIsInstance(rows[0], ResolutionFailure)
        self.assertEqual(rows[0].error_code, "DNS_RESOLUTION_FAILED")

    def test_invalid_items_are_reported_together(self) -> None:
        with self.assertRaises(TargetParseError) as context:
            parse_targets("10.0.0.999, broken_name!, 10.0.0.0/99")

        self.assertEqual(len(context.exception.errors), 3)

    def test_scan_targets_deduplicate_overlapping_sources(self) -> None:
        plan = parse_targets("10.0.0.1, 10.0.0.0/30, files.nordis.local")

        preview = list(plan.iter_expanded(resolver=lambda _hostname: ["10.0.0.1"]))
        scheduled = list(plan.iter_scan_targets(resolver=lambda _hostname: ["10.0.0.1"]))

        self.assertEqual([str(row.address) for row in preview], [
            "10.0.0.1",
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.1",
        ])
        self.assertEqual([str(row.address) for row in scheduled], ["10.0.0.1", "10.0.0.2"])

    def test_point_to_point_and_single_host_network_counts_match_expansion(self) -> None:
        for expression in ("192.0.2.0/31", "192.0.2.1/32", "2001:db8::/127", "2001:db8::1/128"):
            with self.subTest(expression=expression):
                plan = parse_targets(expression)
                self.assertEqual(plan.known_address_count, len(list(plan.iter_expanded())))


if __name__ == "__main__":
    unittest.main()
