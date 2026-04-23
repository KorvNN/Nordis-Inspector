from __future__ import annotations

import ipaddress
import socket
import unittest

from nordis_smb_inspector.core.kerberos import resolve_kerberos_hostname
from nordis_smb_inspector.core.targets import ExpandedTarget, TargetKind


def _target(
    address: str = "10.20.30.40",
    *,
    source_kind: TargetKind = TargetKind.IP,
    source_hostname: str | None = None,
) -> ExpandedTarget:
    return ExpandedTarget(
        address=ipaddress.ip_address(address),
        source=address,
        source_kind=source_kind,
        source_hostname=source_hostname,
    )


class KerberosHostnameTests(unittest.TestCase):
    def test_hostname_input_uses_canonical_source_without_reverse_lookup(self) -> None:
        target = _target(
            source_kind=TargetKind.HOSTNAME,
            source_hostname="Files01.Nordis.Local.",
        )

        result = resolve_kerberos_hostname(
            target,
            reverse_resolver=lambda _address: self.fail("unexpected reverse lookup"),
            forward_resolver=lambda _hostname: self.fail("unexpected forward lookup"),
        )

        self.assertEqual(result, "files01.nordis.local")

    def test_ip_ptr_is_accepted_only_when_forward_lookup_contains_same_ip(self) -> None:
        reverse_calls: list[str] = []
        forward_calls: list[str] = []

        def reverse(address) -> str:
            reverse_calls.append(str(address))
            return "Files01.Nordis.Local."

        def forward(hostname: str) -> list[str]:
            forward_calls.append(hostname)
            return ["10.20.30.41", "10.20.30.40"]

        result = resolve_kerberos_hostname(
            _target(),
            reverse_resolver=reverse,
            forward_resolver=forward,
        )

        self.assertEqual(result, "files01.nordis.local")
        self.assertEqual(reverse_calls, ["10.20.30.40"])
        self.assertEqual(forward_calls, ["files01.nordis.local"])

    def test_cidr_address_uses_same_forward_confirmed_reverse_dns_rule(self) -> None:
        result = resolve_kerberos_hostname(
            _target(source_kind=TargetKind.CIDR),
            reverse_resolver=lambda _address: "files01.nordis.local",
            forward_resolver=lambda _hostname: [ipaddress.ip_address("10.20.30.40")],
        )

        self.assertEqual(result, "files01.nordis.local")

    def test_ptr_name_is_rejected_when_it_resolves_to_a_different_ip(self) -> None:
        result = resolve_kerberos_hostname(
            _target(),
            reverse_resolver=lambda _address: "other.nordis.local",
            forward_resolver=lambda _hostname: ["10.20.30.41"],
        )

        self.assertIsNone(result)

    def test_invalid_ptr_or_dns_failure_is_fail_closed(self) -> None:
        cases = (
            (
                lambda _address: "10.20.30.40",
                lambda _hostname: ["10.20.30.40"],
            ),
            (
                lambda _address: "files01.nordis.local",
                lambda _hostname: ["not-an-ip"],
            ),
        )
        for reverse, forward in cases:
            with self.subTest(reverse=reverse, forward=forward):
                self.assertIsNone(
                    resolve_kerberos_hostname(
                        _target(),
                        reverse_resolver=reverse,
                        forward_resolver=forward,
                    )
                )

        def unavailable(_address) -> str:
            raise socket.herror("no PTR")

        self.assertIsNone(
            resolve_kerberos_hostname(
                _target(),
                reverse_resolver=unavailable,
                forward_resolver=lambda _hostname: ["10.20.30.40"],
            )
        )

    def test_ipv6_requires_an_exact_forward_match(self) -> None:
        result = resolve_kerberos_hostname(
            _target("2001:db8::25"),
            reverse_resolver=lambda _address: "files-v6.nordis.local",
            forward_resolver=lambda _hostname: ["2001:db8::25"],
        )

        self.assertEqual(result, "files-v6.nordis.local")


if __name__ == "__main__":
    unittest.main()
