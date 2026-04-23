"""Safe Kerberos service-hostname selection for expanded scan targets."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence

from .targets import ExpandedTarget, IPAddress, TargetKind, parse_targets, system_resolver

type ReverseResolver = Callable[[IPAddress], str]
type ForwardResolver = Callable[[str], Sequence[str | IPAddress]]


def system_reverse_resolver(address: IPAddress) -> str:
    """Return the primary PTR hostname reported by the system resolver."""

    return socket.gethostbyaddr(str(address))[0]


def resolve_kerberos_hostname(
    target: ExpandedTarget,
    *,
    reverse_resolver: ReverseResolver = system_reverse_resolver,
    forward_resolver: ForwardResolver = system_resolver,
) -> str | None:
    """Return a verified hostname suitable for a ``cifs/host`` SPN.

    Hostname inputs retain their normalized source name.  Literal IP and CIDR
    targets use forward-confirmed reverse DNS: a PTR name is accepted only when
    resolving that name includes the exact address being scanned.
    """

    if target.source_kind is TargetKind.HOSTNAME:
        return _canonical_hostname(target.source_hostname)

    try:
        ptr_hostname = reverse_resolver(target.address)
        hostname = _canonical_hostname(ptr_hostname)
        if hostname is None:
            return None
        addresses = _normalized_addresses(forward_resolver(hostname))
    except (OSError, TimeoutError, TypeError, ValueError, UnicodeError):
        return None
    return hostname if target.address in addresses else None


def _canonical_hostname(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        plan = parse_targets(value)
    except ValueError:
        return None
    if len(plan.specs) != 1 or plan.specs[0].kind is not TargetKind.HOSTNAME:
        return None
    return str(plan.specs[0].value)


def _normalized_addresses(values: Sequence[str | IPAddress]) -> frozenset[IPAddress]:
    return frozenset(
        value if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address)
        else ipaddress.ip_address(value)
        for value in values
    )
