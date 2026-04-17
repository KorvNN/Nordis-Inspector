"""Parsing and streaming expansion for mixed IP, CIDR, and hostname targets."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver: TypeAlias = Callable[[str], Sequence[str | IPAddress]]

_SPLIT_TARGETS = re.compile(r"[\n,]+")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_LIKE = re.compile(r"^[0-9.]+$")


class TargetKind(StrEnum):
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"


@dataclass(frozen=True, slots=True)
class TargetInputError:
    value: str
    reason: str


class TargetParseError(ValueError):
    """Raised with every invalid item rather than failing on only the first."""

    def __init__(self, errors: Sequence[TargetInputError]) -> None:
        self.errors = tuple(errors)
        detail = "; ".join(f"{error.value!r}: {error.reason}" for error in self.errors)
        super().__init__(f"Invalid target input: {detail}")


@dataclass(frozen=True, slots=True)
class TargetSpec:
    source: str
    kind: TargetKind
    value: IPAddress | IPNetwork | str


@dataclass(frozen=True, slots=True)
class ExpandedTarget:
    """One address row shown in the expanded-target view."""

    address: IPAddress
    source: str
    source_kind: TargetKind
    source_hostname: str | None = None


@dataclass(frozen=True, slots=True)
class ResolutionFailure:
    hostname: str
    source: str
    error_code: str
    message: str


ExpansionEvent: TypeAlias = ExpandedTarget | ResolutionFailure


@dataclass(frozen=True, slots=True)
class TargetPlan:
    specs: tuple[TargetSpec, ...]

    @property
    def known_address_count(self) -> int:
        """Count IP/CIDR rows without resolving hostnames or expanding them."""

        total = 0
        for spec in self.specs:
            if spec.kind is TargetKind.IP:
                total += 1
            elif spec.kind is TargetKind.CIDR:
                total += _network_host_count(spec.value)
        return total

    @property
    def hostname_count(self) -> int:
        return sum(spec.kind is TargetKind.HOSTNAME for spec in self.specs)

    def iter_expanded(self, resolver: Resolver | None = None) -> Iterator[ExpansionEvent]:
        """Expand lazily so large CIDRs do not need an intermediate address list.

        Duplicate source rows are deliberately preserved for the UI.  The scan
        scheduler can deduplicate the resulting :attr:`ExpandedTarget.address`
        values while retaining the source-to-address mapping.
        """

        resolve = resolver or system_resolver
        for spec in self.specs:
            if spec.kind is TargetKind.IP:
                yield ExpandedTarget(spec.value, spec.source, spec.kind)
                continue

            if spec.kind is TargetKind.CIDR:
                network = spec.value
                for address in network.hosts():
                    yield ExpandedTarget(address, spec.source, spec.kind)
                continue

            hostname = str(spec.value)
            try:
                addresses = _unique_addresses(resolve(hostname))
            except (OSError, TimeoutError, ValueError) as exc:
                yield ResolutionFailure(
                    hostname=hostname,
                    source=spec.source,
                    error_code=_resolution_error_code(exc),
                    message=str(exc) or exc.__class__.__name__,
                )
                continue

            if not addresses:
                yield ResolutionFailure(
                    hostname=hostname,
                    source=spec.source,
                    error_code="DNS_NO_ADDRESSES",
                    message="Hostname resolved without an IP address.",
                )
                continue

            for address in addresses:
                yield ExpandedTarget(
                    address=address,
                    source=spec.source,
                    source_kind=spec.kind,
                    source_hostname=hostname,
                )

    def iter_scan_targets(self, resolver: Resolver | None = None) -> Iterator[ExpansionEvent]:
        """Yield each resolved address once while keeping DNS failures visible.

        ``iter_expanded`` remains the source-to-address mapping for the preview
        table. The scheduler uses this iterator so overlapping literals, CIDRs,
        and hostnames never cause duplicate SMB authentication attempts.
        """

        seen: set[IPAddress] = set()
        for event in self.iter_expanded(resolver):
            if isinstance(event, ResolutionFailure):
                yield event
                continue
            if event.address in seen:
                continue
            seen.add(event.address)
            yield event


def parse_targets(expression: str) -> TargetPlan:
    """Parse a comma/newline-separated mixture of IP, CIDR, and hostnames."""

    if not expression or not expression.strip():
        raise TargetParseError((TargetInputError("", "At least one target is required."),))

    raw_items = [item.strip() for item in _SPLIT_TARGETS.split(expression) if item.strip()]
    specs: list[TargetSpec] = []
    errors: list[TargetInputError] = []

    for raw in raw_items:
        try:
            specs.append(_parse_one(raw))
        except ValueError as exc:
            errors.append(TargetInputError(raw, str(exc)))

    if errors:
        raise TargetParseError(errors)
    if not specs:
        raise TargetParseError((TargetInputError("", "At least one target is required."),))
    return TargetPlan(tuple(specs))


def system_resolver(hostname: str) -> Sequence[IPAddress]:
    """Resolve every IPv4/IPv6 address returned for an SMB TCP connection."""

    records = socket.getaddrinfo(hostname, 445, type=socket.SOCK_STREAM)
    return tuple(ipaddress.ip_address(record[4][0]) for record in records)


def _parse_one(raw: str) -> TargetSpec:
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR network.") from exc
        return TargetSpec(source=raw, kind=TargetKind.CIDR, value=network)

    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        # A mistyped IPv4 address must not silently become a DNS hostname.
        if _IPV4_LIKE.fullmatch(raw):
            raise ValueError("Invalid IP address.")
        hostname = _normalize_hostname(raw)
        return TargetSpec(source=raw, kind=TargetKind.HOSTNAME, value=hostname)
    return TargetSpec(source=raw, kind=TargetKind.IP, value=address)


def _normalize_hostname(raw: str) -> str:
    candidate = raw.rstrip(".")
    if not candidate:
        raise ValueError("Hostname is empty.")
    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Hostname cannot be encoded as IDNA.") from exc
    if len(ascii_name) > 253:
        raise ValueError("Hostname exceeds 253 characters.")
    labels = ascii_name.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Hostname contains an invalid label.")
    return ascii_name.lower()


def _network_host_count(network: IPNetwork) -> int:
    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen < 31:
        return max(0, network.num_addresses - 2)
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen < 127:
        return max(0, network.num_addresses - 1)
    return network.num_addresses


def _unique_addresses(values: Sequence[str | IPAddress]) -> tuple[IPAddress, ...]:
    result: list[IPAddress] = []
    seen: set[IPAddress] = set()
    for value in values:
        address = (
            value
            if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address)
            else ipaddress.ip_address(value)
        )
        if address not in seen:
            seen.add(address)
            result.append(address)
    return tuple(result)


def _resolution_error_code(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "DNS_RESOLUTION_FAILED"
    if isinstance(exc, TimeoutError):
        return "DNS_TIMEOUT"
    return "DNS_ERROR"
