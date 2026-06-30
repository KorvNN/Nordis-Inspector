"""Fail-closed DC hostname discovery for principal-scoped Kerberos access."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from contextlib import suppress
from threading import RLock
from typing import Any

from .directory import url_host, valid_dns_name

_DEFAULT_TIMEOUT_SECONDS = 2.0
_SOCKET_DEFAULT_TIMEOUT_LOCK = RLock()

type RootDseHostnameReader = Callable[[str, float], str | None]
type DnsAddressReader = Callable[[str, str, float], Sequence[str]]


def discover_directory_hostname(
    controller: str,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    root_dse_reader: RootDseHostnameReader | None = None,
    dns_address_reader: DnsAddressReader | None = None,
) -> str | None:
    """Return a DC FQDN only when the same host's DNS confirms its address.

    Discovery is reserved for an address already identified as a DC candidate by
    readable SYSVOL or NETLOGON shares.  RootDSE supplies a candidate name without
    credentials; that untrusted name is accepted only when DNS on the same address
    maps it back to the exact scanned controller.
    """

    if not isinstance(controller, str) or not isinstance(timeout_seconds, int | float):
        return None
    if timeout_seconds <= 0:
        return None
    try:
        address = ipaddress.ip_address(controller.strip())
    except ValueError:
        return None

    read_root_dse = root_dse_reader or _read_root_dse_hostname
    read_dns = dns_address_reader or _read_dns_addresses
    try:
        raw_hostname = read_root_dse(str(address), float(timeout_seconds))
        if not isinstance(raw_hostname, str):
            return None
        hostname = raw_hostname.strip().rstrip(".").casefold()
        if not valid_dns_name(hostname, require_fqdn=True):
            return None
        resolved = frozenset(
            ipaddress.ip_address(value)
            for value in read_dns(hostname, str(address), float(timeout_seconds))
        )
    except Exception:
        return None
    return hostname if address in resolved else None


def _read_root_dse_hostname(controller: str, timeout_seconds: float) -> str | None:
    from impacket.ldap.ldap import LDAPConnection
    from impacket.ldap.ldapasn1 import Scope, SearchResultEntry

    connection: Any | None = None
    with _SOCKET_DEFAULT_TIMEOUT_LOCK:
        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout_seconds)
        try:
            connection = LDAPConnection(
                f"ldap://{url_host(controller)}",
                "",
                dstIp=controller,
                signing=False,
            )
            response = connection.search(
                searchBase="",
                scope=Scope("baseObject"),
                sizeLimit=1,
                timeLimit=max(1, int(timeout_seconds)),
                searchFilter="(objectClass=*)",
                attributes=("dnsHostName",),
            )
        finally:
            socket.setdefaulttimeout(previous_timeout)
            if connection is not None:
                with suppress(Exception):
                    connection.close()

    for item in response:
        if not isinstance(item, SearchResultEntry):
            continue
        for attribute in item["attributes"]:
            if str(attribute["type"]).casefold() != "dnshostname":
                continue
            for value in attribute["vals"]:
                with suppress(UnicodeError):
                    return value.asOctets().decode("utf-8")
    return None


def _read_dns_addresses(
    hostname: str,
    controller: str,
    timeout_seconds: float,
) -> tuple[str, ...]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [controller]
    resolver.timeout = timeout_seconds
    resolver.lifetime = timeout_seconds
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(
                hostname,
                record_type,
                search=False,
                lifetime=timeout_seconds,
            )
        except (
            dns.exception.Timeout,
            dns.resolver.LifetimeTimeout,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.NXDOMAIN,
        ):
            continue
        addresses.extend(str(answer) for answer in answers)
    return tuple(addresses)
