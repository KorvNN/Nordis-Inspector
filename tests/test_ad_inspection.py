from __future__ import annotations

from collections.abc import Sequence

import pytest

from nordis_smb_inspector.ad.inspection import inspect_directory
from nordis_smb_inspector.ad.ldap_adapter import (
    AdInspectionError,
    DirectoryRecord,
    domain_to_base_dn,
    escape_filter,
)
from nordis_smb_inspector.ad.models import AdEvidenceState, AdFindingLane
from nordis_smb_inspector.core.credentials import AuthMode, Credential


class _Cancellation:
    def raise_if_requested(self) -> None:
        return None


class _FakeDirectory:
    authentication_method = "ntlm"
    bound_username = "KorvNN"

    def __init__(self, *, fail_filter_fragment: str | None = None) -> None:
        self.closed = False
        self.fail_filter_fragment = fail_filter_fragment

    def search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        search_base: str | None = None,
        base_object: bool = False,
    ) -> tuple[DirectoryRecord, ...]:
        del attributes, search_base, base_object
        if self.fail_filter_fragment and self.fail_filter_fragment in search_filter:
            raise AdInspectionError("LDAP_QUERY_FAILED", "LDAP sorgusu tamamlanamadı.")
        if "sAMAccountName=KorvNN" in search_filter:
            return (
                _record(
                    "CN=KorvNN,CN=Users,DC=efelab,DC=test",
                    sAMAccountName="KorvNN",
                    userPrincipalName="KorvNN@efelab.test",
                    primaryGroupID="513",
                    objectSid=_sid_bytes("S-1-5-21-1-2-3-1105"),
                ),
            )
        if "1.2.840.113556.1.4.1941" in search_filter:
            return (
                _record(
                    "CN=Smb-Public-Read,CN=Users,DC=efelab,DC=test",
                    sAMAccountName="Smb-Public-Read",
                ),
            )
        if "objectSid=S-1-5-21-1-2-3-513" in search_filter:
            return (
                _record(
                    "CN=Domain Users,CN=Users,DC=efelab,DC=test",
                    sAMAccountName="Domain Users",
                ),
            )
        if search_filter == "(objectCategory=computer)":
            return (
                _record(
                    "CN=WS01,CN=Computers,DC=efelab,DC=test",
                    sAMAccountName="WS01$",
                    dNSHostName="ws01.efelab.test",
                    operatingSystem="Windows 11",
                    userAccountControl="4096",
                    **{"msLAPS-Password": "SuperSecretMustNeverLeak"},
                ),
                _record(
                    "CN=WS02,CN=Computers,DC=efelab,DC=test",
                    sAMAccountName="WS02$",
                    dNSHostName="ws02.efelab.test",
                    userAccountControl="4096",
                    **{"msLAPS-EncryptedPassword": b"EncryptedBlob"},
                ),
            )
        if "msDS-GroupManagedServiceAccount" in search_filter:
            return (
                _record(
                    "CN=svc_web,CN=Managed Service Accounts,DC=efelab,DC=test",
                    sAMAccountName="svc_web$",
                    **{"msDS-ManagedPassword": b"SecretBinaryBlob"},
                ),
            )
        if "servicePrincipalName=*" in search_filter:
            return (
                _record(
                    "CN=svc_sql,CN=Users,DC=efelab,DC=test",
                    sAMAccountName="svc_sql",
                    servicePrincipalName=("MSSQLSvc/sql01:1433",),
                    adminCount="1",
                ),
            )
        if "4194304" in search_filter:
            return (_record("CN=legacy,CN=Users,DC=efelab,DC=test", sAMAccountName="legacy"),)
        if "524288" in search_filter:
            return (
                _record(
                    "CN=APP01,CN=Computers,DC=efelab,DC=test",
                    sAMAccountName="APP01$",
                    userAccountControl=str(0x80000),
                ),
            )
        if search_filter == "(objectClass=domainDNS)":
            return (
                _record(
                    "DC=efelab,DC=test",
                    minPwdLength="8",
                    lockoutThreshold="0",
                    **{"ms-DS-MachineAccountQuota": "10"},
                ),
            )
        raise AssertionError(f"Unexpected filter: {search_filter}")

    def close(self) -> None:
        self.closed = True


def _record(distinguished_name: str, **attributes: object) -> DirectoryRecord:
    encoded: dict[str, tuple[bytes, ...]] = {}
    for name, raw in attributes.items():
        values = raw if isinstance(raw, tuple) else (raw,)
        encoded[name] = tuple(
            value if isinstance(value, bytes) else str(value).encode() for value in values
        )
    return DirectoryRecord(distinguished_name, encoded)


def _sid_bytes(canonical: str) -> bytes:
    from impacket.ldap.ldaptypes import LDAP_SID

    sid = LDAP_SID()
    sid.fromCanonical(canonical)
    return sid.getData()


def _credential() -> Credential:
    return Credential.from_password(
        username="KorvNN",
        password="Admin123.Aa",
        domain="efelab.test",
        auth_mode=AuthMode.NTLM_ONLY,
    )


def test_principal_centric_inspection_distinguishes_verified_and_inferred_results() -> None:
    directory = _FakeDirectory()

    report = inspect_directory(
        controller="DC01",
        domain="efelab.test",
        credential=_credential(),
        cancellation=_Cancellation(),
        client_factory=lambda *_args: directory,
    )

    assert directory.closed
    assert report.identity.principal == "KorvNN@efelab.test"
    assert report.identity.groups == ("Domain Users", "Smb-Public-Read")
    assert report.computers[0].hostname == "ws01.efelab.test"
    by_check = {finding.check_id: finding for finding in report.findings}
    assert by_check["laps_readable"].evidence_state is AdEvidenceState.VERIFIED
    assert by_check["gmsa_password_readable"].evidence_state is AdEvidenceState.VERIFIED
    assert by_check["kerberoast_candidate"].evidence_state is AdEvidenceState.INFERRED
    assert by_check["machine_account_quota"].lane is AdFindingLane.CAPABILITY
    assert by_check["delegation_configuration"].lane is AdFindingLane.ENVIRONMENT
    assert [
        finding.subject for finding in report.findings if finding.check_id == "laps_readable"
    ] == ["ws01.efelab.test"]

    rendered = repr(report) + repr(report.findings) + str(
        [finding.public_payload() for finding in report.findings]
    )
    assert "SuperSecretMustNeverLeak" not in rendered
    assert "SecretBinaryBlob" not in rendered
    assert "Admin123.Aa" not in rendered


def test_failed_optional_query_is_reported_as_not_checked() -> None:
    directory = _FakeDirectory(fail_filter_fragment="servicePrincipalName=*")

    report = inspect_directory(
        controller="DC01",
        domain="efelab.test",
        credential=_credential(),
        cancellation=_Cancellation(),
        client_factory=lambda *_args: directory,
    )

    coverage = {item.check_id: item for item in report.coverage}
    assert coverage["kerberoast"].state.value == "not_checked"
    assert not any(finding.check_id == "kerberoast_candidate" for finding in report.findings)


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [("a*b", r"a\2ab"), ("(x)", r"\28x\29"), ("a\\b", r"a\5cb")],
)
def test_ldap_filter_values_are_escaped(raw: str, escaped: str) -> None:
    assert escape_filter(raw) == escaped


def test_domain_to_base_dn_requires_fqdn() -> None:
    assert domain_to_base_dn("efelab.test") == "DC=efelab,DC=test"
    with pytest.raises(AdInspectionError):
        domain_to_base_dn("EFELAB")
    with pytest.raises(AdInspectionError):
        domain_to_base_dn("efelab.test.")
