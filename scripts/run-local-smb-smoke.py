#!/usr/bin/env python3
"""Run a real loopback SMB2/NTLM/SRVSVC/content smoke test without root."""

from __future__ import annotations

import socket
import tempfile
import threading
from pathlib import Path

from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.smbserver import SimpleSMBServer

from nordis_smb_inspector.core.credentials import AuthMode, Credential
from nordis_smb_inspector.smb.cancellation import NEVER_CANCELLED
from nordis_smb_inspector.smb.contracts import ConnectRequest
from nordis_smb_inspector.smb.impacket_discovery import ImpacketShareDiscoverer
from nordis_smb_inspector.smb.inspection import ContentFinding, inspect_target
from nordis_smb_inspector.smb.models import InventoryEntry, TargetStatus
from nordis_smb_inspector.smb.smbprotocol_adapter import SmbProtocolConnector
from nordis_smb_inspector.smb.smbprotocol_auth_adapter import SmbProtocolAuthenticator
from nordis_smb_inspector.smb.smbprotocol_files import SmbProtocolFileAdapter

_HOST = "127.0.0.1"
_USER = "nordis-smoke"
_PASSWORD = "NordisSmokePassword123!"
_CANARY = "NORDIS_LOCAL_SMB_CANARY"


def main() -> int:
    inventory: list[InventoryEntry] = []
    findings: list[ContentFinding] = []

    with tempfile.TemporaryDirectory(prefix="nordis-smb-smoke-") as temporary:
        share_root = Path(temporary) / "Data"
        share_root.mkdir()
        (share_root / "canary.txt").write_text(
            f"password = {_CANARY}\n",
            encoding="utf-8",
        )

        server = _server(share_root)
        port = int(server.getServer().socket.getsockname()[1])
        server_thread = threading.Thread(
            target=server.start,
            name="nordis-local-smb-smoke",
            daemon=True,
        )
        server_thread.start()
        try:
            _wait_until_listening(port)
            result = inspect_target(
                target=_HOST,
                connect_request=ConnectRequest(
                    target=_HOST,
                    port=port,
                    timeout_seconds=5,
                    require_signing=False,
                    require_secure_negotiate=False,
                ),
                credential=Credential.from_password(
                    username=_USER,
                    password=_PASSWORD,
                    domain=None,
                    auth_mode=AuthMode.NTLM_ONLY,
                ),
                kerberos_hostname=None,
                search_terms=(_CANARY,),
                max_depth=8,
                connector=SmbProtocolConnector(),
                authenticator=SmbProtocolAuthenticator(),
                file_adapter=SmbProtocolFileAdapter(require_secure_negotiate=False),
                cancellation=NEVER_CANCELLED,
                share_discoverer=ImpacketShareDiscoverer(port=port),
                detect_patterns=False,
                on_inventory=inventory.append,
                on_finding=findings.append,
            )
        finally:
            server.getServer().shutdown()
            server.stop()
            server_thread.join(timeout=5)

    if result.status is not TargetStatus.COMPLETED:
        raise RuntimeError(f"Local SMB smoke ended with {result.status.value}.")
    if result.files_scanned != 1 or result.findings != 1:
        raise RuntimeError("Local SMB smoke did not scan the expected fixture.")
    if len(findings) != 1 or findings[0].term != _CANARY:
        raise RuntimeError("Local SMB smoke did not return the expected canary.")
    if not any(item.relative_path == "canary.txt" for item in inventory):
        raise RuntimeError("Local SMB smoke did not inventory the expected file.")

    print(
        "Local SMB smoke passed: "
        f"dialect={result.negotiation.dialect.value}, "
        f"shares={result.shares_probed}, files={result.files_scanned}, "
        f"findings={result.findings}"
    )
    return 0


def _server(share_root: Path) -> SimpleSMBServer:
    server = SimpleSMBServer(listenAddress=_HOST, listenPort=0)
    server.setSMB2Support(True)
    server.addCredential(
        _USER,
        0,
        compute_lmhash(_PASSWORD).hex(),
        compute_nthash(_PASSWORD).hex(),
    )
    server.addShare("Data", str(share_root), "Nordis local smoke", readOnly="yes")
    return server


def _wait_until_listening(port: int) -> None:
    for _attempt in range(50):
        try:
            with socket.create_connection((_HOST, port), timeout=0.1):
                return
        except OSError:
            threading.Event().wait(0.02)
    raise RuntimeError("Local SMB smoke server did not start.")


if __name__ == "__main__":
    raise SystemExit(main())
