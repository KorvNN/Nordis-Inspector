# Nordis SMB Inspector

Nordis SMB Inspector is a local, read-only SMB 2/3 auditing tool. It discovers
shares, inventories accessible files, scans supported content for sensitive
data, and streams results to a web interface.

Use it only on systems you are authorized to assess.

## Features

- IP address, CIDR, and hostname targets
- Password, NT hash, and Kerberos ccache authentication
- Kerberos-to-NTLM fallback with explicit authentication history
- SMB dialect, signing, and encryption reporting
- SRVSVC share discovery with explicit enumeration errors
- Read-only share, directory, and file inventory
- Streaming content scans without local file copies
- Built-in wordlist and credential-pattern detection
- PDF, Office, OpenDocument, ZIP, TAR, and GZIP inspection
- Live target, inventory, finding, and progress views

Share names are obtained only through SRVSVC. If enumeration fails, the target
reports a `SHARE_ENUM_*` status and no guessed share names are attempted.
Partial file or directory access is reported as `PARTIAL_ACCESS`.

## Quick start

```bash
./setup.sh
./run.sh
```

The interface is available at <http://127.0.0.1:8765>. To use another loopback
port:

```bash
./run.sh --port 9000
```

The server does not expose a non-loopback bind option.

## Development

```bash
.venv/bin/pip install -e '.[dev]'
./scripts/check.sh
```

Source checkouts use
[`wordlists/content/default-sensitive.txt`](wordlists/content/default-sensitive.txt).
Wheel installations create an editable copy under the user's XDG configuration
directory on first use.

## Documentation

- [Scope and behavior](docs/SCOPE.md)
- [Detection model](docs/DETECTION.md)
- [SMB architecture](docs/TECH_SMB.md)
- [Web architecture](docs/TECH_WEB.md)
- [Isolated integration lab](docs/TEST_LAB.md)
