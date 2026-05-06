# Scope and Behavior

Nordis SMB Inspector is a local, read-only SMB 2/3 auditing tool for authorized
security assessments. It discovers shares through SRVSVC, inventories accessible
content, and reports sensitive-data matches through a loopback-only web interface.

## Supported workflow

1. Accept an IPv4/IPv6 address, CIDR, or hostname.
2. Connect to TCP 445 and negotiate SMB 2/3.
3. Authenticate with a password, NT hash, or Kerberos ccache.
4. Enumerate shares through the authenticated SRVSVC session.
5. Probe each discovered disk share with read-only access.
6. Walk accessible directories and stream supported files through the detectors.
7. Keep inventory and findings in process memory and publish live progress.

The scanner never guesses common share names. A denied, unavailable, or failed
SRVSVC request is reported explicitly and ends share discovery for that target.

## Current capabilities

- Password, NT-hash, Kerberos, and automatic Kerberos-to-NTLM authentication
- SMB dialect, signing, encryption, and DFS-capability reporting
- Bounded target concurrency and cooperative cancellation
- Directory and file inventory with stable access/error statuses
- Streaming text scans without downloading whole remote files
- Wordlist and built-in credential-pattern detection
- PDF, Office Open XML, OpenDocument, ZIP, TAR, and GZIP inspection
- In-memory pagination for inventory and findings
- Packaged default wordlist with an editable source or per-user copy

The web application currently uses 32 target workers and a default directory depth
limit of 32. These are implementation constants, not selectable load profiles.

## Result semantics

`COMPLETED` means every discovered, supported object that was attempted completed
without an access or read error. `PARTIAL_ACCESS` means useful inventory or findings
were collected, but at least one discovered share, directory, file, archive member,
or document could not be inspected completely.

Partial access is not the same as “visible but unreadable.” The scanner still shows
the metadata it was able to enumerate, records an access status such as
`file_read_denied`, and marks the target partial. It does not show file contents when
the file could not be read.

Connectivity, negotiation, authentication, share enumeration, directory listing,
and file reading each have separate statuses. This prevents an earlier success from
masking a later authorization failure.

## Safety boundaries

- The server binds only to `127.0.0.1`.
- SMB handles request read-only access; remote writes and deletes are not part of the
  workflow.
- Reparse points and symbolic links are not followed.
- Remote files are read in bounded ranges and are not persisted locally.
- Scan state is memory-only and is discarded when the process exits.
- Credentials and target/path context are redacted from routine object
  representations.
- One scan may run at a time.
- Inventory and finding collections have finite capacities; reaching a capacity is a
  visible partial result rather than silent eviction.

Read-only design reduces risk but does not make scanning impact-free. Directory
enumeration and file reads still create network, server, and storage load. Use narrow
targets first and obtain authorization before scanning.

## Out of scope

- SMB1 scanning
- Share-name guessing or brute force
- Credential discovery, password attacks, exploitation, or persistence
- Remote file modification, quarantine, or remediation
- Following DFS referrals to additional servers
- Recursive inspection of nested archives
- Distributed workers, scheduled scans, multi-user access, or durable result storage
- A guarantee that every binary or proprietary format can be inspected

## Known limitations

- The automated test suite uses fakes and does not replace validation against real
  Windows/Samba servers. See [TEST_LAB.md](TEST_LAB.md).
- DFS capability is recorded, but referrals are not followed.
- SMB1-only classification exists in the result model, but there is no separate SMB1
  dialect probe.
- No project license has been selected yet.

Detection details are documented in [DETECTION.md](DETECTION.md). SMB and web
implementation notes are in [TECH_SMB.md](TECH_SMB.md) and
[TECH_WEB.md](TECH_WEB.md).
