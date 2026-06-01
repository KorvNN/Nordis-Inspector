# Nordis SMB Inspector

Nordis SMB Inspector is a local, read-only SMB 2/3 assessment tool for finding
exposed files, weak access boundaries, and credential material across authorized
Windows and Samba environments.

It combines protocol-aware SMB inspection with bounded content scanning. Results
arrive live in a local web console so operators can see what responded, what was
accessible, what was readable, and which lines require review.

## What it does

- Scans IPs, CIDR ranges, and hostnames on SMB/TCP 445
- Supports password, NT hash, and Kerberos CCache authentication
- Records Kerberos, NTLM, and fallback authentication outcomes
- Reports SMB dialect, signing, encryption, share access, and file readability
- Enumerates shares through SRVSVC without guessing hidden share names
- Builds separate share, directory, and file inventory views
- Scans readable text and bounded document/archive content without copying files locally
- Uses an editable literal wordlist plus built-in credential-pattern rules
- Recognizes common NTLM/Kerberos exports and CCache, keytab, and KIRBI files
- Sends supported offline password-hash findings to locally installed Hashcat or
  John the Ripper with an operator-selected TXT wordlist
- Streams progress, target states, inventory entries, and findings to the UI
- Keeps local scan history with safe credential metadata and JSON export

Nordis is intentionally read-only. It does not modify remote files, test write
permissions, or expose a non-loopback web bind.

Hash Tools is an explicit local post-processing step. Findings and wordlists are
never sent to an external service; large lists are streamed to private temporary
storage and discarded on the next scan or when the process exits.

## Quick start

```bash
./setup.sh
./run.sh
```

Open <http://127.0.0.1:8765>. To use another local port:

```bash
./run.sh --port 9000
```

Use Nordis only against systems and data you are authorized to assess.

## Detection model

The scanner currently supports:

- Literal, Unicode case-insensitive wordlist matching
- Built-in credential-pattern rules with rule IDs, categories, and confidence
- Optional built-in pattern detection
- Additional terms entered per scan, including comma- or newline-separated values

User-supplied regular expressions, user-configurable category rule packs, multiple
selectable wordlists, case-sensitive matching, and whole-word matching are not
currently exposed by the web panel. The matching engine has some lower-level
support for boundary and case options, but those options are not part of the web
scan contract yet.

## Documentation

- [Detection model](docs/DETECTION.md)
- [Scope and behavior](docs/SCOPE.md)
- [SMB architecture](docs/TECH_SMB.md)
- [Web architecture](docs/TECH_WEB.md)
- [Isolated integration lab](docs/TEST_LAB.md)

## License

MIT License. See [LICENSE](LICENSE).
