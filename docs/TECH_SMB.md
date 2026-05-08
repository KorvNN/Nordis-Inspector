# SMB Architecture

The SMB subsystem is organized around framework-neutral contracts. The web layer
supplies targets, credentials, immutable scan options, cancellation, and event
callbacks; adapters return normalized models rather than third-party SMB objects.

## Runtime components

- `smbprotocol` handles SMB 2/3 connection, negotiation, authentication, tree
  connections, directory enumeration, and bounded file reads.
- Impacket opens a separate authenticated connection for SRVSVC share enumeration.
- The inspection orchestrator combines discovery, access probing, tree walking,
  document extraction, detection, and status normalization.
- The access pipeline runs independent targets with bounded thread concurrency.

The separate SRVSVC connection is intentional. Share names come only from the
server's authenticated enumeration result; the scanner does not inject a list of
common names when enumeration fails.

## Target sequence

For each expanded address, the scanner performs:

1. TCP connection and SMB 2/3 negotiation on port 445
2. Authentication
3. SRVSVC share enumeration
4. Read-only probe of each discovered disk share
5. Bounded directory walk
6. Streaming inspection of supported, readable files
7. Handle cleanup and one terminal target outcome

DNS failures and connection errors are reported before authentication. Later stages
do not overwrite the reason an earlier stage failed.

## Authentication

Supported credentials are passwords, NT hashes, and uploaded Kerberos ccache data.
Authentication modes are:

- `auto`: try Kerberos first and use one fresh NTLM connection for an eligible
  fallback when a password is available
- `kerberos_only`: do not attempt NTLM
- `ntlm_only`: do not attempt Kerberos

The result retains the mechanism attempts and a normalized fallback reason. NT hashes
are NTLM-only. Ccache credentials are Kerberos-only.

Uploaded ccache bytes remain in memory. For the `smbprotocol` GSSAPI path on Linux,
the bytes are exposed through `memfd_create` and `/proc/self/fd`; there is no
temporary-file fallback. Impacket parses the same in-memory bytes for SRVSVC.

Kerberos requires a hostname that can form a valid `cifs/<hostname>` service
principal. Scanning an IP address without resolvable hostname context can therefore
succeed with NTLM but fail or fall back from Kerberos.

## Negotiation policy

The default connection request permits SMB 2/3 only, requires signing and secure
negotiate, and does not require encryption. Negotiated dialect, signing state,
encryption state, and DFS capability are reported when available.

`smb1_only_unsupported` exists in the status model for a positively classified
legacy target, but the current connector does not issue a separate SMB1 probe after
SMB 2/3 negotiation fails. Do not treat every negotiation failure as proof of SMB1.

## Share discovery

SRVSVC is the only source of share names. The outcomes are distinct:

- Enumeration completed, including a valid empty list
- Enumeration was denied
- The SRVSVC service or transport was unavailable
- Enumeration failed for another normalized reason

An empty successful list means the server reported no shares. A discovery error
means the scanner does not know which shares exist. No guessed fallback is attempted
in either case.

## Read-only access

The adapter contracts expose connect, enumerate, open-for-read, and bounded-range
operations only. There are no create, write, rename, delete, permission-change, or
remote-materialization methods.

Directory walks do not follow reparse points or symbolic links. File content is
read in 64 KiB ranges through a validated random-access wrapper. Documents and
archives may seek within that wrapper, but the remote object is not copied to disk.

Read-only access does not guarantee zero operational impact. Authentication,
enumeration, metadata queries, and reads still consume server resources.

## Status and partial access

The model separates network, negotiation, authentication, authorization, share
enumeration, tree walk, and file-read stages. Common terminal outcomes include
timeouts, connection refusal, authentication failure, share-enumeration errors,
access denial, partial access, completion, and cancellation.

`partial_access` means the target produced useful results but at least one attempted
object could not be fully inspected. For example, the scanner may enumerate a file
name and size but receive access denied when opening it. The inventory entry remains
visible with `file_read_denied`; content is neither read nor shown.

## Cancellation and cleanup

Cancellation is cooperative and checked between network, enumeration, walk, read,
and extraction operations. Every opened reader, tree connection, session, and SMB
connection is closed on success, failure, and cancellation. Cleanup errors do not
replace the primary target outcome.

## Current limitations

- DFS capability is recorded, but referrals are not followed.
- There is no SMB1 data path or active SMB1-only probe.
- SRVSVC discovery is not supplemented with common-share guesses.
- Unit tests validate adapters with fakes. The manual loopback smoke test exercises
  SMB2, NTLM, SRVSVC, and content reads against an embedded server; real
  Windows/Samba policy behavior still requires the isolated lab in
  [TEST_LAB.md](TEST_LAB.md).
- Server-specific throttling and selectable load profiles are not implemented.
