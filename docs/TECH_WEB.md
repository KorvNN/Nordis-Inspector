# Web Architecture

Nordis SMB Inspector runs a single local Starlette application with a server-rendered
page, plain JavaScript, and Server-Sent Events (SSE). It is an operator interface,
not a multi-user service or remote API.

## Runtime

- Uvicorn binds to `127.0.0.1` only.
- Jinja renders the initial HTML page.
- Static CSS and JavaScript are served from package resources.
- One daemon worker thread coordinates each scan.
- Up to 32 targets are inspected concurrently.
- One SMB scan or one local Hash Tools job may be active at a time.
- State, credentials, inventory, findings, and events are process-memory only.

Closing the process discards server-side scan data. Completed scans can be retained
in the current browser's local storage and downloaded as JSON. There is no database,
access log, analytics hook, or background scheduler in the application.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/` | Render the operator interface |
| `POST` | `/scan` | Validate input and start a scan |
| `POST` | `/scan/cancel` | Request cooperative cancellation |
| `GET` | `/scan/snapshot` | Return current lifecycle, progress, and targets |
| `GET` | `/scan/events` | Stream replayable SSE updates |
| `GET` | `/inventory` | Return a paginated inventory page |
| `GET` | `/findings` | Return a paginated findings page |
| `GET` | `/hash-tools` | Return local-tool, job, and staged-wordlist state |
| `PUT` | `/hash-tools/wordlist` | Stream a TXT wordlist to private temporary storage |
| `POST` | `/hash-tools/jobs` | Start an allow-listed local recovery job |
| `POST` | `/hash-tools/jobs/cancel` | Stop the active local recovery job |
| `GET` | `/wordlists` | Read editable wordlist state |
| `PUT` | `/wordlists/content` | Save the content wordlist atomically |
| `GET` | `/static/{asset_name}` | Serve an allow-listed asset |

The endpoints are internal implementation details and are not versioned as a public
API.

## Session state

`ScanSessionManager` owns a generation token, lifecycle state, progress snapshot,
inventory, and findings. Worker updates must present the current token, so late
events from an old scan cannot mutate a new scan.

The default memory bounds are 250,000 inventory entries and 100,000 findings.
Inventory and findings default to 100 rows per page and reject page sizes over 1,000.
The SSE replay buffer retains 2,048 events. Reaching a result capacity ends the scan
with a visible partial result; records are not silently evicted.

## Event flow

The worker publishes small SSE notifications for snapshot, target, inventory, and
finding changes. Event IDs allow a reconnecting browser to request replay while the
event remains in the bounded buffer. The browser periodically reconciles with the
snapshot and paginated result endpoints, so SSE is a notification channel rather
than the authoritative store.

## Request security

The application is deliberately loopback-only and accepts the Host header
`127.0.0.1`. State-changing requests must include:

- The exact origin `http://127.0.0.1:<port>`
- A process-local CSRF nonce sent in `X-CSRF-Token`

Aliases such as `localhost` are rejected for state changes. JSON request bodies are
limited to 2 MiB, uploaded ccache data is limited to 1 MiB, and Hash Tools
wordlists are limited to 256 MiB.

Every response receives no-store caching directives, a restrictive Content Security
Policy, frame denial, MIME sniffing protection, no-referrer policy, and a restricted
Permissions Policy. Public HTTP errors come from a fixed safe-message catalog rather
than raw exception text.

These controls reduce browser exposure but do not make the application suitable for
binding to a LAN address. There is no user authentication, TLS termination, tenant
separation, or remote authorization model.

## Wordlist persistence

Wordlist saves use an atomic replacement. Source checkouts edit the tracked
`wordlists` file. Wheel and `pipx` installations copy the packaged default to the
user's XDG configuration directory on first use and edit that copy. Existing user
content is never overwritten during initialization. A running scan keeps the
wordlist snapshot it started with.

## Local Hash Tools

The panel probes locally installed Hashcat and John the Ripper before offering
them, including the formats exposed by the installed version. A job can only use a
tool-specific format derived from an existing finding and confirmed by that local
catalog; the request cannot supply a command, executable path, mode, or arbitrary
hash value. Commands use fixed argument templates and never invoke a shell.

Wordlists are uploaded as raw bytes so common non-UTF-8 lists remain usable. The
request is processed incrementally and written to an owner-only temporary file
instead of being copied into JSON or process memory. Uploads are limited to 256 MiB
and individual lines to 64 KiB. Only one job runs at a time, with an operator-selected
30-, 120-, or 300-second limit.

Recovered plaintext is retained only in process memory. Tool input, output, and
wordlist files use private temporary storage; starting a new SMB scan or closing the
process removes the staged wordlist. No finding, wordlist, or result is forwarded to
an external service.

## Operational limits

- The directory-depth default is 32.
- Target concurrency is fixed at 32.
- No selectable load profiles or per-host rate limiter exist.
- No results survive restart.
- The interface ships with Turkish and English language packs.
