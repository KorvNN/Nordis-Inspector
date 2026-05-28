# Detection Model

Nordis SMB Inspector combines an editable content wordlist with built-in credential
patterns. Detection is intentionally explainable: every finding identifies the
method and matched term or rule. Structured findings also include a category and
confidence; text findings retain their source line for review.

## Wordlist matching

The source-checkout wordlist is
[`wordlists/content/default-sensitive.txt`](../wordlists/content/default-sensitive.txt).
The web editor reads and saves this file atomically.

Wheel and `pipx` installations bundle the same default and create an editable copy
at `$XDG_CONFIG_HOME/nordis-smb-inspector/wordlists/default-sensitive.txt` on first
use. If `XDG_CONFIG_HOME` is unset, `~/.config` is used. Existing user content is not
overwritten by startup or package upgrades.

- One literal term per line
- Blank lines and lines beginning with `#` are ignored
- Matching is Unicode case-insensitive
- Duplicate terms are removed after case folding
- All occurrences on a physical line are retained
- Terms are literal text, not regular expressions

Additional terms entered for a scan are combined with the saved wordlist for that
scan only. Editing the saved wordlist while a scan is running does not change the
active scan's immutable configuration.

## Built-in patterns

Patterns target recognizable credential material rather than arbitrary high-entropy
text. Current rule families include:

- Cloud access keys
- JSON Web Tokens
- PEM private-key headers
- Basic and Bearer authorization values
- Provider token prefixes for GitHub, GitLab, Slack, Stripe, Google, npm, PyPI,
  Hugging Face, and Vault
- Credentials embedded in URLs
- Database and service connection strings
- netrc, Docker registry auth, Ansible Vault, and SOPS secret artifacts
- Secret assignments such as passwords, tokens, API keys, and client secrets
- Group Policy Preferences `cpassword` values
- Hashcat-style Kerberos TGS-REP, AS-REP, pre-auth, and KDC database-key material
- Labelled NTLM hashes and Kerberos RC4, AES-128, AES-256, and DES keys
- LM/NT hash pairs, account RID/hash records, NetNTLMv1/NetNTLMv2 responses, and DCC2
- Windows LAPS/managed-password attributes and private access-token headers
- Unix password hashes and modern application password hashes

Each rule has a stable identifier and confidence level. Common examples and obvious
placeholders are filtered where the rule can identify them reliably. The detector
does not use a general entropy threshold, so a finding is evidence for review rather
than proof that a live secret exists.

The scan form can generate literal search-term variants from supplied roots. Generated
terms are added only to the current scan's additional terms; they do not modify the
saved default wordlist. The web panel currently exposes one editable content list.

Unlabelled 32- or 64-character hexadecimal strings are not treated as NT or Kerberos
keys. Those lengths occur in checksums and unrelated identifiers, so the detector
requires either a recognized export format or a nearby key-type label.

The following matching controls are deliberately not part of the current web
contract: user-supplied regular expressions, selectable rule-category packs,
multiple wordlist selection, case-sensitive matching, and whole-word matching.
The lower-level text matcher has case and word-boundary options for future use, but
the scan configuration does not expose them yet.

## File processing

Plain text is decoded as BOM-declared UTF-16/UTF-32, strict UTF-8, or a supported
legacy encoding selected from a bounded sample. Lines are processed incrementally.
An undecidable encoding, decoding error, or over-limit line produces an explicit
incomplete-content status; partially decoded lines are not exposed as findings.

Supported structured formats include:

- PDF
- DOCX, XLSX, and PPTX
- ODT and related OpenDocument containers
- ZIP, TAR, and GZIP archives

Documents and archive members are read through bounded range adapters. Archive
recursion is not performed. Unsupported, encrypted, malformed, or over-limit
members are represented as inventory diagnostics rather than silently treated as a
clean scan.

When built-in detection is enabled, plain files and archive members named like
Kerberos CCache, keytab, or KIRBI files are also checked against their binary header.
Both the expected name and signature must match. Their contents are not decoded or
included in a finding.

## Finding fields

A finding contains:

- Target, share, and remote path
- Detection method (`wordlist`, `pattern`, or `artifact`)
- Match term for wordlist findings
- Rule identifier, category, and confidence for structured findings
- Physical or extracted line number and full decoded line for text findings

The full line gives the operator review context, but it can contain sensitive
material. Binary artifact findings never include decoded content. Do not paste text
findings into tickets, chat, or logs without redaction.

## Interpretation

A finding means that readable content matched a configured term or built-in rule. A
missing finding does not prove that a file is safe: access controls, unsupported
formats, encoding failures, scan limits, and cancellation can all prevent complete
inspection. Review the target and inventory statuses together with findings.
