# Content Wordlist

`content/default-sensitive.txt` contains the terms used for case-insensitive
content matching in a source checkout. The same default is bundled in the Python
package; a regression test keeps both copies identical.

Each non-empty line is one term. Lines beginning with `#` are comments, and
duplicate terms are matched once. The web interface can edit and atomically
replace the active file.

Wheel and `pipx` installations copy the packaged default to
`$XDG_CONFIG_HOME/nordis-smb-inspector/wordlists/default-sensitive.txt` on first
use. If `XDG_CONFIG_HOME` is unset, `~/.config` is used. An existing user copy is
never overwritten by an upgrade or startup.

Share names are not stored in a wordlist. They are discovered from each target
through SRVSVC.

See [Detection](../docs/DETECTION.md) for matching and pattern-detection details.
