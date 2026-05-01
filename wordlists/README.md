# Content Wordlist

`content/default-sensitive.txt` contains the terms used for case-insensitive
content matching.

Each non-empty line is one term. Lines beginning with `#` are comments, and
duplicate terms are matched once. The web interface can edit and atomically
replace this file.

Share names are not stored in a wordlist. They are discovered from each target
through SRVSVC.

See [Detection](../docs/DETECTION.md) for matching and pattern-detection details.
