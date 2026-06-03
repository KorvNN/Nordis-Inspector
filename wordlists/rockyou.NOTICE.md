# rockyou.txt

`rockyou.txt.gz` is redistributed from the
[Kali Linux wordlists package](https://gitlab.com/kalilinux/packages/wordlists/-/blob/kali/master/rockyou.txt.gz).
Kali's package metadata identifies Kali Linux as the copyright holder and states
the license for this file as: “Free — Free and widely accessible.”

This archive is third-party data and is not covered by this project's MIT license.
It originates from a historical password disclosure and is included only for
authorized, local password-audit testing.

The web interface accepts an uncompressed TXT file. Create the ignored local copy
with:

```bash
mkdir -p data/wordlists
gzip -dc wordlists/rockyou.txt.gz > data/wordlists/rockyou.txt
```
