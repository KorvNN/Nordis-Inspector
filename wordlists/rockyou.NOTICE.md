# rockyou.txt

`rockyou.txt` is **not** distributed with this repository. It is third-party data,
not covered by this project's MIT license, and it originates from a historical
password disclosure. Use it only for authorized, local password-audit testing.

Fetch it yourself from the
[Kali Linux wordlists package](https://gitlab.com/kalilinux/packages/wordlists/-/blob/kali/master/rockyou.txt.gz).
Kali's package metadata identifies Kali Linux as the copyright holder and states
the license for this file as: “Free — Free and widely accessible.”

The web interface accepts an uncompressed TXT file. Place the archive in this
directory and extract it:

```bash
gzip -dk wordlists/rockyou.txt.gz
```

Both the archive and the extracted copy are ignored by git.
