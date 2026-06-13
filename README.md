# Nordis SMB Inspector

Nordis is a local SMB assessment tool for authorized Windows and
Samba environments. It inventories accessible data and highlights exposed
credential material in a live web dashboard.

## Highlights

- Scans IPs, CIDR ranges, and hostnames over SMB/TCP 445
- Supports passwords, NT hashes, and Kerberos CCache files
- Reports SMB security settings, authentication outcomes, shares, and readable files
- Searches bounded text, document, and archive content using wordlists and rule packs
- Streams results live and keeps browser-local history with JSON export
- Can pass supported offline hashes to local Hashcat or John the Ripper installations

## Quick start

```bash
./setup.sh
./run.sh
```

Open <http://127.0.0.1:8765>. To use another local port:

```bash
./run.sh --port 9000
```

## Safety

Use Nordis only against systems and data you are authorized to assess. It never
tests write access. Scan history may contain submitted passwords or NT hashes.

## License

MIT License. See [LICENSE](LICENSE).
