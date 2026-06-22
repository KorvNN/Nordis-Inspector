<p>
  <img src="src/nordis_smb_inspector/web/static/favicon.svg" alt="Nordis Inspector" width="96" align="left">
</p>

# Nordis Inspector<br><small><small>"What is visible, accessible, and potentially usable."</small></small>

Nordis Inspector is a local assessment tool for authorized Windows and Active
Directory environments. It evaluates the supplied identity in a live local web
dashboard.

## Highlights

- Inspects SMB security, shares, readable files, and exposed credential material
- Uses authenticated LDAP to separate principal capabilities from environment findings
- Supports passwords, NT hashes, Kerberos, and CCache files
- Shows verification state and incomplete coverage instead of treating unknowns as clean
- Keeps results local and can export completed SMB scans as JSON

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

Use Nordis Inspector only against systems and data you are authorized to assess.
The optional SMB write check is disabled by default. AD inspection does not modify
directory objects or return readable LAPS and gMSA secret values.

## License

MIT License. See [LICENSE](LICENSE).
