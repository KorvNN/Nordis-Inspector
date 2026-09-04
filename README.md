<p>
  <img src="src/nordis_smb_inspector/web/static/nordis-icon.svg" alt="Nordis Inspector" width="96" align="left">
</p>

# Nordis Inspector<br><sup><sup><em>"What is visible, accessible, and potentially usable."</em></sup></sup>

Nordis Inspector is a local assessment tool for authorized Windows and Active
Directory environments. It evaluates the supplied identity in a live local web
dashboard.

## Highlights

- Inspects SMB security, shares, readable files, and exposed credential material
- Combines a default literal term list, structured regex rules, and filename signals
- Uses authenticated LDAP to separate principal capabilities from environment findings
- Supports passwords, NT hashes, Kerberos, and CCache files

## Quick start

```bash
./setup.sh
./run.sh

# Open one of the LAN addresses printed by the command
```

`setup.sh` does not re-download unchanged dependencies on later runs and keeps
the pip cache under `.pip-cache/`. Use `./setup.sh --force` to rebuild the
environment deliberately.

To use another local port:

```bash
./run.sh --port 9000
```

The panel listens on local IPv4 interfaces by default. To restrict it to this
machine:

```bash
./run.sh --host 127.0.0.1
```

The panel uses plain HTTP, so do not expose it to an untrusted network.

## Safety

Use Nordis Inspector only against systems and data you are authorized to assess.
The optional SMB write check is disabled by default. AD inspection does not modify
directory objects or return readable LAPS and gMSA secret values.

## License

MIT License. See [LICENSE](LICENSE).
