<p>
  <img src="src/nordis_smb_inspector/web/static/nordis-icon.svg" alt="Nordis Inspector" width="96" align="left">
</p>

# Nordis Inspector<br><sup><sup><em>"What is visible, accessible, and potentially usable."</em></sup></sup>

Nordis Inspector is a local SMB assessment tool for authorized Windows and Samba
environments. It inventories accessible data and highlights exposed credential
material in a live local web dashboard.

## Highlights

- Inspects SMB security, shares, readable files, and exposed credential material
- Supports passwords, NT hashes, Kerberos, and CCache files

## Quick start

```bash
./setup.sh
./run.sh

# Open http://127.0.0.1:8765
```

To use another local port:

```bash
./run.sh --port 9000
```

## Safety

Use Nordis Inspector only against systems and data you are authorized to assess.
The optional SMB write check is disabled by default.

## License

MIT License. See [LICENSE](LICENSE).
