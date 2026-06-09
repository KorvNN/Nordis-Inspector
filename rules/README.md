# Detection Rules

These five TOML files are the built-in rule packs used by the scanner. Each file
declares its schema version, stable pack ID, display names, and reviewed regular
expressions. The application validates and compiles every pack at startup.

The web panel can enable or disable packs per scan. Rules are local, versioned
with the application, and never downloaded or updated automatically. Arbitrary
user-supplied regular expressions are not supported.
