"""Console entry point for the loopback-only Nordis web panel."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

DEFAULT_PORT = 8765


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nordis-smb-inspector",
        description="Start the authorized, local-only SMB inspection panel.",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=DEFAULT_PORT,
        help=f"loopback TCP port (default: {DEFAULT_PORT})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    import uvicorn

    from nordis_smb_inspector.web.app import create_app

    url = f"http://127.0.0.1:{args.port}"
    print(f"Nordis SMB Inspector: {url}")
    print("Tarama verileri yalnız süreç belleğinde tutulur. Durdurmak için Ctrl+C.")
    uvicorn.run(
        create_app(port=args.port),
        host="127.0.0.1",
        port=args.port,
        access_log=False,
        reload=False,
        workers=1,
        log_level="warning",
        server_header=False,
        date_header=False,
    )
    return 0


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


if __name__ == "__main__":
    raise SystemExit(main())
