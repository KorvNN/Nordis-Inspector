"""Console entry point for the Nordis web panel."""

from __future__ import annotations

import argparse
import ipaddress
import socket
from collections.abc import Callable, Sequence
from contextlib import suppress
from types import FrameType

import uvicorn

DEFAULT_PORT = 8765
DEFAULT_HOST = "0.0.0.0"


class _NordisServer(uvicorn.Server):
    """Wake long-lived local event streams before Uvicorn drains requests."""

    def __init__(self, config: uvicorn.Config, before_exit: Callable[[], None]) -> None:
        super().__init__(config)
        self._before_exit = before_exit

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        try:
            self._before_exit()
        finally:
            super().handle_exit(sig, frame)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nordis-smb-inspector",
        description="Start the local Nordis inspection panel.",
    )
    parser.add_argument(
        "--host",
        type=_host,
        default=DEFAULT_HOST,
        help="IPv4 listen address (default: 0.0.0.0; use 127.0.0.1 for local-only)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=DEFAULT_PORT,
        help=f"panel TCP port (default: {DEFAULT_PORT})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from nordis_smb_inspector.web.app import create_app

    if args.host == "0.0.0.0":
        urls = [f"http://{address}:{args.port}" for address in _local_ipv4_addresses()]
        print("Nordis Inspector (LAN):")
        for url in urls or [f"http://<yerel-ip>:{args.port}"]:
            print(f"  {url}")
        print("Uyarı: Panel HTTP kullanır; yalnız güvendiğiniz yerel ağda açın.")
    else:
        print(f"Nordis Inspector: http://{args.host}:{args.port}")
    print("Durdurmak için Ctrl+C.")
    app = create_app(host=args.host, port=args.port)
    config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        access_log=False,
        reload=False,
        workers=1,
        log_level="warning",
        server_header=False,
        date_header=False,
        # The signal hook closes live SSE streams first; this finite bound is a
        # final guard for a connection that cannot complete cleanly.
        timeout_graceful_shutdown=2,
    )
    server = _NordisServer(config, app.state.runtime.events.close)
    # Uvicorn restores and re-raises the original SIGINT after its graceful
    # shutdown. The signal has already been handled; keep the CLI clean.
    with suppress(KeyboardInterrupt):
        server.run()
    if not server.started:
        return 3
    return 0


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _host(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("host must be an IPv4 address") from exc
    if address.is_multicast or (
        not address.is_unspecified
        and not address.is_loopback
        and not address.is_private
        and not address.is_link_local
    ):
        raise argparse.ArgumentTypeError("host must be a local IPv4 address or 0.0.0.0")
    return address.compressed


def _local_ipv4_addresses() -> tuple[str, ...]:
    addresses = {"127.0.0.1"}
    try:
        for result in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = ipaddress.IPv4Address(result[4][0])
            if address.is_private or address.is_link_local:
                addresses.add(address.compressed)
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            address = ipaddress.IPv4Address(probe.getsockname()[0])
            if address.is_private or address.is_link_local:
                addresses.add(address.compressed)
    except OSError:
        pass
    return tuple(sorted(addresses, key=ipaddress.IPv4Address))


if __name__ == "__main__":
    raise SystemExit(main())
