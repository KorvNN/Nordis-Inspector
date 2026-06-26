"""Console entry point for the loopback-only Nordis web panel."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import suppress
from types import FrameType

import uvicorn

DEFAULT_PORT = 8765


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
        "--port",
        type=_port,
        default=DEFAULT_PORT,
        help=f"loopback TCP port (default: {DEFAULT_PORT})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    from nordis_smb_inspector.web.app import create_app

    url = f"http://127.0.0.1:{args.port}"
    print(f"Nordis Inspector: {url}")
    print("Durdurmak için Ctrl+C.")
    app = create_app(port=args.port)
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
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


if __name__ == "__main__":
    raise SystemExit(main())
