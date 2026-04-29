from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import Mock, patch

import uvicorn

from nordis_smb_inspector.cli import _NordisServer, main


class CliTests(unittest.TestCase):
    def test_ctrl_c_shutdown_has_a_finite_sse_grace_period(self) -> None:
        output = StringIO()

        with (
            patch("nordis_smb_inspector.cli.uvicorn.Config") as config,
            patch("nordis_smb_inspector.cli._NordisServer") as server,
            redirect_stdout(output),
        ):
            server.return_value.started = True
            result = main(["--port", "9876"])

        self.assertEqual(result, 0)
        self.assertEqual(config.call_args.kwargs["timeout_graceful_shutdown"], 2)
        server.return_value.run.assert_called_once_with()
        self.assertIn("Durdurmak için Ctrl+C.", output.getvalue())

    def test_exit_wakes_event_streams_before_uvicorn_shutdown(self) -> None:
        callback = Mock()
        config = Mock(spec=uvicorn.Config)

        with patch.object(uvicorn.Server, "handle_exit") as parent_exit:
            server = _NordisServer(config, callback)
            server.handle_exit(2, None)

        callback.assert_called_once_with()
        parent_exit.assert_called_once_with(2, None)

    def test_restored_sigint_is_clean_and_bind_failure_still_returns_three(self) -> None:
        with (
            patch("nordis_smb_inspector.cli.uvicorn.Config"),
            patch("nordis_smb_inspector.cli._NordisServer") as server,
        ):
            server.return_value.run.side_effect = KeyboardInterrupt
            server.return_value.started = True
            self.assertEqual(main(["--port", "9876"]), 0)

            server.return_value.run.side_effect = None
            server.return_value.started = False
            self.assertEqual(main(["--port", "9876"]), 3)


if __name__ == "__main__":
    unittest.main()
