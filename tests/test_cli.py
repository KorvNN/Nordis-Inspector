from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from nordis_smb_inspector.cli import main


class CliTests(unittest.TestCase):
    def test_ctrl_c_shutdown_has_a_finite_sse_grace_period(self) -> None:
        output = StringIO()

        with patch("uvicorn.run") as run, redirect_stdout(output):
            result = main(["--port", "9876"])

        self.assertEqual(result, 0)
        self.assertEqual(run.call_args.kwargs["timeout_graceful_shutdown"], 1)
        self.assertIn("Durdurmak için Ctrl+C.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
