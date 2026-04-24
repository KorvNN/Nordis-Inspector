from __future__ import annotations

import io
import unittest

from nordis_smb_inspector.smb.cancellation import NEVER_CANCELLED
from nordis_smb_inspector.smb.contracts import ValidatedRangeReader
from nordis_smb_inspector.smb.range_io import RangeIoReadLimitError, RemoteRangeIO


class _Reader(ValidatedRangeReader):
    def __init__(self, data: bytes, max_read_size: int = 3) -> None:
        super().__init__(size=len(data), max_read_size=max_read_size)
        self.data = data
        self.calls: list[tuple[int, int]] = []

    def _read_remote_range(self, offset: int, length: int, *, cancellation) -> bytes:
        del cancellation
        self.calls.append((offset, length))
        return self.data[offset : offset + length]


class RemoteRangeIoTests(unittest.TestCase):
    def test_read_seek_and_readinto_use_bounded_remote_ranges(self) -> None:
        reader = _Reader(b"0123456789")
        stream = RemoteRangeIO(reader, cancellation=NEVER_CANCELLED, max_single_read=8)

        self.assertEqual(b"01234", stream.read(5))
        self.assertEqual([(0, 3), (3, 2)], reader.calls)
        self.assertEqual(5, stream.tell())
        self.assertEqual(8, stream.seek(-2, io.SEEK_END))
        target = bytearray(2)
        self.assertEqual(2, stream.readinto(target))
        self.assertEqual(b"89", bytes(target))
        self.assertEqual(0, stream.seek(0))
        self.assertEqual(b"012", stream.read(3))

    def test_large_contiguous_requests_fail_without_remote_read(self) -> None:
        reader = _Reader(b"0123456789")
        stream = RemoteRangeIO(reader, cancellation=NEVER_CANCELLED, max_single_read=4)

        with self.assertRaises(RangeIoReadLimitError):
            stream.read()

        self.assertEqual([], reader.calls)

    def test_close_does_not_close_underlying_smb_reader(self) -> None:
        reader = _Reader(b"data")
        stream = RemoteRangeIO(reader, cancellation=NEVER_CANCELLED)

        stream.close()

        self.assertFalse(reader.closed)
        with self.assertRaises(ValueError):
            stream.read(1)

    def test_invalid_seeks_and_limits_are_rejected(self) -> None:
        reader = _Reader(b"data")
        with self.assertRaises(ValueError):
            RemoteRangeIO(reader, cancellation=NEVER_CANCELLED, max_single_read=0)
        stream = RemoteRangeIO(reader, cancellation=NEVER_CANCELLED)
        with self.assertRaises(ValueError):
            stream.seek(-1)
        with self.assertRaises(ValueError):
            stream.seek(0, 99)


if __name__ == "__main__":
    unittest.main()
