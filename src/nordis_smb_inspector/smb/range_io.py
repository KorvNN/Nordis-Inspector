"""Seekable read-only file facade over a validated remote range reader."""

from __future__ import annotations

import io

from .cancellation import CancellationToken
from .contracts import ValidatedRangeReader

_DEFAULT_MAX_SINGLE_READ = 16 * 1024 * 1024


class RangeIoReadLimitError(OSError):
    """Raised when a parser requests an unexpectedly large contiguous buffer."""


class RemoteRangeIO(io.RawIOBase):
    """Expose seek/read without giving parsers ownership of the SMB handle."""

    def __init__(
        self,
        reader: ValidatedRangeReader,
        *,
        cancellation: CancellationToken,
        max_single_read: int = _DEFAULT_MAX_SINGLE_READ,
    ) -> None:
        super().__init__()
        if not isinstance(reader, ValidatedRangeReader):
            raise TypeError("reader must be a ValidatedRangeReader.")
        if isinstance(max_single_read, bool) or not isinstance(max_single_read, int):
            raise TypeError("max_single_read must be an integer.")
        if max_single_read < 1:
            raise ValueError("max_single_read must be at least one byte.")
        self._reader = reader
        self._cancellation = cancellation
        self._max_single_read = max_single_read
        self._position = 0

    @property
    def size(self) -> int:
        return self._reader.size

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        self._checkClosed()
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._checkClosed()
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise TypeError("offset must be an integer.")
        if whence == io.SEEK_SET:
            position = offset
        elif whence == io.SEEK_CUR:
            position = self._position + offset
        elif whence == io.SEEK_END:
            position = self.size + offset
        else:
            raise ValueError("Unsupported seek mode.")
        if position < 0:
            raise ValueError("Cannot seek before the start of the remote file.")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        self._checkClosed()
        if isinstance(size, bool) or not isinstance(size, int):
            raise TypeError("size must be an integer.")
        remaining = max(0, self.size - self._position)
        requested = remaining if size < 0 else min(size, remaining)
        if requested > self._max_single_read:
            raise RangeIoReadLimitError(
                "The document parser requested a contiguous buffer above the safe limit."
            )
        chunks: list[bytes] = []
        bytes_read = 0
        while bytes_read < requested:
            chunk = self._reader.read_range(
                self._position,
                min(requested - bytes_read, self._reader.max_read_size),
                cancellation=self._cancellation,
            )
            if not chunk:
                break
            chunks.append(chunk)
            chunk_length = len(chunk)
            self._position += chunk_length
            bytes_read += chunk_length
        return b"".join(chunks)

    def readinto(self, buffer: object) -> int:
        self._checkClosed()
        view = memoryview(buffer).cast("B")
        data = self.read(len(view))
        view[: len(data)] = data
        return len(data)

    def close(self) -> None:
        # The inspection worker owns and closes the underlying SMB reader.
        super().close()

