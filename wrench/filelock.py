"""A small cross-process advisory file lock (fcntl on POSIX, msvcrt on Windows).

Several wrench processes share one data directory: a scheduled patrol, the
dashboard, an interactive command. Anything that does read-modify-write on a
plain file there (the notification inbox, the audit chain) takes this lock.
The lock lives on a ``<file>.lock`` sidecar so the data file itself can be
atomically replaced while held.
"""

from __future__ import annotations

import threading
from pathlib import Path

_process_locks: dict[str, threading.RLock] = {}
_registry_lock = threading.Lock()


class FileLock:
    def __init__(self, path: Path | str):
        self.path = Path(str(path) + ".lock")
        self.fh = None
        with _registry_lock:
            self._tlock = _process_locks.setdefault(str(self.path), threading.RLock())

    def __enter__(self):
        self._tlock.acquire()          # threads in this process
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fh = open(self.path, "a+")  # noqa: SIM115
            try:
                import fcntl
                fcntl.flock(self.fh, fcntl.LOCK_EX)
            except ImportError:        # Windows
                try:
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_LOCK, 1)
                except (ImportError, OSError):
                    pass
        except OSError:
            self.fh = None             # unlockable location: still serialized in-process
        return self

    def __exit__(self, *exc):
        try:
            if self.fh is not None:
                try:
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                except (ImportError, OSError):
                    pass
                self.fh.close()        # closing releases flock
                self.fh = None
        finally:
            self._tlock.release()
        return False
