"""Small pieces shared by the engine and its components."""
from __future__ import annotations

import time
from pathlib import Path

from .models import uid


def _clock_origin():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "process:" + uid()


# Elapsed-clock readings are only comparable within one boot of the host.
ACCOUNTING_CLOCK_ORIGIN = _clock_origin()


def accounting_elapsed_clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, "CLOCK_BOOTTIME") else time.monotonic()


class CommandError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message
        super().__init__(message)


def require(condition, message, status=409):
    if not condition:
        raise CommandError(status, message)
