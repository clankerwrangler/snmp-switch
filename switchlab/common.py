"""Small pieces shared by the engine and its components."""
from __future__ import annotations

import os
import time
from pathlib import Path

from .models import Target, View, uid


# The Docker image fixes the container-side listener ports, so only Compose chooses the
# host ports (SWITCHLAB_SNMP_PORT, SWITCHLAB_COA_PORT) and nothing has to match the UI.
# Native installs leave these unset and use the configured ports.
FIXED_PORT_VARIABLES = {"snmp": "SWITCHLAB_SNMP_LISTEN_PORT", "coa": "SWITCHLAB_COA_LISTEN_PORT"}


def fixed_port(service):
    value = os.environ.get(FIXED_PORT_VARIABLES[service])
    return int(value) if value else None


def listen_port(service, configured):
    return fixed_port(service) or configured


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


def event_resource_label(record):
    """Select the existing public display, never credential or profile contents."""
    if isinstance(record, Target):
        address = f"[{record.address}]" if ":" in record.address else record.address
        return f"{address}:{record.port}"
    return record.name if isinstance(record, View) else record.label
