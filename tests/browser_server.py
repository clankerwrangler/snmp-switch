"""Synthetic browser server; inherited listener only, no SNMP or RADIUS I/O."""
import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
listener = socket.socket(fileno=int(sys.argv[1]))
assert listener.getsockname()[0] == "127.0.0.1"


def guard(event, args):
    if event == "socket.__new__" and args[1] in (socket.AF_INET, socket.AF_INET6):
        if args[2] & socket.SOCK_DGRAM:
            raise AssertionError("UDP is prohibited in the browser fixture")
    if event in ("socket.connect", "socket.sendto", "socket.getaddrinfo",
                 "socket.gethostbyname", "socket.gethostbyaddr"):
        raise AssertionError("Outbound networking is prohibited in the browser fixture")


sys.addaudithook(guard)
import uvicorn
from switchlab.snmp import SnmpAdapter
import switchlab.radius


def prohibited(*args, **kwargs):
    raise AssertionError("SNMP and external RADIUS are prohibited in the browser fixture")


SnmpAdapter._initialize = prohibited
switchlab.radius.native_exchange = prohibited
switchlab.radius.mab_exchange = prohibited
switchlab.radius.accounting_delivery = prohibited
from switchlab.api import app

asyncio.run(uvicorn.Server(uvicorn.Config(app, log_level="warning", access_log=False)).serve(sockets=[listener]))
