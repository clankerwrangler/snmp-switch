"""First-run setup: the encryption key, fixed container listener ports and the quick SNMP setup."""
import os
import socket
import stat

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from switchlab.api import configuration_key, create_app
from switchlab.models import initial_configuration
from test_api import change, sign_in


def test_a_fresh_installation_gets_a_private_key_on_first_start(tmp_path):
    key_path, database = tmp_path / "key" / "config.key", tmp_path / "switch.db"
    key = configuration_key(key_path, database)
    Fernet(key)  # A usable key.
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700
    assert configuration_key(key_path, database) == key, "later starts keep the same key"


def test_saved_data_without_its_key_stops_startup(tmp_path):
    database = tmp_path / "switch.db"
    database.write_bytes(b"saved settings")
    with pytest.raises(RuntimeError, match="config.key"):
        configuration_key(tmp_path / "config.key", database)
    assert not (tmp_path / "config.key").exists(), "no new key that could never read the saved data"


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_fixed_container_port_wins_over_the_saved_port_and_is_reported(store, monkeypatch):
    fixed = free_udp_port()
    monkeypatch.setenv("SWITCHLAB_SNMP_LISTEN_PORT", str(fixed))
    monkeypatch.setenv("SWITCHLAB_COA_LISTEN_PORT", "3799")
    cfg = initial_configuration(4); cfg.paused = True
    with TestClient(create_app(store, cfg)) as c:
        sign_in(c, store)
        assert c.get("/api/v1/state").json()["fixed_ports"] == {"snmp": fixed, "coa": 3799}
        assert change(c, "/switch", {"identity": {"sys_descr": "Switch", "sys_object_id": "2.999.7"}}, "PATCH").status_code == 200
        assert change(c, "/snmp/credentials", {"label": "Read", "version": "2c", "community": "fixture-community",
            "polling": {"enabled": True, "view_id": "all", "networks": []}}).status_code == 200
        assert change(c, "/snmp/settings", {"enabled": True, "port": 1161}, "PATCH").status_code == 200
        state = c.get("/api/v1/state").json()
        assert state["snmp"]["port"] == 1161, "the saved port is kept for native use"
        assert state["snmp_status"]["listener_ready"]
        assert c.app.state.adapter.binding == ("127.0.0.1", fixed)


def test_natively_the_saved_port_is_the_listener(store, monkeypatch):
    monkeypatch.delenv("SWITCHLAB_SNMP_LISTEN_PORT", raising=False)
    monkeypatch.delenv("SWITCHLAB_COA_LISTEN_PORT", raising=False)
    cfg = initial_configuration(4); cfg.paused = True
    with TestClient(create_app(store, cfg)) as c:
        sign_in(c, store)
        assert c.get("/api/v1/state").json()["fixed_ports"] == {"snmp": None, "coa": None}


def test_a_fresh_container_binds_coa_to_all_addresses(store, monkeypatch):
    monkeypatch.setenv("SWITCHLAB_COA_DEFAULT_HOST", "0.0.0.0")
    monkeypatch.setenv("SWITCHLAB_PORT_COUNT", "4")
    with TestClient(create_app(store)) as c:
        sign_in(c, store)
        assert c.get("/api/v1/state").json()["radius"]["dynamic_authorization"]["host"] == "0.0.0.0"


def test_the_quick_setup_steps_leave_snmp_answering_and_saved(store, monkeypatch):
    monkeypatch.setenv("SWITCHLAB_SNMP_LISTEN_PORT", str(free_udp_port()))
    cfg = initial_configuration(4); cfg.paused = True
    with TestClient(create_app(store, cfg)) as c:
        sign_in(c, store)
        # The same requests, in the same order, as the UI's Set up SNMP form.
        assert change(c, "/switch", {"identity": {"sys_descr": "Generic SNMP Switch Emulator", "sys_object_id": "2.999.123"}}, "PATCH").status_code == 200
        assert change(c, "/snmp/credentials", {"label": "Read-only community", "version": "2c", "community": "quick-community",
            "enabled": True, "polling": {"enabled": True, "view_id": "all", "networks": []},
            "writing": {"enabled": False, "view_id": None, "networks": []}}).status_code == 200
        assert change(c, "/snmp/settings", {"enabled": True}, "PATCH").status_code == 200
        assert change(c, "/switch/save").status_code == 200
        state = c.get("/api/v1/state").json()
        assert state["snmp_status"]["ready"] and state["snmp_status"]["listener_ready"]
        assert state["configuration_status"]["unsaved"] is False
        assert [cr["polling"]["enabled"] and not cr["writing"]["enabled"] for cr in state["credentials"].values()] == [True]
