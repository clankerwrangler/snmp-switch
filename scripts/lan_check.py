"""Check canonical Compose bindings on a disposable internal Docker network.

Requires Linux Docker Engine, Compose v2, and prebuilt switchlab:0.1.0 and
switchlab-test images. Ports 8000/tcp and 1161/udp must be free on localhost.
"""
import argparse
import base64
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid


def run(*args, env=None, timeout=30, check=True):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}\n{result.stderr}")
    return result


def probe(host, subnet, expect_closed):
    address, network = ipaddress.IPv4Address(host), ipaddress.IPv4Network(subnet)
    assert not address.is_loopback and address in network
    if expect_closed:
        try:
            with socket.create_connection((host, 8000), timeout=2):
                pass
        except OSError:
            print(json.dumps({"localhost_binding_rejects_remote_http": "passed"}))
            return
        raise AssertionError("Localhost-only publication accepted a remote connection")

    base = f"http://{host}:8000"
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))
    csrf = ""

    def api(route, method="GET", data=None, expected=200, origin=None, token=None):
        headers = {"Content-Type": "application/json", "Origin": origin or base,
                   "X-CSRF-Token": csrf if token is None else token}
        request = urllib.request.Request(base + route, method=method, headers=headers,
            data=json.dumps(data).encode() if data is not None else None)
        try:
            response = opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == expected, (route, response.status, expected)
            assert "Access-Control-Allow-Origin" not in response.headers
            return json.load(response)

    def command(route, data=None, method="POST", **kwargs):
        revision = api("/api/v1/state")["configuration_revision"]
        return api("/api/v1" + route, method,
                   {**(data or {}), "expected_configuration_revision": revision}, **kwargs)

    with opener.open(base + "/", timeout=3) as response:
        html = response.read().decode()
        assert response.status == 200
    assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
    assert assets
    for asset in assets:
        with opener.open(base + asset, timeout=3) as response:
            assert response.status == 200 and response.read()
    api("/api/v1/state", expected=401)
    setup = {"setup_token": "lan-fixture-token", "password": "lan-fixture-password"}
    api("/api/v1/auth/setup", "POST", setup, expected=403, origin="http://other-host.invalid")
    csrf = api("/api/v1/auth/setup", "POST", setup)["csrf_token"]
    cookie = next(c for c in cookies if c.name == "switchlab_session")
    assert not cookie.secure and not cookie.domain_specified
    assert cookie.has_nonstandard_attr("HttpOnly")
    assert cookie.get_nonstandard_attr("SameSite").lower() == "strict"
    assert api("/api/v1/auth/status")["authenticated"]
    command("/clock/pause")
    before = api("/api/v1/state")
    assert before["switch"]["identity"]["sys_object_id"] is None
    assert before["snmp_status"]["reason"] == "identity_required"
    command("/clock/advance", {"duration_ms": 1000}, expected=403, token="")
    command("/clock/advance", {"duration_ms": 1000}, expected=403,
            origin=f"http://{host}:8001")
    after = api("/api/v1/state")
    assert after["configuration_revision"] == before["configuration_revision"]
    assert after["simulation_ms"] == before["simulation_ms"]
    command("/clock/advance", {"duration_ms": 1000})
    assert api("/api/v1/state")["simulation_ms"] == before["simulation_ms"] + 1000
    api("/api/v1/auth/logout", "POST")
    api("/api/v1/state", expected=401)
    csrf = api("/api/v1/auth/login", "POST", {"password": setup["password"]})["csrf_token"]

    def polling(allowed):
        result = run("snmpget", "-v2c", "-c", "lan-fixture-community", "-On",
                     "-t", "1", "-r", "0", f"{host}:1161", "1.3.6.1.2.1.1.2.0",
                     timeout=5, check=False)
        if allowed:
            assert result.returncode == 0 and "2.999.123" in result.stdout
        else:
            assert result.returncode != 0 and "Timeout" in result.stderr

    credential = command("/snmp/credentials", {
        "label": "LAN fixture", "community": "lan-fixture-community"})["id"]
    command("/snmp/settings", {"enabled": True, "host": "0.0.0.0"}, "PATCH")
    assert not api("/api/v1/snmp/status")["ready"]
    polling(False)
    command("/switch", {"identity": {"sys_object_id": "2.999.123"}}, "PATCH")
    assert api("/api/v1/snmp/status")["ready"]
    polling(False)  # The credential still allows only loopback sources.
    command(f"/snmp/credentials/{credential}", {"networks": [subnet]}, "PUT")
    polling(True)
    command("/snmp/settings", {"host": "127.0.0.1"}, "PATCH")
    polling(False)
    command("/snmp/settings", {"host": "0.0.0.0"}, "PATCH")
    polling(True)
    command(f"/snmp/credentials/{credential}", {"networks": ["127.0.0.0/8"]}, "PUT")
    polling(False)
    command(f"/snmp/credentials/{credential}", {"networks": [subnet]}, "PUT")
    polling(True)
    command("/switch", {"identity": {"sys_object_id": None}}, "PATCH")
    assert not api("/api/v1/snmp/status")["ready"]
    polling(False)
    print(json.dumps({"non_loopback_http_and_assets": "passed", "session_login_logout": "passed",
        "same_origin_csrf": "passed", "cross_origin_and_missing_csrf_rejected": "passed",
        "snmp_identity_gate": "passed", "snmp_loopback_and_lan_listener": "passed",
        "snmp_source_cidr_allow_and_revoke": "passed"}))


def check_compose():
    source = Path(__file__).resolve().parents[1]
    run("docker", "image", "inspect", "switchlab:0.1.0", "switchlab-test")
    project = "switchlab-lan-" + uuid.uuid4().hex[:12]
    network_name, probe_name = project + "-network", project + "-probe"
    run("docker", "network", "create", "--internal", network_name)
    try:
        network = json.loads(run("docker", "network", "inspect", network_name).stdout)[0]
        assert network["Internal"]
        ipam = next(c for c in network["IPAM"]["Config"] if ":" not in c["Subnet"])
        gateway, subnet = ipam["Gateway"], ipam["Subnet"]
        address = ipaddress.IPv4Address(gateway)
        assert not address.is_loopback and not address.is_unspecified
        assert address in ipaddress.IPv4Network(subnet)
        with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
            fixture = Path(temporary)
            (fixture / "secrets").mkdir(mode=0o700)
            key = fixture / "secrets/config.key"
            key.write_bytes(base64.urlsafe_b64encode(os.urandom(32)))
            key.chmod(0o644)  # The private parent protects the fixture; UID 10001 reads the mount.
            (fixture / "empty.env").write_text("")
            override = fixture / "fixture.json"
            override.write_text(json.dumps({
                "services": {"switchlab": {"environment": {"SWITCHLAB_SETUP_TOKEN": "lan-fixture-token"}}},
                "networks": {"default": {"external": True, "name": network_name}}}))
            compose_args = ["docker", "compose", "--project-name", project,
                "--project-directory", str(fixture), "--env-file", str(fixture / "empty.env"),
                "-f", str(source / "compose.yaml"), "-f", str(override)]

            def compose(*args, bind=None, secure="0", check=True):
                env = {**os.environ, "SWITCHLAB_SECURE_COOKIES": secure}
                env.pop("SWITCHLAB_BIND_ADDRESS", None)
                if bind is not None:
                    env["SWITCHLAB_BIND_ADDRESS"] = bind
                return run(*compose_args, *args, env=env, timeout=90, check=check)

            def assert_ports(ports, bind):
                assert {(p["target"], str(p["published"]), p["protocol"], p["host_ip"])
                        for p in ports} == {(8000, "8000", "tcp", bind), (1161, "1161", "udp", bind)}

            def remote_probe(closed=False):
                args = ["docker", "run", "--rm", "--name", probe_name, "--network", network_name,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                    "--tmpfs", "/tmp", "-e", "HOME=/tmp", "--mount",
                    f"type=bind,source={source / 'scripts/lan_check.py'},target=/lan_check.py,readonly",
                    "switchlab-test", "python", "/lan_check.py", "--probe-host", gateway,
                    "--probe-subnet", subnet]
                if closed:
                    args.append("--expect-closed")
                print(run(*args, timeout=60).stdout.strip())

            try:
                # Render wildcard opt-in without ever opening wildcard host ports.
                for selected in (None, "", gateway, "0.0.0.0"):
                    service = json.loads(compose("config", "--format", "json", bind=selected).stdout)["services"]["switchlab"]
                    assert_ports(service["ports"], selected or "127.0.0.1")
                    assert service["environment"]["SWITCHLAB_SECURE_COOKIES"] == "0"
                secure = json.loads(compose("config", "--format", "json", secure="1").stdout)
                assert secure["services"]["switchlab"]["environment"]["SWITCHLAB_SECURE_COOKIES"] == "1"
                for bind in (None, gateway):
                    compose("up", "--detach", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "60", bind=bind)
                    container = compose("ps", "--quiet", "switchlab", bind=bind).stdout.strip()
                    ports = json.loads(run("docker", "inspect", container).stdout)[0]["NetworkSettings"]["Ports"]
                    for port in ("8000/tcp", "1161/udp"):
                        assert ports[port] == [{"HostIp": bind or "127.0.0.1", "HostPort": port.split("/")[0]}]
                    if bind is None:
                        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                        with opener.open("http://127.0.0.1:8000/healthz", timeout=3) as response:
                            assert json.load(response)["ready"]
                    remote_probe(closed=bind is None)
            finally:
                try:
                    run("docker", "rm", "--force", probe_name, timeout=10, check=False)
                finally:
                    compose("down", "--volumes", "--remove-orphans")
    finally:
        run("docker", "network", "rm", network_name)
    print(json.dumps({"compose_default_and_explicit_bindings": "passed",
                      "secure_cookie_environment_forwarding": "passed", "fixture_cleanup": "passed"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-host", help=argparse.SUPPRESS)
    parser.add_argument("--probe-subnet", help=argparse.SUPPRESS)
    parser.add_argument("--expect-closed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe_host:
        if not args.probe_subnet:
            parser.error("The fixture probe requires --probe-subnet")
        probe(args.probe_host, args.probe_subnet, args.expect_closed)
    else:
        check_compose()
