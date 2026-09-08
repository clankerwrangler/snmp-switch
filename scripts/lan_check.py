"""Check canonical Compose bindings on a disposable Docker bridge.

Requires Linux Docker Engine, Compose v2, and prebuilt switchlab:0.1.0 and
switchlab-test images. Ports 8000/tcp and 161/udp must be free on localhost.
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


def probe(host, subnet, expect_closed, snmp_port, next_port, http_port):
    address, network = ipaddress.IPv4Address(host), ipaddress.IPv4Network(subnet)
    assert not address.is_loopback and address in network
    if expect_closed:
        try:
            with socket.create_connection((host, http_port), timeout=2):
                pass
        except OSError:
            print(json.dumps({"localhost_binding_rejects_remote_http": "passed"}))
            return
        raise AssertionError("Localhost-only publication accepted a remote connection")

    base = f"http://{host}:{http_port}"
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
    fresh = api("/api/v1/auth/status")["setup_required"]
    if fresh:
        api("/api/v1/auth/setup", "POST", setup, expected=403, origin="http://other-host.invalid")
        csrf = api("/api/v1/auth/setup", "POST", setup)["csrf_token"]
    else:
        login = {"password": setup["password"]}
        api("/api/v1/auth/login", "POST", login, expected=403, origin="http://other-host.invalid")
        csrf = api("/api/v1/auth/login", "POST", login)["csrf_token"]
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
            origin=f"http://{host}:{http_port + 1}")
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
                     "-t", "1", "-r", "0", f"{host}:{snmp_port}", "1.3.6.1.2.1.1.2.0",
                     timeout=5, check=False)
        if allowed:
            assert result.returncode == 0 and "2.999.123" in result.stdout
        else:
            assert result.returncode != 0 and "Timeout" in result.stderr

    state = api("/api/v1/state")
    assert state["snmp"]["port"] == snmp_port
    if fresh:
        credential = command("/snmp/credentials", {
            "label": "LAN fixture", "community": "lan-fixture-community"})["id"]
    else:
        assert len(state["credentials"]) == 1
        credential = next(iter(state["credentials"]))
        command(f"/snmp/credentials/{credential}", {"networks": ["127.0.0.0/8", "::1/128"]}, "PUT")
        print(json.dumps({f"saved_listener_{snmp_port}_preserved": "passed"}))
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
    if next_port is not None:
        command("/switch", {"identity": {"sys_object_id": "2.999.123"}}, "PATCH")
        polling(True)
        command("/snmp/settings", {"port": next_port}, "PATCH")
        assert api("/api/v1/snmp/status")["ready"]
        assert api("/healthz")["ready"]
        polling(False)  # Compose still publishes the previous listener port.
        command("/switch", {"identity": {"sys_object_id": None}}, "PATCH")
        assert api("/api/v1/state")["snmp"]["port"] == next_port
        print(json.dumps({f"listener_port_{snmp_port}_to_{next_port}_saved": "passed"}))
    print(json.dumps({"non_loopback_http_and_assets": "passed", "session_login_logout": "passed",
        "same_origin_csrf": "passed", "cross_origin_and_missing_csrf_rejected": "passed",
        "snmp_identity_gate": "passed", "snmp_loopback_and_lan_listener": "passed",
        "snmp_source_cidr_allow_and_revoke": "passed"}))


def check_compose():
    source = Path(__file__).resolve().parents[1]
    run("docker", "image", "inspect", "switchlab:0.1.0", "switchlab-test")
    host_sysctl = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text()
    project = "switchlab-lan-" + uuid.uuid4().hex[:12]
    network_name, probe_name = project + "-network", project + "-probe"
    run("docker", "network", "create", "--driver", "bridge", network_name)
    try:
        network = json.loads(run("docker", "network", "inspect", network_name).stdout)[0]
        assert network["Driver"] == "bridge" and not network["Internal"]
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

            def compose(*args, bind=None, snmp_port=None, http_port=None, secure="0", check=True):
                env = {**os.environ, "SWITCHLAB_SECURE_COOKIES": secure}
                env.pop("SWITCHLAB_BIND_ADDRESS", None)
                env.pop("SWITCHLAB_SNMP_PORT", None)
                env.pop("SWITCHLAB_HTTP_PORT", None)
                if http_port is not None:
                    env["SWITCHLAB_HTTP_PORT"] = str(http_port)
                if snmp_port is not None:
                    env["SWITCHLAB_SNMP_PORT"] = str(snmp_port)
                if bind is not None:
                    env["SWITCHLAB_BIND_ADDRESS"] = bind
                return run(*compose_args, *args, env=env, timeout=90, check=check)

            def assert_ports(ports, bind, snmp_port="161", http_port="8000"):
                assert {(p["target"], str(p["published"]), p["protocol"], p["host_ip"])
                        for p in ports} == {(8000, str(http_port), "tcp", bind), (int(snmp_port), str(snmp_port), "udp", bind)}

            def remote_probe(closed=False, snmp_port=161, next_port=None, http_port=8000):
                args = ["docker", "run", "--rm", "--name", probe_name, "--network", network_name,
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                    "--tmpfs", "/tmp", "-e", "HOME=/tmp", "--mount",
                    f"type=bind,source={source / 'scripts/lan_check.py'},target=/lan_check.py,readonly",
                    "switchlab-test", "python", "/lan_check.py", "--probe-host", gateway,
                    "--probe-subnet", subnet, "--probe-snmp-port", str(snmp_port),
                    "--probe-http-port", str(http_port)]
                if next_port is not None:
                    args.extend(["--next-port", str(next_port)])
                if closed:
                    args.append("--expect-closed")
                print(run(*args, timeout=60).stdout.strip())

            try:
                # Render wildcard opt-in without ever opening wildcard host ports.
                for selected in (None, "", gateway, "0.0.0.0"):
                    service = json.loads(compose("config", "--format", "json", bind=selected).stdout)["services"]["switchlab"]
                    assert_ports(service["ports"], selected or "127.0.0.1")
                    assert service["environment"]["SWITCHLAB_SECURE_COOKIES"] == "0"
                    assert str(service["sysctls"]["net.ipv4.ip_unprivileged_port_start"]) == "161"
                for selected_port in (None, "", "1161", "2161"):
                    service = json.loads(compose("config", "--format", "json", snmp_port=selected_port).stdout)["services"]["switchlab"]
                    assert_ports(service["ports"], "127.0.0.1", selected_port or "161")
                for selected_http in (None, "", "8080"):
                    service = json.loads(compose("config", "--format", "json", http_port=selected_http).stdout)["services"]["switchlab"]
                    assert_ports(service["ports"], "127.0.0.1", http_port=selected_http or "8000")
                secure = json.loads(compose("config", "--format", "json", secure="1").stdout)
                assert secure["services"]["switchlab"]["environment"]["SWITCHLAB_SECURE_COOKIES"] == "1"
                for bind, selected_port, selected_http, next_port in (
                        (None, None, None, None), (gateway, None, None, 1161),
                        (gateway, "1161", "8080", 161), (gateway, None, None, None)):
                    host_port, http_port = selected_port or "161", selected_http or "8000"
                    compose("up", "--detach", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "60", bind=bind, snmp_port=selected_port, http_port=selected_http)
                    container = compose("ps", "--quiet", "switchlab", bind=bind, snmp_port=selected_port, http_port=selected_http).stdout.strip()
                    info = json.loads(run("docker", "inspect", container).stdout)[0]
                    assert info["Config"]["User"] == "10001:10001"
                    assert info["HostConfig"]["CapDrop"] == ["ALL"] and not info["HostConfig"]["CapAdd"]
                    assert "no-new-privileges:true" in info["HostConfig"]["SecurityOpt"]
                    assert info["HostConfig"]["ReadonlyRootfs"]
                    assert info["HostConfig"]["Sysctls"]["net.ipv4.ip_unprivileged_port_start"] == "161"
                    check_process = """import os; from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
assert os.geteuid()==10001 and int(status['CapEff'],16)==0 and int(status['CapPrm'],16)==0
assert status['NoNewPrivs'].strip()=='1'
assert Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip()=='161'
"""
                    run("docker", "exec", container, "python", "-c", check_process)
                    ports = info["NetworkSettings"]["Ports"]
                    for port, published in (("8000/tcp", http_port), (f"{host_port}/udp", host_port)):
                        assert ports[port] == [{"HostIp": bind or "127.0.0.1", "HostPort": published}]
                    if bind is None:
                        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                        with opener.open("http://127.0.0.1:8000/healthz", timeout=3) as response:
                            assert json.load(response)["ready"]
                    remote_probe(closed=bind is None, snmp_port=int(host_port), next_port=next_port, http_port=int(http_port))
                    if bind is not None:
                        print(json.dumps({f"published_snmp_{host_port}_same_port": "passed",
                                          f"published_http_{http_port}_to_8000": "passed"}))
            finally:
                try:
                    run("docker", "rm", "--force", probe_name, timeout=10, check=False)
                finally:
                    compose("down", "--volumes", "--remove-orphans")
    finally:
        run("docker", "network", "rm", network_name)
    assert Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text() == host_sysctl
    print(json.dumps({"container_only_unprivileged_port_setting": "passed",
                      "compose_default_and_explicit_bindings": "passed",
                      "secure_cookie_environment_forwarding": "passed", "fixture_cleanup": "passed"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-host", help=argparse.SUPPRESS)
    parser.add_argument("--probe-subnet", help=argparse.SUPPRESS)
    parser.add_argument("--probe-snmp-port", type=int, default=161, help=argparse.SUPPRESS)
    parser.add_argument("--probe-http-port", type=int, default=8000, help=argparse.SUPPRESS)
    parser.add_argument("--expect-closed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--next-port", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.probe_host:
        if not args.probe_subnet:
            parser.error("The fixture probe requires --probe-subnet")
        probe(args.probe_host, args.probe_subnet, args.expect_closed, args.probe_snmp_port, args.next_port, args.probe_http_port)
    else:
        check_compose()
