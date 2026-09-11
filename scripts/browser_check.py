"""Run the maintained browser flow against an owned synthetic loopback app.

Requires Linux (child subreaper), installed project/test Python dependencies,
Node, and `pnpm --dir tests/browser install --frozen-lockfile --ignore-scripts`.
The matching Playwright Chromium must already be installed.
"""
import argparse
import ctypes
import datetime
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BROWSER_SCRIPT = ROOT / "tests/ui-smoke.cjs"
SERVER_SCRIPT = ROOT / "tests/browser_server.py"


def children():
    # PR_SET_CHILD_SUBREAPER makes orphaned Chromium descendants ours to reap.
    records = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            records[int(entry.name)] = (int(fields[1]), fields[19])
        except (OSError, IndexError, ValueError):
            continue
    owned = {os.getpid()}
    while True:
        added = {pid for pid, (parent, _) in records.items() if parent in owned} - owned
        if not added:
            return {pid: records[pid][1] for pid in owned if pid != os.getpid()}
        owned.update(added)


def stop_children(processes):
    def reap():
        for proc in processes:
            proc.poll()
        while True:
            try:
                if os.waitpid(-1, os.WNOHANG)[0] == 0:
                    break
            except ChildProcessError:
                break

    for sig, budget in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        end = time.monotonic() + budget
        while True:
            owned = children()
            for pid, start in owned.items():
                try:
                    # Do not signal a recycled PID.
                    current = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                    if current == start:
                        os.kill(pid, sig)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            reap()
            if not children():
                return True
            if time.monotonic() >= end:
                break
            time.sleep(.05)
    return not children()


def material(directory):
    from cryptography import x509
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    (directory / "config.key").write_bytes(Fernet.generate_key())
    private = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-radius")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(private.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private, hashes.SHA256()))
    (directory / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "client.key").write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"synthetic-certificate-password")))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("full", "ui"), default="full")
    parser.add_argument("--timeout", type=int, default=165, help="Work budget, 1..165 seconds; cleanup adds at most 10")
    parser.add_argument("--artifacts", type=Path, help="New directory for synthetic screenshots and result; never fixture keys or DB")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 165:
        parser.error("timeout must be 1..165")
    if sys.platform != "linux" or ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("Linux child-subreaper containment is required")
    os.umask(0o077)
    output = args.artifacts.resolve() if args.artifacts else None
    if output:
        output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {"mode": args.mode, "ber_history": "not_run", "passed": False,
              "snmp_enabled": False, "identity": None, "external_radius": False, "udp": False}
    processes = []
    listener = None
    port = None
    temporary = tempfile.TemporaryDirectory(prefix="switchlab-browser-")
    directory = Path(temporary.name)
    previous = {}

    def interrupted(signum, frame):
        raise TimeoutError() if signum == signal.SIGALRM else InterruptedError()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        previous[sig] = signal.signal(sig, interrupted)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        material(directory)
        # Start from an allowlist, never inherit app configuration, proxy, Python
        # injection, live credentials, or a target URL from the caller.
        env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
        env.update(HOME=str(directory), TMPDIR=str(directory), XDG_CACHE_HOME=str(directory / "cache"),
                   PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT),
                   SWITCHLAB_DB=str(directory / "state.db"), SWITCHLAB_KEY_FILE=str(directory / "config.key"),
                   SWITCHLAB_PORT_COUNT="8")
        if args.mode == "full":
            seed = subprocess.Popen([sys.executable, str(ROOT / "tests/browser_seed.py"),
                                     str(directory / "events.json")], env=env, cwd=ROOT, start_new_session=True)
            processes.append(seed)
            if seed.wait() != 0:
                raise RuntimeError("BER fixture failed")
            fixture = json.loads((directory / "events.json").read_text())
            assert fixture["real_supported_ber"] and fixture["INET_socket_attempts"] == 0
            result["ber_history"] = "seeded"
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        result.update(host="127.0.0.1", port=port)
        server = subprocess.Popen([sys.executable, str(SERVER_SCRIPT), str(listener.fileno())],
                                  pass_fds=[listener.fileno()], env=env, cwd=ROOT, start_new_session=True)
        processes.append(server)
        listener.close()
        url = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError("Synthetic server exited")
            try:
                with opener.open(url + "/healthz", timeout=.3) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError("Synthetic server readiness failed")
        browser_env = env.copy()
        # Resolve the caller's tool cache before giving Chromium a synthetic HOME.
        browser_env["PLAYWRIGHT_BROWSERS_PATH"] = os.environ.get(
            "PLAYWRIGHT_BROWSERS_PATH",
            str(Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "ms-playwright"))
        # These are tool locations only, not application settings or a live URL.
        for key in ("SWITCHLAB_BROWSER_LIBRARY_PATH", "SWITCHLAB_BROWSER_FONTCONFIG"):
            if key in os.environ:
                browser_env[key] = os.environ[key]
        browser_env.update(NODE_PATH=str(ROOT / "tests/browser/node_modules"),
                           SWITCHLAB_TEST_URL=url, SWITCHLAB_TEST_PASSWORD="synthetic-fixture",
                           SWITCHLAB_TEST_COVERAGE=args.mode, SWITCHLAB_TEST_RADIUS_CA_FILE=str(directory / "ca.pem"),
                           SWITCHLAB_TEST_RADIUS_KEY_FILE=str(directory / "client.key"),
                           SWITCHLAB_TEST_SCREENSHOTS=str(output) if output else "0")
        if args.mode == "full":
            browser_env["SWITCHLAB_TEST_EVENT_FIXTURE"] = str(directory / "events.json")
        browser = subprocess.Popen(["node", str(BROWSER_SCRIPT)], env=browser_env, cwd=ROOT, start_new_session=True)
        processes.append(browser)
        result["browser_exit"] = browser.wait()
        result["passed"] = result["browser_exit"] == 0
        if result["passed"] and args.mode == "full":
            result["ber_history"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        result["passed"] = False
        result["failure"] = type(exc).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if listener:
            listener.close()
        result["children_exited"] = stop_children(processes)
        if port is not None:
            with socket.socket() as probe:
                probe.settimeout(.2)
                result["port_closed"] = probe.connect_ex(("127.0.0.1", port)) != 0
        else:
            result["port_closed"] = True
        temporary.cleanup()
        result["synthetic_state_removed"] = not directory.exists()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        result["passed"] = result["passed"] and all(result[k] for k in ("children_exited", "port_closed", "synthetic_state_removed"))
        if output:
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
