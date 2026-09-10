"""Build the pinned Linux EAP peer; inputs and notices stay beside this script."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

inputs = Path(__file__).resolve().parent
work, output = map(Path, sys.argv[1:])
work.mkdir(parents=True, exist_ok=False)
output.mkdir(parents=True, exist_ok=False)
manifest = json.loads((inputs / "source.json").read_text())
archive = work / "wpa_supplicant-2.12.tar.gz"
request = urllib.request.Request(manifest["url"], headers={"User-Agent": "SwitchLab-source-build"})
with urllib.request.urlopen(request, timeout=30) as response:
    origin = urllib.parse.urlsplit(response.url)
    if origin.scheme != "https" or origin.hostname != "w1.fi":
        raise RuntimeError("Unexpected upstream source redirect")
    content = response.read(8388609)
if len(content) > 8388608 or hashlib.sha256(content).hexdigest() != manifest["sha256"]:
    raise RuntimeError("Upstream archive digest mismatch")
archive.write_bytes(content)
with tarfile.open(archive, "r:gz") as source:
    source.extractall(work, filter="data")
root = work / "wpa_supplicant-2.12"
if '#define VERSION_STR "2.12"' not in (root / "src/common/version.h").read_text():
    raise RuntimeError("Unexpected upstream version")
for name, expected in sorted(manifest["patches"].items()):
    patch = inputs / name
    if patch.parent != inputs or hashlib.sha256(patch.read_bytes()).hexdigest() != expected:
        raise RuntimeError("Patch digest mismatch")
    with patch.open("rb") as source:
        subprocess.run(["patch", "-p1", "--batch", "--forward", "--fuzz=0"], cwd=root, stdin=source, check=True, timeout=30)
config = inputs / "eapol_test.config"
if hashlib.sha256(config.read_bytes()).hexdigest() != manifest["config_sha256"]:
    raise RuntimeError("Native configuration digest mismatch")
shutil.copyfile(config, root / "wpa_supplicant/.config")
subprocess.run(["make", "-j2", "eapol_test"], cwd=root / "wpa_supplicant", check=True, timeout=480)
binary = output / "eapol_test"
shutil.copyfile(root / "wpa_supplicant/eapol_test", binary)
binary.chmod(0o755)
subprocess.run(["strip", str(binary)], check=True, timeout=15)
linkage = subprocess.check_output(["ldd", str(binary)], text=True, timeout=15)
if "not found" in linkage or "libssl.so" not in linkage or "libcrypto.so" not in linkage:
    raise RuntimeError("Missing native runtime linkage")
packages = set()
for line in linkage.splitlines():
    if not any(name in line for name in ("libssl.so", "libcrypto.so")):
        continue
    library = Path(line.split("=>", 1)[1].split()[0]).resolve()
    owner = subprocess.check_output(["dpkg-query", "-S", str(library)], text=True, timeout=10).split(": ", 1)[0]
    pin = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}=${Version}", owner], text=True, timeout=10)
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+(?::[a-z0-9]+)?=[A-Za-z0-9.+:~_-]+", pin):
        raise RuntimeError("Unexpected runtime package identity")
    packages.add(pin)
(output / "runtime-packages.txt").write_text("\n".join(sorted(packages)) + "\n")
receipt = {"interface": "SLR1", "upstream": manifest["version"], "security_fix": manifest["security_fix"],
    "managed_patch_sha256": manifest["patches"]["0005-switchlab-managed-result.patch"],
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "source_sha256": manifest["sha256"], "runtime_packages": sorted(packages)}
(output / "eapol_test.switchlab.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
notices = output / "notices"
notices.mkdir()
for name in ["COPYING", "README", "source.json", "eapol_test.config", *manifest["patches"]]:
    shutil.copyfile(inputs / name, notices / name)
(notices / "linkage.txt").write_text(linkage)
(notices / "build-packages.txt").write_text(subprocess.check_output(["dpkg-query", "-W"], text=True, timeout=15))
print(json.dumps(receipt, sort_keys=True))
