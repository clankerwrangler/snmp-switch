"""The model runners never write into an existing output directory."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("runner", ["run_tlc.py", "tests/check_mutations.py"])
def test_runner_refuses_existing_output(tmp_path, runner):
    spec = tmp_path / "specification"
    shutil.copytree(APP / "specification", spec, ignore=shutil.ignore_patterns("logs", "states"))
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"")
    output = tmp_path / "earlier-run"
    output.mkdir()
    log = output / "tlc-Smoke.log"
    log.write_text("earlier result\n")
    run = subprocess.run([sys.executable, runner, "--java", sys.executable, "--jar", str(jar),
                          "--output", str(output)], cwd=spec, capture_output=True, text=True, timeout=60)
    assert run.returncode == 2 and "already exists" in run.stderr
    assert [p.name for p in output.iterdir()] == ["tlc-Smoke.log"] and log.read_text() == "earlier result\n"
