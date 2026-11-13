"""Every TLA+ model names the source files it models, and each of them exists."""
import re
import shutil
import subprocess
import sys
from pathlib import Path

APP = Path(__file__).resolve().parents[1]
SOURCES = re.compile(r"^\\\* Sources: (\S.*)$")


def test_every_model_names_existing_sources(tmp_path):
    spec = tmp_path / "specification"
    shutil.copytree(APP / "specification", spec, ignore=shutil.ignore_patterns("logs", "states"))
    # Generated scenario modules are checked too, so build them in the copy.
    subprocess.run([sys.executable, "run_tlc.py", "--prepare-only"], cwd=spec, check=True,
                   capture_output=True, timeout=60)
    models = sorted(spec.glob("*.tla"))
    assert models
    problems = []
    for model in models:
        lines = model.read_text().splitlines()
        match = SOURCES.match(lines[1]) if len(lines) > 1 and " MODULE " in lines[0] else None
        if match is None:
            problems.append(f"{model.name}: no '\\* Sources:' line right after the MODULE line")
            continue
        problems += [f"{model.name}: {name} does not exist" for name in match[1].split()
                     if not (APP / name).is_file()]
    assert not problems, "\n".join(problems)
