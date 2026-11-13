#!/usr/bin/env python3
"""Run bounded TLC checks; an incomplete search is never a pass."""
from __future__ import annotations
import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# The checked equality quotient (SetTransactionsEquality) replaces this graph in normal runs.
DIAGNOSTIC_MODELS = {'SetTransactions'}


def prepare_inputs():
    """Regenerate the ignored checker inputs from their generators."""
    for script in ('make_configs.py', 'tests/make_scenarios.py',
                   'tests/make_access_scenarios.py', 'tests/make_management_scenarios.py'):
        subprocess.run([sys.executable, str(ROOT / script)], cwd=ROOT, check=True, timeout=30)


def config_module(path):
    match = re.search(r'^\\\* TLC_MODULE ([A-Za-z][A-Za-z0-9_]*)$', path.read_text(), re.MULTILINE)
    if not match:
        raise ValueError(f'{path.name}: missing TLC_MODULE comment')
    module = ROOT / (match[1] + '.tla')
    if not module.is_file():
        raise ValueError(f'{path.name}: missing module {module.name}')
    return module.name


def fresh_output(parser, output, prefix):
    """Create a new output directory; never reuse one, so earlier logs and TLC state survive."""
    output = (output or ROOT / 'logs' / f'{prefix}{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}-{os.getpid()}').resolve()
    try:
        output.mkdir(parents=True)
    except FileExistsError:
        parser.error(f'{output} already exists; choose a new --output directory.')
    return output


def find_java(parser, java, jar):
    java = str(java.resolve()) if java else shutil.which('java')
    if not java or not Path(java).is_file() or not jar.is_file():
        parser.error('An existing Java executable and --jar are required.')
    return java


def run_model(cmd, cwd, log, timeout, min_free_bytes):
    """Run one TLC process; return (status, counts)."""
    with log.open('w', encoding='utf-8') as stream:
        process = subprocess.Popen(cmd, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
        deadline, stopped = time.monotonic() + timeout, None
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    stopped = 'TIMEOUT'
                elif shutil.disk_usage(log.parent).free < min_free_bytes:
                    stopped = 'LOW_DISK'
                if stopped:
                    break
                try:
                    process.wait(timeout=min(5, max(.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.kill()
            code = process.wait()
        if stopped:
            stream.write(f'\nRUNNER: {stopped}; exploration incomplete.\n')
    text = log.read_text(errors='replace')
    matches = re.findall(r'([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue', text)
    counts = dict(zip(('generated', 'distinct', 'queue'), (int(n.replace(',', '')) for n in matches[-1]))) if matches else {}
    if stopped:
        return stopped, counts, text
    passed = code == 0 and 'No error has been found' in text and counts.get('queue') == 0
    return ('PASS' if passed else 'FAIL'), counts, text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--prepare-only', action='store_true', help='Regenerate inputs without Java or TLC.')
    parser.add_argument('--java', type=Path, help='Java executable; otherwise use PATH.')
    parser.add_argument('--models', nargs='*', help='Config stems; default: every normal configuration.')
    parser.add_argument('--timeout', type=int, default=600, help='Seconds per model.')
    parser.add_argument('--heap', default='2g')
    parser.add_argument('--output', type=Path, help='New output directory; default: logs/<UTC time>-<pid>. An existing one is refused.')
    parser.add_argument('--min-free-mib', type=int, default=1024, help='Stop a model if free disk space drops below this.')
    args = parser.parse_args()
    prepare_inputs()
    if args.prepare_only:
        return 0
    if args.jar is None:
        parser.error('--jar is required unless --prepare-only is selected.')
    if args.timeout <= 0 or args.min_free_mib < 0:
        parser.error('Use a positive timeout and a non-negative free-space reserve.')
    java = find_java(parser, args.java, args.jar.resolve())
    configs = {p.stem: p for p in (ROOT / 'configs').glob('*.cfg')}
    names = args.models or sorted(configs.keys() - DIAGNOSTIC_MODELS)
    if len(set(names)) != len(names) or any(name not in configs for name in names):
        parser.error('Select unique existing configuration stems.')
    try:
        modules = {name: config_module(configs[name]) for name in names}
    except ValueError as error:
        parser.error(str(error))
    output = fresh_output(parser, args.output, '')
    failed = []
    for name in names:
        cmd = [java, '-XX:+UseParallelGC', f'-Xmx{args.heap}', '-Dutil.ExecutionStatisticsCollector.id=',
               '-cp', str(args.jar.resolve()), 'tlc2.TLC', '-workers', '1', '-seed', '20260907', '-fp', '0',
               '-metadir', str(output / 'states' / name), '-config', f'configs/{name}.cfg', modules[name]]
        print(f'Checking {name}', flush=True)
        status, counts, text = run_model(cmd, ROOT, output / f'tlc-{name}.log', args.timeout, args.min_free_mib * 1024**2)
        print(f'{name}: {status} {counts}', flush=True)
        if status != 'PASS':
            failed.append(name)
            print(text[-3500:], flush=True)
    print(f'{len(names) - len(failed)}/{len(names)} passed' + (f'; not passed: {" ".join(failed)}' if failed else ''))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
