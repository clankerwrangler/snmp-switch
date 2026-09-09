#!/usr/bin/env python3
"""Run finite TLC checks with separate output, exact inputs, and bounded outcomes."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# The certified token VIEW replaces this unreduced reference in normal checks.
DIAGNOSTIC_MODELS = {'SetTransactions'}
NORMAL_REQUIRED_MODELS = {'SetTokenEquivalence', 'SetTransactionsEquality'}


def prepare_inputs():
    """Regenerate local checker inputs from their tracked source owners."""
    for script in ('make_configs.py', 'tests/make_scenarios.py',
                   'tests/make_access_scenarios.py', 'tests/make_management_scenarios.py'):
        subprocess.run([sys.executable, str(ROOT / script)], cwd=ROOT,
                       check=True, timeout=30)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_hashes():
    paths = list(ROOT.glob('*.tla')) + list((ROOT / 'configs').glob('*.cfg'))
    return {str(p.relative_to(ROOT)): sha256(p) for p in sorted(paths)}


def config_module(path):
    match = re.search(r'^\\\* TLC_MODULE ([A-Za-z][A-Za-z0-9_]*)$', path.read_text(), re.MULTILINE)
    if not match:
        raise ValueError(f'{path.name}: missing TLC_MODULE comment')
    module = ROOT / (match[1] + '.tla')
    if not module.is_file():
        raise ValueError(f'{path.name}: missing module {module.name}')
    return module.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--prepare-only', action='store_true',
                        help='Regenerate local inputs without Java or TLC.')
    parser.add_argument('--java', type=Path, help='Task-local Java executable; otherwise use PATH.')
    parser.add_argument('--models', nargs='*', help='Config stems; default: normal suite. Select the unreduced diagnostic explicitly.')
    parser.add_argument('--timeout', type=int, default=600, help='Positive seconds per model; an incomplete search is not a pass.')
    parser.add_argument('--batch-timeout', type=int, default=3600, help='Total seconds, including all models.')
    parser.add_argument('--heap', default='2g')
    parser.add_argument('--output', type=Path, default=ROOT / 'logs' / 'current',
                        help='Fresh result directory; an existing directory is never overwritten.')
    parser.add_argument('--checkpoint-minutes', type=int, default=30)
    parser.add_argument('--max-state-mib', type=int, help='Abort if this run state directory exceeds the budget.')
    parser.add_argument('--min-free-mib', type=int, default=0, help='Abort if output filesystem free space falls below this reserve.')
    args = parser.parse_args()
    if args.prepare_only:
        prepare_inputs()
        return 0
    if args.jar is None:
        parser.error('--jar is required unless --prepare-only is selected.')
    java = str(args.java.resolve()) if args.java else shutil.which('java')
    jar = args.jar.resolve()
    if not java or not Path(java).is_file() or not jar.is_file():
        parser.error('An existing Java executable and --jar are required.')
    if args.timeout <= 0 or args.batch_timeout <= 0:
        parser.error('Use positive model and batch timeouts.')
    if args.checkpoint_minutes <= 0 or args.min_free_mib < 0 or (args.max_state_mib is not None and args.max_state_mib <= 0):
        parser.error('Checkpoint interval and state budget must be positive; free-space reserve cannot be negative.')
    prepare_inputs()
    configs = {p.stem: p for p in (ROOT / 'configs').glob('*.cfg')}
    if args.models:
        names = args.models
    else:
        missing = NORMAL_REQUIRED_MODELS - configs.keys()
        if missing:
            parser.error('Normal suite requires replacement configs: ' + ', '.join(sorted(missing)))
        names = sorted(configs.keys() - DIAGNOSTIC_MODELS)
    if len(set(names)) != len(names) or any(name not in configs for name in names):
        parser.error('Select unique existing configuration stems.')
    try:
        modules = {name: config_module(configs[name]) for name in names}
    except ValueError as error:
        parser.error(str(error))
    output = args.output.resolve()
    if output.exists():
        parser.error('--output must be a new directory; preserve prior run evidence.')
    output.mkdir(parents=True)
    inputs = input_hashes()
    version = subprocess.run([java, '-version'], capture_output=True, text=True, timeout=15)
    results = []
    summary = dict(status='RUNNING', jar_sha256=sha256(jar), java=java,
                   java_version=version.stdout + version.stderr, java_version_returncode=version.returncode,
                   formal_input_sha256=inputs, runner_sha256=sha256(Path(__file__)),
                   results=results, timeout_seconds=args.timeout, batch_timeout_seconds=args.batch_timeout,
                   max_state_mib=args.max_state_mib, min_free_mib=args.min_free_mib)
    summary_path = output / 'verification.json'
    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    batch_start = time.monotonic()
    for name in names:
        remaining = args.batch_timeout - (time.monotonic() - batch_start)
        if remaining <= 0:
            results.append(dict(model=name, status='NOT_RUN', reason='batch timeout'))
            continue
        cmd = [java, '-XX:+UseParallelGC', f'-Xmx{args.heap}',
               '-Dutil.ExecutionStatisticsCollector.id=', '-cp', str(jar), 'tlc2.TLC',
               '-checkpoint', str(args.checkpoint_minutes), '-workers', '1', '-seed', '20260907', '-fp', '0',
               '-metadir', str(output / 'states' / name), '-config', f'configs/{name}.cfg', modules[name]]
        log = output / f'tlc-{name}.log'
        print(f'Checking {name}', flush=True)
        start = time.monotonic()
        code, timed_out, resource_failure = None, False, None
        with log.open('w', encoding='utf-8') as stream:
            process = subprocess.Popen(cmd, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
            deadline = start + min(args.timeout, remaining)
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    state_root = output / 'states'
                    state_bytes = 0
                    if state_root.exists():
                        for path in state_root.rglob('*'):
                            try:
                                if path.is_file() and not path.is_symlink():
                                    state_bytes += path.stat().st_size
                            except FileNotFoundError:
                                pass  # TLC can rename checkpoint files during this measurement.
                    free_bytes = shutil.disk_usage(output).free
                    if args.max_state_mib is not None and state_bytes > args.max_state_mib * 1024**2:
                        resource_failure = 'state storage budget exceeded'
                        break
                    if free_bytes < args.min_free_mib * 1024**2:
                        resource_failure = 'filesystem reserve breached'
                        break
                    try:
                        process.wait(timeout=min(5, max(.001, deadline-time.monotonic())))
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                if process.poll() is None:
                    process.kill()
                code = process.wait()
            if timed_out:
                stream.write('\nRUNNER: TIMEOUT; exploration incomplete.\n')
            if resource_failure:
                stream.write(f'\nRUNNER: RESOURCE_LIMIT: {resource_failure}; exploration incomplete.\n')
        text = log.read_text(errors='replace')
        matches = re.findall(r'([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue', text)
        counts = dict(zip(('generated', 'distinct', 'queue'), (int(n.replace(',', '')) for n in matches[-1]))) if matches else {}
        unchanged = input_hashes() == inputs
        good = code == 0 and not timed_out and not resource_failure and 'No error has been found' in text and counts.get('queue') == 0 and unchanged
        result = dict(model=name, module=modules[name], status='PASS' if good else ('TIMEOUT' if timed_out else ('RESOURCE_LIMIT' if resource_failure else 'FAIL')),
                      returncode=code, elapsed_seconds=round(time.monotonic() - start, 3), counts=counts,
                      command=cmd, log=log.name, log_sha256=sha256(log), inputs_unchanged=unchanged, resource_failure=resource_failure)
        results.append(result)
        (output / f'result-{name}.json').write_text(json.dumps(result, indent=2) + '\n')
        summary_path.write_text(json.dumps(summary, indent=2) + '\n')
        print(f'{name}: {result["status"]} {counts}', flush=True)
        if not good:
            print(text[-3500:], flush=True)
        if not unchanged:
            break
    summary['status'] = 'PASS' if len(results) == len(names) and all(r['status'] == 'PASS' for r in results) else 'FAIL'
    summary['elapsed_seconds'] = round(time.monotonic() - batch_start, 3)
    summary['formal_inputs_unchanged'] = input_hashes() == inputs
    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
