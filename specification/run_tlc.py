#!/usr/bin/env python3
"""Run finite TLC checks, recording commands, hashes and outcomes."""
from __future__ import annotations
import argparse, hashlib, json, re, shutil, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--jar', required=True, type=Path)
    p.add_argument('--models', nargs='*', help='Config stems; default: every supplied config.')
    p.add_argument('--timeout', type=int, default=180, help='Seconds per model; timeout is not a pass.')
    p.add_argument('--heap', default='2g')
    a = p.parse_args()
    java, jar = shutil.which('java'), a.jar.resolve()
    if not java or not jar.is_file(): p.error('Java on PATH and an existing --jar are required.')
    logs = ROOT/'logs'; logs.mkdir(exist_ok=True)
    names = a.models or [x.stem for x in sorted((ROOT/'configs').glob('*.cfg'))]
    results = []
    for name in names:
        if not (ROOT/'configs'/f'{name}.cfg').is_file(): p.error(f'Unknown configuration: {name}')
        module = 'ReadAccess.tla' if name == 'ReadAccess' else ('Scenarios.tla' if name.startswith('Scenario') else 'TestSwitch.tla')
        cmd = [java, '-XX:+UseParallelGC', f'-Xmx{a.heap}',
               '-Dutil.ExecutionStatisticsCollector.id=', '-cp', str(jar), 'tlc2.TLC',
               '-workers', '1', '-seed', '20260907', '-fp', '0',
               '-metadir', str(ROOT/'states'/name), '-config', f'configs/{name}.cfg', module]
        start = time.monotonic(); timed_out = False; code = None
        print(f'Checking {name}', flush=True)
        log = logs/f'tlc-{name}.log'
        with log.open('w', encoding='utf-8') as out:
            try:
                run = subprocess.run(cmd, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT, timeout=a.timeout)
                code = run.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                out.write('\nRUNNER: TIMEOUT; exploration incomplete.\n')
        text = log.read_text(errors='replace')
        good = code == 0 and 'No error has been found' in text
        matches = re.findall(r'([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue',text)
        counts = dict(zip(('generated','distinct','queue'),map(lambda n:int(n.replace(',','')),matches[-1]))) if matches else {}
        result = dict(model=name, status='PASS' if good else ('TIMEOUT' if timed_out else 'FAIL'),
                      returncode=code, elapsed_seconds=round(time.monotonic()-start,3),
                      counts=counts, command=cmd, log=str(log.relative_to(ROOT)))
        results.append(result)
        print(f'{name}: {result["status"]} {counts}',flush=True)
        if not good: print(text[-3500:],flush=True)
        (logs/f'result-{name}.json').write_text(json.dumps(result,indent=2)+'\n')
    summary = dict(jar_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(), results=results)
    (logs/'last-run.json').write_text(json.dumps(summary,indent=2)+'\n')
    return 0 if all(x['status']=='PASS' for x in results) else 1
if __name__ == '__main__': sys.exit(main())
