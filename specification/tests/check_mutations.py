#!/usr/bin/env python3
"""Confirm selected specification defects are rejected by existing TLC checks."""
from __future__ import annotations
import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    (
        'accept_obsolete_job', 'ScenarioAttachmentABA',
        'accepted == ValidJob(s, sk, j) /\\ Admitted(s, j.port, j.vlan)',
        'accepted == CanEmit(s, sk) /\\ Admitted(s, j.port, j.vlan)',
    ),
    (
        'flush_whole_port_on_vlan_edit', 'ScenarioSelectiveAndPvid',
        'Mutate([s EXCEPT !.pvid[p] = native, !.allowed[p] = members], {}, {p})',
        '''Mutate([s EXCEPT !.pvid[p] = native, !.allowed[p] = members,
            !.fdb = [k \\in FdbKeys |->
                IF s.fdb[k].port = p THEN EmptyEntry ELSE s.fdb[k]]], {}, {p})''',
    ),
    (
        'omit_vlan1_admission_on_fallback', 'ScenarioDeleteFallback',
        '(IF s.pvid[p] = v THEN {1} ELSE {})', '{}',
    ),
]

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', required=True, type=Path)
    args = parser.parse_args()
    java, jar = shutil.which('java'), args.jar.resolve()
    if not java or not jar.is_file():
        parser.error('Java on PATH and an existing --jar are required.')
    results = []
    (ROOT/'logs').mkdir(exist_ok=True)
    original = (ROOT/'Switch.tla').read_text()
    for name, config, before, after in MUTATIONS:
        if original.count(before) != 1:
            raise RuntimeError(f'{name}: mutation anchor is not unique')
        with tempfile.TemporaryDirectory(prefix='switch-mutation-') as td:
            work = Path(td)
            for source in ROOT.glob('*.tla'):
                shutil.copy2(source, work/source.name)
            (work/'Switch.tla').write_text(original.replace(before, after))
            shutil.copy2(ROOT/'configs'/f'{config}.cfg', work/'check.cfg')
            cmd = [java, '-Xmx1g', '-Dutil.ExecutionStatisticsCollector.id=',
                   '-cp', str(jar), 'tlc2.TLC', '-workers', '1', '-seed', '20260907',
                   '-fp', '0', '-config', 'check.cfg', 'Scenarios.tla']
            try:
                run = subprocess.run(cmd, cwd=work, text=True, capture_output=True, timeout=60)
                text = run.stdout + run.stderr
                # Parse/type errors and timeouts do NOT count as detected behavioral defects.
                detected = run.returncode != 0 and any(marker in text for marker in
                    ('is violated', 'Temporal properties were violated'))
                code = run.returncode
            except subprocess.TimeoutExpired:
                text, detected, code = 'TIMEOUT: no behavioral rejection established.\n', False, None
            (ROOT/'logs'/f'mutation-{name}.log').write_text(text)
            result = {'mutation':name, 'scenario':config, 'behavioral_defect_detected':detected,
                      'returncode':code, 'log':f'logs/mutation-{name}.log'}
            results.append(result)
            print(f'{name}: {"DETECTED" if detected else "NOT ESTABLISHED"}', flush=True)
    (ROOT/'logs'/'mutation-results.json').write_text(json.dumps(results, indent=2)+'\n')
    return 0 if all(r['behavioral_defect_detected'] for r in results) else 1

if __name__ == '__main__':
    raise SystemExit(main())
