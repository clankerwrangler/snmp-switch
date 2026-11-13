#!/usr/bin/env python3
"""Check that each deliberate model defect is rejected by a violated property."""
from __future__ import annotations
import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_tlc import config_module, find_java, prepare_inputs
MUTATIONS = [('accept_obsolete_job', 'ScenarioAttachmentABA', 'Switch.tla', 'accepted == ValidJob(s, sk, j) /\\ Admitted(s, j.port, j.vlan)', 'accepted == CanEmit(s, sk) /\\ Admitted(s, j.port, j.vlan)'), ('flush_whole_port_on_vlan_edit', 'ScenarioSelectiveAndPvid', 'Switch.tla', 'Mutate([s EXCEPT !.pvid[p] = native, !.allowed[p] = members,\n                              !.untagged[p] = tags], {}, {p})', 'Mutate([s EXCEPT !.pvid[p] = native, !.allowed[p] = members,\n                              !.untagged[p] = tags,\n                              !.fdb = [k \\in FdbKeys |-> IF s.fdb[k].port = p THEN EmptyEntry ELSE s.fdb[k]]], {}, {p})'), ('omit_vlan1_admission_on_fallback', 'ScenarioDeleteFallback', 'Switch.tla', '(IF s.pvid[p] = v THEN {1} ELSE {})', '{}'), ('allow_unauthorized_set', 'SetAuthorization', 'SetTransactions.tla', 'ELSE IF ~auth THEN Reject("authorizationError",0)', 'ELSE IF FALSE THEN Reject("authorizationError",0)'), ('publish_failed_set_prefix', 'SetAtomicMixed', 'SetTransactions.tla', 'ELSE IF error.status # "noError" THEN Reject(error.status,error.index)', 'ELSE IF error.status # "noError" THEN\n               /\\ s\' = [s EXCEPT !.admin[P0] = FALSE]\n               /\\ result\' = [status |-> error.status,index |-> error.index] /\\ pending\' = NoPdu\n               /\\ UNCHANGED <<accessvars,registration,gate,activation>>'), ('entity_alias_uses_bridge_port', 'EntityInventory', 'Switch.tla', '[logicalIndex |-> 0, pointer |-> <<"ifIndex", IfIndex[PhysicalPort(i)]>>]]', '[logicalIndex |-> 0, pointer |-> <<"ifIndex", PhysicalPort(i)>>]]')]

MUTATIONS += [
    ('shared_group_misses_second_member', 'GroupQueuedSet', 'GroupedAccess.tla', 'IF changed /\\ c \\in Affected(x) THEN Tx!Fresh(Tx!UsedRegistration(c)) ELSE registration[c]', 'IF changed /\\ c = C1 /\\ c \\in Affected(x) THEN Tx!Fresh(Tx!UsedRegistration(c)) ELSE registration[c]'),
    ('migration_shares_policy_owner', 'GroupOwnership', 'GroupedAccess.tla', 'MigrationGroup(c) == IF c = C1 THEN G1 ELSE G2', 'MigrationGroup(c) == G1'),
    ('failed_group_save_publishes_prefix', 'GroupOwnership', 'GroupedAccess.tla', "cfg' = IF accepted THEN x ELSE cfg", "cfg' = IF accepted THEN x ELSE [cfg EXCEPT !.groups = x.groups]"),
]

MUTATIONS += [
    ('radius_stale_accept', 'RadiusAuthorization', 'RadiusAuthorization.tla', 'current == pending[c] = generation[c] /\\ mode = "auto" /\\ link', 'current == TRUE /\\ mode = "auto" /\\ link'),
    ('radius_duplicate_reexecution', 'RadiusDynamicAuthorization', 'RadiusDynamicAuthorization.tla', 'IF reply # "none"\n       THEN UNCHANGED <<session, vlan, reply>>', 'IF FALSE\n       THEN UNCHANGED <<session, vlan, reply>>'),
    ('radius_partial_coa_on_nak', 'RadiusDynamicAuthorization', 'RadiusDynamicAuthorization.tla', 'IF Applicable /\\ c \\in Matched\n                  THEN', 'IF c \\in Matched /\\ (Applicable \\/ (operation = "coa" /\\ c \\in canApply /\\ requestedVlan \\in VLANs))\n                  THEN'),
]

MUTATIONS += [('running_apply_autosaves', 'StartupLifecycle', 'StorageOutcomes.tla', '[] OTHER -> store.durable\n    IN [published', '[] operation \\in {"api","set"} -> [store.durable EXCEPT !.startup = published.policy]\n          [] OTHER -> store.durable\n    IN [published'), ('mixed_lab_autosaves_policy', 'StartupLifecycle', 'StorageOutcomes.tla', 'operation = "lab" -> [store.durable EXCEPT !.lab = ReplacementLab]', 'operation = "lab" -> [store.durable EXCEPT !.lab = ReplacementLab, !.startup = published.policy]'), ('startup_resurrects_hardware', 'StartupLifecycle', 'StorageOutcomes.tla', 'RebootLab == store.durable.lab', 'RebootLab == [store.durable.lab EXCEPT !.ports = @ \\cup DOMAIN store.saved]'), ('storage_fault_gate_removed', 'StorageRecovery', 'StorageOutcomes.tla', 'CommitAllowed == Gate', 'CommitAllowed == store.open /\\ store.active')]

MUTATIONS += [('failed_commit_publishes_event', 'EventHistory', 'SetResponseScenarios.tla', 'EventPublishedStore(committed,candidate) == committed', 'EventPublishedStore(committed,candidate) ==\n    IF scenario = "rolledBack" THEN [committed EXCEPT\n        !.published = EventWithHistory(@,candidate.published.history)] ELSE committed')]

MUTATIONS += [
    ('skip_affected_port_relations', 'SetVlanFallback', 'SetTransactions.tla',
     r'p \in AffectedPorts(x) : IllegalVlans(p,x) = {}', r'p \in {} : IllegalVlans(p,x) = {}'),
    ('ignore_disabled_target_reference', 'AccessLifecycle', 'ReadAccess.tla',
     r'TargetsUsing(c) == {t \in Targets : targetCredential[t] = c}',
     r'TargetsUsing(c) == {t \in targetEnabled : targetCredential[t] = c}'),
    ('audit_resource_projection', 'AccessLifecycle', 'AccessScenarios.tla',
     "audits' = IF full THEN audits + 1 ELSE audits", "audits' = audits + 1"),
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', required=True, type=Path)
    parser.add_argument('--java', type=Path)
    parser.add_argument('--mutations', nargs='+', choices=[m[0] for m in MUTATIONS],
                        help='Selected controls; default: all current controls.')
    parser.add_argument('--output', type=Path, help='Output directory; default: logs/mutations-<UTC time>.')
    args = parser.parse_args()
    jar = args.jar.resolve()
    java = find_java(parser, args.java, jar)
    output = (args.output or ROOT / 'logs' / time.strftime('mutations-%Y%m%dT%H%M%SZ', time.gmtime())).resolve()
    prepare_inputs()
    output.mkdir(parents=True, exist_ok=True)
    missed = []
    selected = [m for m in MUTATIONS if not args.mutations or m[0] in args.mutations]
    for name, config, module, before, after in selected:
        original = (ROOT / module).read_text()
        if original.count(before) != 1:
            raise RuntimeError(f'{name}: mutation anchor is not unique')
        with tempfile.TemporaryDirectory(prefix='switch-mutation-', dir=output) as td:
            work = Path(td)
            for source in ROOT.glob('*.tla'):
                shutil.copy2(source, work / source.name)
            (work / module).write_text(original.replace(before, after))
            cfg = ROOT / 'configs' / f'{config}.cfg'
            shutil.copy2(cfg, work / 'check.cfg')
            cmd =[java, '-Xmx1g', '-Dutil.ExecutionStatisticsCollector.id=', '-cp', str(jar),
                   'tlc2.TLC', '-workers', '1', '-seed', '20260907', '-fp', '0',
                   '-config', 'check.cfg', config_module(cfg)]
            try:
                run = subprocess.run(cmd, cwd=work, text=True, capture_output=True, timeout=60)
                text = run.stdout + run.stderr
                detected = run.returncode != 0 and any(marker in text for marker in
                    ('is violated', 'Temporal properties were violated'))
                status = 'DETECTED' if detected else 'NOT_DETECTED'
            except subprocess.TimeoutExpired:
                text, detected, status = 'TIMEOUT: no rejection established.\n', False, 'TIMEOUT'
            (output / f'mutation-{name}.log').write_text(text)
            if not detected:
                missed.append(name)
            print(f'{name}: {status}', flush=True)
    print(f'{len(selected) - len(missed)}/{len(selected)} detected' + (f'; missed: {" ".join(missed)}' if missed else ''))
    return 1 if missed else 0
if __name__ == '__main__':
    raise SystemExit(main())
