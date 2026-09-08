#!/usr/bin/env python3
"""Generate small finite TLC configurations; see README for their scope."""
from pathlib import Path
ROOT = Path(__file__).resolve().parent
CASES = {
    'Smoke': ('Spec', [1], ['e1'], [1], ['macA'], [1], 0),
    'VlanLifecycle': ('VlanSpec', [1], ['e1'], [1], ['macA'], [1,10], 1),
    'LiveEditRace': ('EditSpec', [1,2], ['e1'], [1], ['macA','macB'], [1], 1),
    'MultiSource': ('MultiSpec', [1], ['e1'], [1,2], ['macA'], [1,10], 1),
    'SharedPort': ('SharedSpec', [1], ['e1','e2'], [1], ['macA'], [1], 1),
    'ActiveLiveness': ('ActiveSpec', [1], ['e1'], [1,2], ['macA'], [1], 1),
    'TrapDrainLiveness': ('DrainSpec', [1], ['e1'], [1], ['macA'], [1], 1),
    'AgingLiveness': ('AgingSpec', [1], ['e1'], [1], ['macA'], [1], 1),
}
def tla_set(xs): return '{' + ', '.join(map(str,xs)) + '}'
def constants(ports, endpoints, slots, macs, vlans, queue=2):
    n = len(endpoints)*len(slots)+2
    return f'''CONSTANTS
    Ports = {tla_set(ports)}
    Endpoints = {tla_set(endpoints)}
    Slots = {tla_set(slots)}
    MACs = {tla_set(macs)}
    VLANs = {tla_set(vlans)}
    Tokens = {tla_set(range(n))}
    PortOrder <- OrderedPorts
    IfIndex <- Indices
    VlanToFdb <- FdbMap
    AgingTicks = 2
    PeriodTicks = 1
    FirstDelayTicks = 1
    QueueLimit = {queue}
    NoPort = NoPort
    NoSource = NoSource
    NoJob = NoJob
    Untagged = Untagged
'''
def main():
    for name,(spec,ps,es,slots,ms,vs,q) in CASES.items():
        text = f'\\* TLC_MODULE TestSwitch\nSPECIFICATION {spec}\n' + constants(ps,es,slots,ms,vs,q)
        text += 'INVARIANTS TypeOK InventoryOK FdbOK JobsOK MibOK TrapsOK\n'
        text += 'PROPERTIES LearningHasSource StaleJobCannotCommit\n'
        if name == 'ActiveLiveness': text += 'PROPERTY StableSourcesProgress\n'
        if name == 'TrapDrainLiveness': text += 'PROPERTY QuietLinksDrain\n'
        if name == 'AgingLiveness': text += 'PROPERTY SilentEventuallyAgesOut\n'
        (ROOT/'configs'/f'{name}.cfg').write_text(text)
if __name__ == '__main__': main()
