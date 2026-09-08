#!/usr/bin/env python3
"""Generate deterministic TLC regression traces using the real Switch actions."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from make_configs import constants
cases=[]
class Case:
    def __init__(self,name): self.name=name; self.steps=[]; self.checks=[]; cases.append(self)
    def add(self,action,check=None):
        self.steps.append(action)
        if check: self.checks.append((len(self.steps),check))
        return self
    def check(self,expr): self.checks.append((len(self.steps),expr)); return self
    def tick(self,keys,manual=False):
        self.add('ManualTick' if manual else 'AutoTick')
        for key in keys: self.add(f'QueueActivity({key})').add(f'ApplyActivity({key})')
        return self.add('FinishStep')
K1='<<E1,1>>'; K2='<<E1,2>>'; K3='<<E1,3>>'; K4='<<E2,1>>'
def defs(a='NoSource',b='NoSource',c='NoSource'): return f'D({a},{b},{c})'
def src(m='M1',v='Untagged'):return f'Src({m},{v})'
def setup(c,defs1,port=1):
    return c.add(f'CreateEndpoint(E1,{defs1})').add('SetActive(E1,TRUE)').add(f'Connect(E1,{port})')

a=Case('LiveEdit')
a.add('CreateVlan(10)').add('CreateVlan(20)').add('ConfigurePort(1,10,{10,20})')
setup(a,defs(src())).tick([K1]).check('Present(10,M1,1)')
a.add(f'EditEndpoint(E1,{defs(src("M2","20"))})','Present(10,M1,1) /\\ Len(s.traps)=1')
a.tick([K1]).check('Present(10,M1,1) /\\ Present(20,M2,1) /\\ Len(s.traps)=1')
a.tick([K1]).check('Absent(10,M1) /\\ Present(20,M2,1)')

b=Case('DeleteFallback')
b.add('CreateVlan(10)').add('CreateVlan(30)').add('ConfigurePort(1,10,{10,30})').add('SetLegacy(10)')
setup(b,defs(src(),src('M2','10'),src('M3','30'))).tick([K1,K2,K3])
b.add('DeleteVlan(10)', 's.pvid[1]=1 /\\ s.allowed[1]={1,30} /\\ s.legacy=1 /\\ '
      'Absent(10,M1) /\\ Absent(10,M2) /\\ Present(30,M3,1) /\\ '
      's.fdb[<<VlanToFdb[30],M3>>].ttl=AgingTicks /\\ s.sources[<<E1,2>>].tag=10 /\\ Len(s.traps)=1')
b.tick([K1,K2,K3]).check('Present(1,M1,1) /\\ Absent(1,M2) /\\ Absent(10,M2) /\\ Present(30,M3,1)')
b.check('~ENABLED DeleteVlan(1)')

c=Case('SelectiveAndPvid')
for v in [10,20,30]:c.add(f'CreateVlan({v})')
c.add('ConfigurePort(1,10,{10,20,30})')
setup(c,defs(src(),src('M2','30'))).tick([K1,K2])
c.add('ConfigurePort(1,20,{10,20,30})','Present(10,M1,1) /\\ Present(30,M2,1) /\\ s.fdb[<<VlanToFdb[10],M1>>].ttl=AgingTicks')
c.tick([K1,K2]).check('Present(10,M1,1) /\\ Present(20,M1,1)')
c.add('ConfigurePort(1,20,{10,20})','Present(10,M1,1) /\\ Present(20,M1,1) /\\ Absent(30,M2) /\\ Len(s.traps)=1')

d=Case('StaleEdit')
setup(d,defs(src())).add('AutoTick').add(f'QueueActivity({K1})')
d.add(f'EditEndpoint(E1,{defs(src("M2"))})').add(f'ApplyActivity({K1})','Live(s)={}')
d.add('FinishStep').tick([K1]).check('Absent(1,M1) /\\ Present(1,M2,1)')

e=Case('AttachmentABA')
setup(e,defs(src())).add('AutoTick').add(f'QueueActivity({K1})')
e.add('Move(E1,2)').add('Move(E1,1)').add(f'ApplyActivity({K1})','Live(s)={}')
e.add('FinishStep').tick([K1]).check('Present(1,M1,1)')

f=Case('PortABA')
f.add('CreateVlan(10)').add('CreateVlan(20)').add('ConfigurePort(1,10,{10,20})')
setup(f,defs(src())).add('AutoTick').add(f'QueueActivity({K1})')
f.add('ConfigurePort(1,20,{10,20})').add('ConfigurePort(1,10,{10,20})')
f.add(f'ApplyActivity({K1})','Live(s)={}').add('FinishStep')

g=Case('VlanABA')
g.add('CreateVlan(10)').add('ConfigurePort(1,10,{10})')
setup(g,defs(src())).add('AutoTick').add(f'QueueActivity({K1})')
g.add('DeleteVlan(10)').add('CreateVlan(10)').add('ConfigurePort(1,10,{10})')
g.add(f'ApplyActivity({K1})','Live(s)={}').add('FinishStep').tick([K1]).check('Present(10,M1,1)')

h=Case('Reboot')
setup(h,defs(src())).add('AutoTick').add(f'QueueActivity({K1})')
h.add('Reboot','s.attached[E1]=1 /\\ E1 \\in s.exists /\\ E1 \\in s.active /\\ Live(s)={}')
h.add('AutoTick').add(f'ApplyActivity({K1})','Live(s)={}')
h.add(f'QueueActivity({K1})').add(f'ApplyActivity({K1})').add('FinishStep','Present(1,M1,1)')

i=Case('SharedCache')
i.add('SetMode(1,"shared")')
setup(i,defs(src()))
i.add(f'CreateEndpoint(E2,{defs(src("M2"))})').add('SetActive(E2,TRUE)').add('Connect(E2,1)')
i.tick([K1,K4]).add('Disconnect(E1)','Oper(s,1) /\\ Present(1,M1,1) /\\ Len(s.traps)=1')
i.add('DeleteEndpoint(E1)','Present(1,M1,1) /\\ Oper(s,1)').tick([K4]).tick([K4])
i.check('Absent(1,M1) /\\ Present(1,M2,1) /\\ Oper(s,1) /\\ Len(s.traps)=1')

j=Case('FaultAndDirect')
setup(j,defs(src())).tick([K1]).check('~ENABLED DeleteEndpoint(E1)')
j.add('SetFault(1,TRUE)','Live(s)={} /\\ s.attached[E1]=1')
j.add('Disconnect(E1)').add('Connect(E1,1)','~Oper(s,1) /\\ s.fault[1]')
j.tick([]).check('Live(s)={}')
j.add('SetFault(1,FALSE)').tick([K1]).add('Disconnect(E1)','~Oper(s,1) /\\ Live(s)={}')

k=Case('PauseManual')
k.add('SetPaused(TRUE)')
setup(k,defs(src())).check('~ENABLED AutoTick /\\ Live(s)={}')
k.tick([K1],manual=True).check('Present(1,M1,1) /\\ s.paused /\\ ~ENABLED AutoTick')
k.add('SetActive(E1,FALSE)').tick([],manual=True).check('Present(1,M1,1)')
k.tick([],manual=True).check('Live(s)={}')

l=Case('DuplicateMacVlans')
l.add('CreateVlan(10)').add('CreateVlan(20)').add('ConfigurePort(1,10,{10,20})')
setup(l,defs(src('M1','10'),src('M1','20'))).tick([K1,K2])
l.add('SetLegacy(10)','Cardinality(Live(s))=2 /\\ DOMAIN Dot1dTpFdbTable={M1} /\\ '
      'Dot1dBasePortTable[Dot1qTpFdbTable[<<VlanToFdb[10],M1>>].dot1qTpFdbPort].dot1dBasePortIfIndex=101')

m=Case('DuplicateMacMove')
setup(m,defs(src()))
m.add(f'CreateEndpoint(E2,{defs(src())})').add('SetActive(E2,TRUE)').add('Connect(E2,2)')
m.tick([K1,K4]).check('Cardinality(Live(s))=1 /\\ Present(1,M1,2)')

n=Case('InstanceABA')
setup(n,defs(src())).add('AutoTick').add(f'QueueActivity({K1})').add('Disconnect(E1)').add('DeleteEndpoint(E1)')
setup(n,defs(src())).add(f'ApplyActivity({K1})','Live(s)={}').add('FinishStep')

p=Case('UnknownTag')
setup(p,defs(src('M1','30'))).tick([K1]).check('Live(s)={} /\\ s.sources[<<E1,1>>].tag=30')
p.add('CreateVlan(30)').tick([K1]).check('Live(s)={}')
p.add('ConfigurePort(1,1,{1,30})').tick([K1]).check('Present(30,M1,1) /\\ Len(s.traps)=1')

q=Case('TrapOverflow')
q.add('SetMode(1,"shared")').add('SetPartner(1,FALSE)','s.overflow /\\ Len(s.traps)=1 /\\ s.traps[1].kind="linkUp"')
q.add('SetPartner(1,TRUE)').add('DispatchTrap','s.traps = <<>> /\\ s.overflow')
q.add('Reboot','~s.overflow')

header=r'''--------------------------- MODULE Scenarios ---------------------------
EXTENDS TestSwitch
CONSTANTS Scenario, E1, E2, M1, M2, M3
VARIABLE pc
allvars == <<s,pc>>
Src(m,t) == [mac |-> m, tag |-> t]
D(a,b,c) == [i \in Slots |-> CASE i=1 -> a [] i=2 -> b [] OTHER -> c]
Present(v,m,p) == s.fdb[<<VlanToFdb[v],m>>].port=p
Absent(v,m) == s.fdb[<<VlanToFdb[v],m>>]=EmptyEntry
ScenarioInit == Init /\ pc=0
'''
parts=[header]
parts.append('ScenarioLength == CASE '+ '\n    [] '.join(f'Scenario="{c.name}" -> {len(c.steps)}' for c in cases)+'\n')
parts.append('ScenarioNext ==\n    \\/ (pc=ScenarioLength /\\ UNCHANGED allvars)\n')
for c in cases:
    parts.append(f'    \\/ /\\ Scenario="{c.name}"\n       /\\ \\/ '+ '\n          \\/ '.join(f'(pc={idx} /\\ {action} /\\ pc\'=pc+1)' for idx,action in enumerate(c.steps))+'\n')
parts.append('ScenarioAssertions ==\n    /\\ pc \\in 0..ScenarioLength\n')
for c in cases:
    for pc,expr in c.checks:
        parts.append(f'    /\\ (Scenario="{c.name}" /\\ pc={pc}) => ({expr})\n')
parts.append('ScenarioSpec == ScenarioInit /\\ [][ScenarioNext]_allvars /\\ WF_allvars(ScenarioNext)\n')
parts.append('Completes == <>(pc=ScenarioLength)\n=============================================================================\n')
(ROOT/'Scenarios.tla').write_text(''.join(parts))
for c in cases:
    text='SPECIFICATION ScenarioSpec\n'+constants([1,2],['e1','e2'],[1,2,3],['macA','macB','macC'],[1,10,20,30],1 if c.name=='TrapOverflow' else 8)
    text+=f'    Scenario = "{c.name}"\n    E1 = e1\n    E2 = e2\n    M1 = macA\n    M2 = macB\n    M3 = macC\n'
    text+='INVARIANTS TypeOK InventoryOK FdbOK JobsOK MibOK TrapsOK ScenarioAssertions\n'
    text+='PROPERTIES LearningHasSource StaleJobCannotCommit Completes\n'
    (ROOT/'configs'/f'Scenario{c.name}.cfg').write_text(text)
print(f'Generated {len(cases)} scenarios, {sum(len(c.steps) for c in cases)} scripted transitions.')
