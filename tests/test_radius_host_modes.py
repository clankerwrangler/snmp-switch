"""Combined host-mode and VLAN lifecycle regressions; no transport is started."""
from dataclasses import replace
import pytest
from pysnmp.proto import rfc1902 as a
from switchlab.engine import Engine
from switchlab.models import Source,Vlan,RadiusServer
from switchlab.mib import Projection,plan_set,oid
from switchlab.radius import AccessResult
from test_radius_engine import configured,PEER
from test_radius_timers import controls
from test_radius_accounting import number


def clients(configured,mode,count):
    cfg,pid,eid=configured;cfg.ports[pid].authentication.host_mode=mode
    cfg.ports[pid].mode='shared';cfg.ports[pid].shared_partner=True
    original=cfg.endpoints[eid].sources[0]
    cfg.endpoints[eid].sources=[Source(mac=f'02:00:00:00:00:{i:02x}',supplicant=original.supplicant.model_copy(deep=True)) for i in range(17,17+count)]
    cfg.vlans[20]=Vlan(vid=20,name='Twenty',fdb_id=1020);cfg.vlans[30]=Vlan(vid=30,name='Thirty',fdb_id=1030)
    cfg.radius.accounting.enabled=True;cfg.radius.accounting.targets=[RadiusServer(label='Collector',address='192.0.2.5',secret='synthetic')]
    return Engine(cfg),pid,eid,[source.mac for source in cfg.endpoints[eid].sources]


async def begin_client(engine,pid,address):
    result=await engine.execute('radius-begin',{'port_id':pid,'mac':address})
    return {**result,'port_id':pid,'mac':address}


async def accept(engine,capture,vid=None):
    await engine.execute('radius-result',{**capture,'result':controls(vid=vid)})


def members(engine,vid):
    return Projection(engine.state,['1']).get(f'1.3.6.1.2.1.17.7.1.4.2.1.4.0.{vid}')[1].asOctets()


async def expire(engine,pid,address):
    session=engine.state.radius_sessions[(pid,address)]
    session.policy=replace(session.policy,idle_timeout=0)
    await engine.execute('radius-discover')


@pytest.mark.asyncio
async def test_single_host_reserves_pending_slot_and_releases_after_failed_cycle(configured):
    engine,pid,eid,macs=clients(configured,'single-host',3)
    first=await begin_client(engine,pid,macs[0]);blocked=await begin_client(engine,pid,macs[1])
    assert blocked['blocked'] and blocked['reason']=='host-mode-limit'
    assert len(engine.state.radius_attempts)==1
    await engine.execute('radius-result',{**first,'result':AccessResult(3,(),PEER,bytes(16))})
    second=await begin_client(engine,pid,macs[1]);assert 'attempt_id' in second
    await accept(engine,second,20);session=engine.state.radius_sessions[(pid,macs[1])]
    third=await begin_client(engine,pid,macs[2]);assert third['blocked']
    assert list(engine.state.radius_sessions)==[(pid,macs[1])] and not engine.state.radius_attempts
    assert engine.state.radius_sessions[(pid,macs[1])].id==session.id and engine.state.up(pid)
    assert engine.state.radius_status[(pid,macs[0])]['retry_at_ms']==60000


@pytest.mark.asyncio
@pytest.mark.parametrize('pvid_path',['api','snmp'])
async def test_multiauth_tags_membership_references_baseline_and_deletion_are_independent(configured,pvid_path):
    engine,pid,eid,macs=clients(configured,'multi-auth',4)
    # Install source tags before any capture. One matches; another is deliberately wrong.
    engine.state.cfg.endpoints[eid].sources[0].tag=20
    engine.state.cfg.endpoints[eid].sources[1].tag=20
    engine.state.schedule(eid)
    captures=[await begin_client(engine,pid,address) for address in macs]
    for capture,vid in zip(captures,[20,30,None,20]):await accept(engine,capture,vid)
    ids={mac:engine.state.radius_sessions[(pid,mac)].id for mac in macs}
    assert [engine.state.session_vid(engine.state.radius_sessions[(pid,mac)]) for mac in macs]==[20,30,1,20]
    assert engine.state.cfg.ports[pid].admitted==[1] and engine.state.cfg.ports[pid].pvid==1
    await engine.execute('advance',{'duration_ms':1000})
    assert engine.state.counters[pid]['in_ucast']==3 and engine.state.counters[pid]['in_discards']==1
    assert {(r['mac'],r['vid']) for r in engine.state.fdb.values()}=={(macs[0],20),(macs[2],1),(macs[3],20)}
    assert engine.state.radius_sessions[(pid,macs[1])].id==ids[macs[1]]
    assert engine.state.radius_sessions[(pid,macs[1])].last_activity_ms is None
    assert members(engine,20)==b'\x80'
    await expire(engine,pid,macs[0]);assert members(engine,20)==b'\x80'
    await expire(engine,pid,macs[3]);assert members(engine,20)==b'\0'
    assert engine.state.radius_sessions[(pid,macs[1])].id==ids[macs[1]]
    pending=await begin_client(engine,pid,macs[1])
    if pvid_path=='api':await engine.execute('port-edit',{'id':pid,'patch':{'pvid':20,'admitted':[1,20]}})
    else:
        binds=[(oid('1.3.6.1.2.1.17.7.1.4.3.1.2.20'),a.OctetString(b'\x80')),
               (oid('1.3.6.1.2.1.17.7.1.4.5.1.1')+(engine.state.cfg.ports[pid].bridge_port,),a.Gauge32(20))]
        plan=plan_set(engine.state.cfg,binds,['1'])
        async with engine.lock:engine.commit_set_locked(plan)
    assert engine.state.current_attempt((pid,macs[1]),pending['attempt_id'])
    assert engine.state.session_vid(engine.state.radius_sessions[(pid,macs[1])])==30
    assert engine.state.session_vid(engine.state.radius_sessions[(pid,macs[2])])==20
    assert engine.state.radius_sessions[(pid,macs[2])].id==ids[macs[2]]
    assert engine.state.cfg.ports[pid].untagged==([20] if pvid_path=='api' else [1])
    await engine.execute('vlan-delete',{'vid':30})
    assert (pid,macs[1]) not in engine.state.radius_sessions and (pid,macs[2]) in engine.state.radius_sessions
    before=engine.state
    assert not (await engine.execute('radius-result',{**pending,'result':controls(vid=30)}))['accepted']
    assert engine.state is before
    await engine.execute('vlan-delete',{'vid':20})
    assert engine.state.cfg.ports[pid].pvid==1 and not engine.state.radius_sessions and engine.state.up(pid)
    assert not engine.state.fdb and all(record['status_type']!=1 or record['session_id'] in ids.values() for record in engine.state.accounting_outbox)
    assert len([r for r in engine.state.accounting_outbox if r['status_type']==2])==4


@pytest.mark.asyncio
async def test_multi_host_owner_counts_dependents_once_and_departure_is_not_logoff(configured):
    engine,pid,eid,macs=clients(configured,'multi-host',3)
    first=await begin_client(engine,pid,macs[0]);assert (await begin_client(engine,pid,macs[1]))['blocked']
    await accept(engine,first,20)
    owner=engine.state.radius_sessions[(pid,macs[0])];sid=owner.id
    await engine.execute('advance',{'duration_ms':1000})
    assert len(engine.state.radius_sessions)==1 and engine.state.session(pid,macs[1]).id==sid
    assert engine.state.radius_sessions[(pid,macs[0])].in_packets==3
    assert len([r for r in engine.state.accounting_outbox if r['status_type']==1])==1
    sources=engine.state.cfg.endpoints[eid].sources
    await engine.execute('endpoint-edit',{'id':eid,'patch':{'sources':[source.model_dump(mode='json') for source in sources if source.mac!=macs[1]]}})
    assert engine.state.radius_sessions[(pid,macs[0])].id==sid
    sources=engine.state.cfg.endpoints[eid].sources
    await engine.execute('endpoint-edit',{'id':eid,'patch':{'sources':[source.model_dump(mode='json') for source in sources if source.mac!=macs[0]]}})
    assert engine.state.radius_sessions[(pid,macs[0])].id==sid and engine.state.session(pid,macs[2]).id==sid
    assert engine.state.up(pid) and not any(e['kind']=='linkDown' for e in engine.state.events)
    await expire(engine,pid,macs[0])
    assert not engine.state.radius_sessions and engine.state.session(pid,macs[2]) is None
    stops=[r for r in engine.state.accounting_outbox if r['status_type']==2]
    assert len(stops)==1 and number(stops[0],47)==3 and number(stops[0],42)==192
    assert not engine.state.fdb and members(engine,20)==b'\0' and engine.state.up(pid)


@pytest.mark.asyncio
async def test_removing_one_same_port_duplicate_source_retains_its_current_grant(configured):
    engine,pid,eid,macs=clients(configured,'multi-auth',2)
    sources=engine.state.cfg.endpoints[eid].sources;sources[1].mac=macs[0];engine.state.schedule(eid)
    capture=await begin_client(engine,pid,macs[0])
    assert (await begin_client(engine,pid,macs[0]))['attempt_id']==capture['attempt_id']
    await accept(engine,capture,20);sid=engine.state.radius_sessions[(pid,macs[0])].id
    await engine.execute('advance',{'duration_ms':1000})
    assert len(engine.state.radius_sessions)==1 and engine.state.radius_sessions[(pid,macs[0])].in_packets==2
    fdb=engine.state.fdb.copy();remaining=engine.state.cfg.endpoints[eid].sources[1]
    await engine.execute('endpoint-edit',{'id':eid,'patch':{'sources':[remaining.model_dump(mode='json')]}})
    assert engine.state.radius_sessions[(pid,macs[0])].id==sid and engine.state.fdb==fdb and engine.state.up(pid)
    assert len([r for r in engine.state.accounting_outbox if r['status_type']==1])==1
    assert not [r for r in engine.state.accounting_outbox if r['status_type']==2]


@pytest.mark.asyncio
async def test_idle_expiry_releases_single_host_slot_for_next_eligible_subject(configured):
    engine,pid,eid,macs=clients(configured,'single-host',2)
    engine.state.cfg.endpoints[eid].active=False;engine.state.schedule(eid)
    capture=await begin_client(engine,pid,macs[0])
    await engine.execute('radius-result',{**capture,'result':controls(idle=1,vid=20)})
    old_id=engine.state.radius_sessions[(pid,macs[0])].id
    assert (await begin_client(engine,pid,macs[1]))['blocked']
    await engine.execute('advance',{'duration_ms':1000})
    assert engine.state.sim_ms==1000 and (pid,macs[0]) not in engine.state.radius_sessions
    next_capture=await begin_client(engine,pid,macs[1]);assert 'attempt_id' in next_capture
    await accept(engine,next_capture,20)
    assert list(engine.state.radius_sessions)==[(pid,macs[1])]
    assert engine.state.radius_sessions[(pid,macs[1])].id!=old_id
    stops=[r for r in engine.state.accounting_outbox if r['status_type']==2]
    assert len(stops)==1 and number(stops[0],49)==4 and engine.state.up(pid) and not engine.state.fdb
