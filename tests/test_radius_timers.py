import copy
from dataclasses import replace
import pytest
from switchlab.engine import Engine
from switchlab.models import Port,Vlan
from switchlab.radius import AccessResult
from test_radius_engine import configured,begin,PEER,vlan
from test_radius_methods import plain


def controls(lease=None,idle=None,action=0,vid=None,state=None):
    values=[]
    if vid is not None:values=[(64,(13).to_bytes(4,'big')),(65,(6).to_bytes(4,'big')),(81,str(vid).encode())]
    if lease is not None:values.append((27,lease.to_bytes(4,'big')))
    if idle is not None:values.append((28,idle.to_bytes(4,'big')))
    values.append((29,action.to_bytes(4,'big')))
    if state is not None:values.append((24,state))
    return AccessResult(2,tuple(values),PEER,bytes(16))


async def grant(engine,pid,eid,result):
    capture=await begin(engine,pid,eid)
    await engine.execute('radius-result',{**capture,'result':result})
    return capture


@pytest.mark.asyncio
async def test_session_limit_expires_before_same_time_packet(configured):
    cfg,pid,eid=configured;cfg.endpoints[eid].sources[0].interval_ms=1000;engine=Engine(cfg)
    await grant(engine,pid,eid,controls(lease=2))
    waiting=await engine.execute('advance',{'duration_ms':5000})
    assert waiting['advance']['status']=='waiting' and engine.state.sim_ms==2000
    assert not engine.state.radius_sessions and not engine.state.fdb
    assert engine.state.counters[pid]['in_ucast']==1 and engine.state.counters[pid]['in_discards']==1
    ended=[e for e in engine.state.events if e['kind']=='authentication-ended']
    assert ended[-1]['simulation_ms']==2000 and ended[-1]['reason']=='session-timeout'


@pytest.mark.asyncio
async def test_idle_expiry_precedes_packet_at_exact_activity_deadline(configured):
    cfg,pid,eid=configured;cfg.endpoints[eid].sources[0].interval_ms=2000;engine=Engine(cfg)
    await grant(engine,pid,eid,controls(idle=2))
    await engine.execute('advance',{'duration_ms':1000})
    assert next(iter(engine.state.radius_sessions.values())).last_activity_ms==1000
    await engine.execute('advance',{'duration_ms':2000})
    assert engine.state.sim_ms==3000 and not engine.state.radius_sessions
    assert engine.state.counters[pid]['in_ucast']==1 and engine.state.counters[pid]['in_discards']==1
    assert next(e for e in reversed(engine.state.events) if e['kind']=='authentication-ended')['reason']=='idle-timeout'


@pytest.mark.asyncio
async def test_reauth_same_policy_retains_id_and_true_idle_across_new_state(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    first=await grant(engine,pid,eid,controls(lease=2,idle=3,action=1,state=b'first'))
    original=engine.state.radius_sessions[(pid,first['mac'])].id
    await engine.execute('advance',{'duration_ms':6000})
    assert engine.state.sim_ms==2000 and engine.state.radius_sessions[(pid,first['mac'])].id==original
    pending=engine.state.radius_attempts[(pid,first['mac'])]
    assert pending.state==b'first' and pending.automatic_renewal
    await engine.execute('radius-result',{'port_id':pid,'mac':first['mac'],'attempt_id':pending.id,'result':controls(lease=2,idle=3,action=1,state=b'next')})
    current=engine.state.radius_sessions[(pid,first['mac'])]
    assert current.id==original and current.last_activity_ms==1000 and current.idle_origin_ms==0
    assert current.lease_deadline_ms==4000 and current.last_auth_ms==2000
    await engine.continue_advance()
    assert engine.state.sim_ms==6000 and not engine.state.radius_sessions
    ended=[e for e in engine.state.events if e['kind']=='authentication-ended']
    assert ended[-1]['simulation_ms']==4000 and ended[-1]['reason']=='idle-timeout'


@pytest.mark.asyncio
async def test_changed_reauth_segment_retains_actual_inactivity(configured):
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020);engine=Engine(cfg)
    capture=await grant(engine,pid,eid,controls(lease=2,idle=3,action=1))
    old_id=engine.state.radius_sessions[(pid,capture['mac'])].id
    await engine.execute('advance',{'duration_ms':2000})
    pending=engine.state.radius_attempts[(pid,capture['mac'])]
    await engine.execute('radius-result',{'port_id':pid,'mac':capture['mac'],'attempt_id':pending.id,'result':controls(lease=2,idle=3,action=1,vid=20)})
    current=engine.state.radius_sessions[(pid,capture['mac'])]
    assert current.id!=old_id and current.started_ms==2000
    assert current.last_activity_ms==1000 and current.idle_origin_ms==0 and current.in_packets==0
    assert not engine.state.fdb
    await engine.continue_advance();assert engine.state.sim_ms==2000


@pytest.mark.asyncio
async def test_zero_default_is_immediate_end_not_disable(configured):
    cfg,pid,eid=configured;cfg.endpoints[eid].active=False;engine=Engine(cfg)
    await grant(engine,pid,eid,controls(lease=0))
    assert not engine.state.radius_sessions and not engine.state.radius_attempts and not engine.state.fdb
    await engine.execute('advance',{'duration_ms':1000})
    assert engine.state.sim_ms==1000 and not engine.state.radius_sessions


@pytest.mark.asyncio
async def test_zero_renewals_guard_survives_segment_changes_and_new_advance(configured):
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020);engine=Engine(cfg)
    waiting=await engine.execute('advance',{'duration_ms':1000});key=next(iter(engine.state.radius_attempts))
    first=engine.state.radius_attempts[key]
    await engine.execute('radius-result',{'port_id':key[0],'mac':key[1],'attempt_id':first.id,'result':controls(lease=0,action=1,vid=1)})
    seen=[]
    for i in range(64):
        attempt=engine.state.radius_attempts[key];assert attempt.automatic_renewal
        seen.append(attempt.id)
        await engine.execute('radius-result',{'port_id':key[0],'mac':key[1],'attempt_id':attempt.id,'result':controls(lease=0,action=1,vid=20 if i%2==0 else 1)})
    assert len(set(seen))==64 and not engine.state.radius_attempts and not engine.state.radius_sessions
    assert engine.state.sim_ms==0 and engine.state.renewal_budget[key]==64
    assert engine.advance_status()['status']=='failed-on-guard'
    assert engine.state.radius_status[key]['reason']=='renewal-work-limit'
    # An explicit new initial operation/segment at the same time does not reset the automatic budget.
    capture=await begin(engine,pid,eid)
    await engine.execute('radius-result',{**capture,'result':controls(lease=0,action=1,vid=1)})
    assert not engine.state.radius_attempts and not engine.state.radius_sessions and engine.state.renewal_budget[key]==64
    await engine.execute('advance',{'duration_ms':1})
    assert engine.state.sim_ms==1 and not engine.state.renewal_budget


@pytest.mark.asyncio
async def test_positive_time_renewal_does_not_hit_zero_time_guard(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    capture=await grant(engine,pid,eid,controls(lease=1,action=1))
    await engine.execute('advance',{'duration_ms':70000})
    for _ in range(70):
        attempt=engine.state.radius_attempts[(pid,capture['mac'])]
        await engine.execute('radius-result',{'port_id':pid,'mac':capture['mac'],'attempt_id':attempt.id,'result':controls(lease=1,action=1)})
        await engine.continue_advance()
    assert engine.state.sim_ms==70000 and engine.advance_status()['status']=='completed'
    assert engine.state.radius_sessions and engine.state.renewal_budget[(pid,capture['mac'])]==1


@pytest.mark.asyncio
async def test_retained_shared_mab_session_renews_without_destination_or_activity():
    cfg,pid,eid=plain();cfg.ports[pid].mode='shared';cfg.ports[pid].shared_partner=True
    other=Port(bridge_port=2,if_index=102,name='Destination');other.authentication.control='auto';other.authentication.method='mab'
    cfg.ports[other.id]=other;cfg.switch.port_count=2;engine=Engine(cfg)
    await engine.execute('advance',{'duration_ms':1000});key=next(iter(engine.state.radius_attempts));initial=engine.state.radius_attempts[key]
    await engine.execute('radius-result',{'port_id':pid,'mac':key[1],'attempt_id':initial.id,'result':controls(lease=2,idle=5,action=1)})
    await engine.continue_advance();session=engine.state.radius_sessions[key];original_id=session.id
    await engine.execute('endpoint-edit',{'id':eid,'patch':{'active':False}})
    await engine.execute('attach',{'id':eid,'port_id':other.id})
    assert engine.state.radius_sessions[key].id==original_id and not engine.state.session(other.id,key[1])
    await engine.execute('advance',{'duration_ms':2000})
    pending=engine.state.radius_attempts[key]
    assert pending.session_owned and pending.automatic_renewal and engine.state.current_attempt(key,pending.id)
    await engine.execute('radius-result',{'port_id':pid,'mac':key[1],'attempt_id':pending.id,'result':controls(lease=2,idle=5,action=1)})
    assert engine.state.radius_sessions[key].id==original_id and engine.state.radius_sessions[key].last_activity_ms is None
    assert engine.state.radius_sessions[key].idle_origin_ms==1000 and not engine.state.fdb
    assert not engine.state.session(other.id,key[1])


@pytest.mark.asyncio
async def test_pre_move_renewal_stays_stale_and_independent_expiry_ends_cached_work():
    cfg,pid,eid=plain();cfg.ports[pid].mode='shared';cfg.ports[pid].shared_partner=True
    other=Port(bridge_port=2,if_index=102,name='Destination');cfg.ports[other.id]=other;cfg.switch.port_count=2
    engine=Engine(cfg);await engine.execute('advance',{'duration_ms':1000});key=next(iter(engine.state.radius_attempts));first=engine.state.radius_attempts[key]
    await engine.execute('radius-result',{'port_id':pid,'mac':key[1],'attempt_id':first.id,'result':controls(lease=1,action=1)})
    await engine.continue_advance();await engine.execute('advance',{'duration_ms':1000})
    old=engine.state.radius_attempts[key];assert not old.session_owned
    await engine.execute('endpoint-edit',{'id':eid,'patch':{'active':False}});await engine.execute('attach',{'id':eid,'port_id':other.id})
    before=engine.state
    assert not (await engine.execute('radius-result',{'port_id':pid,'mac':key[1],'attempt_id':old.id,'result':controls(lease=1,action=1)}))['accepted']
    assert engine.state is before
    await engine.execute('radius-discover');new=engine.state.radius_attempts[key]
    assert new.id!=old.id and new.session_owned
    # A separately due timer (as can be set by an in-place policy update) is not a link bounce.
    engine.state.radius_sessions[key].policy=replace(engine.state.radius_sessions[key].policy,idle_timeout=0)
    await engine.execute('radius-discover');before=engine.state
    assert not engine.state.radius_sessions and key not in engine.state.radius_attempts
    assert not (await engine.execute('radius-result',{'port_id':pid,'mac':key[1],'attempt_id':new.id,'result':controls(lease=1,action=1)}))['accepted']
    assert engine.state is before and engine.state.up(pid)


@pytest.mark.asyncio
async def test_server_session_and_idle_limits_take_precedence_over_local_timers(configured):
    cfg,pid,eid=configured;cfg.radius.reauthentication_seconds=1;cfg.radius.inactivity_seconds=1
    engine=Engine(cfg);capture=await grant(engine,pid,eid,controls(lease=5,idle=7,action=0))
    session=engine.state.radius_sessions[(pid,capture['mac'])]
    idle,termination,renewal=engine.state.session_deadlines(session)
    assert (idle,termination,renewal)==(7000,5000,None)
    session.policy=replace(session.policy,termination_action=1)
    assert engine.state.session_deadlines(session)==(7000,None,5000)
    session.policy=replace(session.policy,session_timeout=None,idle_timeout=None)
    session.lease_deadline_ms=None
    assert engine.state.session_deadlines(session)==(1000,None,1000)
