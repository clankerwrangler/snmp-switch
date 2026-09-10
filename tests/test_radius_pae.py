import copy,struct,time
import pytest
from pysnmp.proto import rfc1902 as a, rfc1905
from switchlab.engine import Engine
from switchlab.mib import Projection,PAE,plan_set,SetError,oid
from switchlab.radius import AccessResult
from switchlab.models import Vlan
from test_radius_engine import configured,begin,PEER,vlan


def event(direction,code=2,method=1,kind=0,address='02:00:00:00:00:11'):
    return bytes((direction,2,kind,code,7,method))+struct.pack('!H',5)+bytes.fromhex(address.replace(':',''))+bytes(2)
def cell(engine,suffix):return Projection(engine.state,['1']).get(PAE+suffix)[1]


@pytest.mark.asyncio
async def test_pae_indexes_actual_events_transitions_and_remote_session(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index
    capture=await begin(engine,pid,eid)
    assert int(cell(engine,(1,1,0)))==1
    assert cell(engine,(1,2,1,3,index)).asOctets()==b'\x80'
    assert cell(engine,(1,2,1,2,index)).isSameTypeWith(rfc1905.noSuchInstance)
    await engine.execute('radius-pae-events',{**capture,'events':(event(2,1),event(1,2))})
    assert int(cell(engine,(1,2,1,2,index)))==2
    assert int(cell(engine,(2,1,1,1,index)))==4
    assert int(cell(engine,(2,2,1,1,index)))==1 and int(cell(engine,(2,2,1,2,index)))==1
    assert int(cell(engine,(2,2,1,5,index)))==1 and int(cell(engine,(2,2,1,7,index)))==1
    assert int(cell(engine,(2,3,1,3,index)))==1
    assert cell(engine,(2,2,1,12,index)).asOctets()==bytes.fromhex(capture['mac'].replace(':',''))
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,(),PEER,bytes(16))})
    assert int(cell(engine,(2,1,1,1,index)))==5 and int(cell(engine,(2,3,1,4,index)))==1
    await engine.execute('advance',{'duration_ms':1234})
    assert int(cell(engine,(2,4,1,7,index)))==123
    assert int(cell(engine,(2,4,1,6,index)))==1 and int(cell(engine,(2,4,1,8,index)))==999
    assert cell(engine,(2,4,1,5,index)).asOctets().decode()==engine.state.radius_sessions[(pid,capture['mac'])].id
    # NAS-Port and ifIndex are deliberately different; no bridge-indexed PAE alias.
    assert cell(engine,(1,2,1,3,cfg.ports[pid].bridge_port)).isSameTypeWith(rfc1905.noSuchInstance)


@pytest.mark.asyncio
async def test_multiauth_scalar_omission_and_last_frame_remains_literal(configured):
    cfg,pid,eid=configured;cfg.ports[pid].authentication.host_mode='multi-auth';engine=Engine(cfg);index=cfg.ports[pid].if_index
    capture=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**capture,'events':(event(1),)})
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,(),PEER,bytes(16))})
    for suffix in [(2,1,1,1),(2,1,1,2),(2,1,1,5),(2,1,1,12),(2,1,1,13),(2,4,1,5)]:
        assert cell(engine,suffix+(index,)).isSameTypeWith(rfc1905.noSuchInstance)
    assert int(cell(engine,(2,2,1,1,index)))==1 and int(cell(engine,(2,2,1,11,index)))==2
    await engine.execute('port-edit',{'id':pid,'patch':{'authentication':{'control':'force-authorized','host_mode':'multi-auth'}}})
    assert int(cell(engine,(2,1,1,1,index)))==8


@pytest.mark.asyncio
async def test_last_session_and_unrepresentable_termination_cause(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index
    capture=await begin(engine,pid,eid)
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,((27,(2).to_bytes(4,'big')),),PEER,bytes(16))})
    session_id=engine.state.radius_sessions[(pid,capture['mac'])].id
    await engine.execute('advance',{'duration_ms':2500})
    assert not engine.state.radius_sessions
    assert cell(engine,(2,4,1,5,index)).asOctets().decode()==session_id
    assert int(cell(engine,(2,4,1,7,index)))==200
    assert cell(engine,(2,4,1,8,index)).isSameTypeWith(rfc1905.noSuchInstance)


@pytest.mark.asyncio
async def test_full_pdu_actions_coalesce_under_final_control_and_preserve_counters(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index
    capture=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**capture,'events':(event(1),)})
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,(),PEER,bytes(16))})
    before_counter=engine.state.pae[pid]['counters'].copy();before_up=engine.state.up(pid)
    bindings=[(PAE+(1,2,1,5,index),a.Integer32(1)),(PAE+(1,2,1,4,index),a.Integer32(1)),
              (PAE+(2,1,1,6,index),a.Integer32(1)),(PAE+(1,2,1,4,index),a.Integer32(1))]
    plan=plan_set(engine.state.cfg,bindings,['1'])
    assert plan.pae_actions==((pid,'initialize'),)
    async with engine.lock:engine.commit_set_locked(plan)
    assert engine.state.up(pid)==before_up and not engine.state.radius_sessions and not engine.state.radius_attempts
    assert engine.state.pae[pid]['counters']==before_counter
    assert int(cell(engine,(1,2,1,4,index)))==2 and int(cell(engine,(1,2,1,5,index)))==2
    assert int(cell(engine,(2,1,1,1,index)))==9 and int(cell(engine,(2,4,1,8,index)))==6
    events=[e for e in engine.state.events if e['kind'].startswith('pae-')]
    assert len(events)==1 and events[0]['kind']=='pae-initialize'
    assert not any(e['kind']=='linkDown' for e in engine.state.events)


@pytest.mark.asyncio
async def test_pae_validation_no_prefix_effect_and_false_action_noop(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index;before=engine.state
    with pytest.raises(SetError) as error:
        plan_set(engine.state.cfg,[(PAE+(1,2,1,4,index),a.Integer32(1)),(oid('1.3.6.1.2.1.2.2.1.7')+(index,),a.Integer32(3))],['1'])
    assert error.value.index==2 and engine.state is before
    false=plan_set(engine.state.cfg,[(PAE+(1,2,1,4,index),a.Integer32(2))],['1'])
    assert not false.changed and not false.pae_actions
    async with engine.lock:engine.commit_set_locked(false)
    assert engine.state is before
    with pytest.raises(SetError) as error:plan_set(engine.state.cfg,[(PAE+(1,1,0),a.Integer32(2))],['1'])
    assert error.value.status=='notWritable'


@pytest.mark.asyncio
async def test_dynamic_current_membership_does_not_rewrite_static_or_untagged(configured):
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020);engine=Engine(cfg)
    capture=await begin(engine,pid,eid);saved=copy.deepcopy(engine.state.cfg.ports[pid])
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,tuple(vlan()),PEER,bytes(16))})
    projection=Projection(engine.state,['1'])
    assert projection.get('1.3.6.1.2.1.17.7.1.4.2.1.4.0.20')[1].asOctets()==b'\x80'
    assert projection.get('1.3.6.1.2.1.17.7.1.4.3.1.2.20')[1].asOctets()==b'\0'
    assert projection.get('1.3.6.1.2.1.17.7.1.4.2.1.5.0.20')[1].asOctets()==b'\0'
    assert engine.state.cfg.ports[pid]==saved


@pytest.mark.asyncio
async def test_incomplete_observation_is_not_published_as_exact_counter_or_last_frame(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index
    capture=await begin(engine,pid,eid);await engine.execute('radius-pae-events',{**capture,'events':(event(1),)})
    await engine.execute('detach',{'id':eid})
    assert not engine.state.pae[pid]['precise']
    for column in (1,11,12):assert cell(engine,(2,2,1,column,index)).isSameTypeWith(rfc1905.noSuchInstance)
    before=engine.state
    await engine.execute('radius-pae-events',{**capture,'events':(event(1),)})
    assert engine.state is before


@pytest.mark.asyncio
@pytest.mark.parametrize('retirement',['initialize','reauthenticate','idle-expiry'])
async def test_pending_eap_retirement_omits_incomplete_observation(configured,retirement):
    from dataclasses import replace
    from switchlab.models import Port
    cfg,pid,eid=configured
    other=Port(bridge_port=2,if_index=102,name='Unrelated')
    cfg.ports[other.id]=other;cfg.switch.port_count=2
    engine=Engine(cfg);index=cfg.ports[pid].if_index
    engine.state.pae_port(other.id)
    unrelated=copy.deepcopy(engine.state.pae[other.id])
    first=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**first,'events':(event(1),)})
    await engine.execute('radius-result',{**first,'result':AccessResult(2,(),PEER,bytes(16))})
    key=(pid,first['mac']);session_id=engine.state.radius_sessions[key].id
    await engine.execute('radius-session-action',{'id':session_id,'action':'reauthenticate'})
    pending={**first,'attempt_id':engine.state.radius_attempts[key].id}
    await engine.execute('radius-pae-events',{**pending,'events':(event(1),)})
    numeric=engine.state.pae[pid]['counters'].copy()
    assert engine.state.pae[pid]['precise'] and numeric[0]==2
    if retirement=='idle-expiry':
        # An independent due timer must retire renewal before late completion.
        session=engine.state.radius_sessions[key]
        session.policy=replace(session.policy,idle_timeout=0)
        await engine.execute('radius-discover')
    else:
        column=4 if retirement=='initialize' else 5
        plan=plan_set(engine.state.cfg,[(PAE+(1,2,1,column,index),a.Integer32(1))],['1'])
        async with engine.lock:engine.commit_set_locked(plan)
    assert not engine.state.pae[pid]['precise']
    assert engine.state.pae[pid]['counters']==numeric
    assert engine.state.pae[other.id]==unrelated and engine.state.up(pid)
    if retirement=='reauthenticate':assert engine.state.radius_sessions[key].id==session_id
    else:assert key not in engine.state.radius_sessions
    assert engine.state.current_attempt(key,pending['attempt_id']) is None
    before=engine.state
    await engine.execute('radius-pae-events',{**pending,'events':(event(1),)})
    stale=await engine.execute('radius-result',{**pending,'result':AccessResult(2,(),PEER,bytes(16))})
    assert not stale['accepted'] and engine.state is before
    for column in (1,11,12):assert cell(engine,(2,2,1,column,index)).isSameTypeWith(rfc1905.noSuchInstance)
    for column in (3,4,5,6):assert cell(engine,(2,3,1,column,index)).isSameTypeWith(rfc1905.noSuchInstance)
    fresh=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**fresh,'events':(event(1),)})
    await engine.execute('radius-result',{**fresh,'result':AccessResult(2,(),PEER,bytes(16))})
    assert engine.state.pae[pid]['counters'][0]==numeric[0]+1 and not engine.state.pae[pid]['precise']
    assert cell(engine,(2,2,1,1,index)).isSameTypeWith(rfc1905.noSuchInstance)
    await engine.execute('reboot')
    assert int(cell(engine,(2,2,1,1,index)))==0


@pytest.mark.asyncio
@pytest.mark.parametrize('code',[2,3])
async def test_completed_eap_renewal_does_not_invalidate_observation(configured,code):
    cfg,pid,eid=configured;engine=Engine(cfg);index=cfg.ports[pid].if_index
    first=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**first,'events':(event(1),)})
    await engine.execute('radius-result',{**first,'result':AccessResult(2,(),PEER,bytes(16))})
    current=await begin(engine,pid,eid)
    await engine.execute('radius-pae-events',{**current,'events':(event(1),)})
    await engine.execute('radius-result',{**current,'result':AccessResult(code,(),PEER,bytes(16))})
    assert engine.state.pae[pid]['precise']
    assert int(cell(engine,(2,2,1,1,index)))==2
    assert bool(engine.state.radius_sessions)==(code==2)


@pytest.mark.asyncio
async def test_session_snapshot_reports_effective_simulation_deadlines(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    attrs=((27,(2).to_bytes(4,'big')),(28,(3).to_bytes(4,'big')),(29,(1).to_bytes(4,'big')))
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,attrs,PEER,bytes(16))})
    snapshot=engine.snapshot()['authentication_sessions'][0]
    assert snapshot['lease_deadline_ms']==snapshot['reauthentication_deadline_ms']==2000
    assert snapshot['idle_deadline_ms']==3000


@pytest.mark.asyncio
async def test_new_accounting_target_defaults_to_1813_and_sparse_save_preserves_it(configured):
    cfg,_,_=configured;engine=Engine(cfg)
    saved=await engine.execute('accounting-target-save',{'label':'Collector','address':'192.0.2.10','secret':'synthetic-collector'})
    assert engine.state.cfg.radius.accounting.targets[0].port==1813
    await engine.execute('accounting-target-save',{'id':saved['id'],'label':'Renamed'})
    assert engine.state.cfg.radius.accounting.targets[0].port==1813
    assert not engine.state.cfg.radius.servers and not engine.state.cfg.radius.accounting.enabled
