import asyncio
import pytest
from switchlab.engine import Engine
from switchlab.models import RadiusServer,initial_configuration,Endpoint,Source,Vlan
from switchlab.radius import AccessResult,NativeObservation,RadiusError
from test_radius_engine import configured,PEER,vlan


def plain(method='mab',active=True):
    cfg=initial_configuration(1);cfg.paused=True
    cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020)
    pid=next(iter(cfg.ports));cfg.ports[pid].authentication.control='auto';cfg.ports[pid].authentication.method=method
    ep=Endpoint(name='Synthetic',active=active,sources=[Source(mac='02:00:00:00:00:11')]);cfg.endpoints[ep.id]=ep;cfg.attachments[ep.id]=pid
    cfg.radius.servers=[RadiusServer(label='Synthetic',address=PEER[0],secret='synthetic-shared')]
    return cfg,pid,ep.id


async def run_workers(engine):
    await engine.service_authentication()
    await asyncio.gather(*engine._authentication_tasks.values())


@pytest.mark.asyncio
async def test_mab_trigger_is_dropped_once_and_never_replayed_as_admitted_data(monkeypatch):
    cfg,pid,eid=plain();engine=Engine(cfg);calls=[]
    async def mab(*args,**kwargs):
        calls.append((engine.state.sim_ms,args[4],kwargs['nas_identity'].identifier))
        return NativeObservation(AccessResult(2,tuple(vlan()),PEER,bytes(16)),0,0,0,0,False,False)
    async def eap(*args,**kwargs):raise AssertionError('MAB must not depend on EAP helper')
    monkeypatch.setattr('switchlab.radius.mab_exchange',mab);monkeypatch.setattr('switchlab.radius.native_exchange',eap)
    waiting=await engine.execute('advance',{'duration_ms':32000})
    assert waiting['advance']['status']=='waiting' and engine.state.sim_ms==1000
    assert not engine.state.fdb and engine.state.counters[pid]['in_discards']==1
    await run_workers(engine);assert engine.state.radius_sessions and not engine.state.fdb
    await engine.continue_advance()
    assert engine.state.sim_ms==32000 and engine.state.counters[pid]['in_discards']==1
    assert engine.state.counters[pid]['in_ucast']==1 and {r['vid'] for r in engine.state.fdb.values()}=={20}
    assert calls==[(1000,'02:00:00:00:00:11',b'Switch Lab')]
    assert engine.state.cfg.ports[pid].pvid==1 and engine.state.cfg.ports[pid].admitted==[1]
    await engine.close_authentication()


@pytest.mark.asyncio
@pytest.mark.parametrize('method',['mab','dot1x-mab'])
async def test_no_supplicant_and_silent_source_never_trigger_mab(method,monkeypatch):
    cfg,pid,eid=plain(method,False);engine=Engine(cfg)
    async def prohibited(*args,**kwargs):raise AssertionError('No ordinary trigger')
    monkeypatch.setattr('switchlab.radius.mab_exchange',prohibited);monkeypatch.setattr('switchlab.radius.native_exchange',prohibited)
    await engine.execute('advance',{'duration_ms':100000});await engine.service_authentication()
    assert engine.state.sim_ms==100000 and not engine.state.radius_sessions and not engine.state.radius_attempts
    assert not engine._authentication_tasks and not engine.state.fdb
    await engine.close_authentication()


@pytest.mark.asyncio
@pytest.mark.parametrize('fallback',[False,True])
async def test_no_supplicant_fallback_waits_for_a_packet_after_discovery(fallback,monkeypatch):
    cfg,pid,eid=plain('dot1x-mab');cfg.ports[pid].authentication.fallback_no_supplicant=fallback
    engine=Engine(cfg);calls=[]
    async def mab(*args,**kwargs):
        calls.append(engine.state.sim_ms)
        return NativeObservation(AccessResult(2,tuple(vlan()),PEER,bytes(16)),0,0,0,0,False,False)
    monkeypatch.setattr('switchlab.radius.mab_exchange',mab)
    result=await engine.execute('advance',{'duration_ms':65000})
    if fallback:
        assert engine.state.sim_ms==31000 and engine.state.counters[pid]['in_discards']==2
        await run_workers(engine);await engine.continue_advance()
        assert calls==[31000] and len(engine.state.fdb)==1
    else:
        assert engine.state.sim_ms==65000 and not engine.state.radius_attempts and not calls and not engine.state.fdb
    await engine.close_authentication()


@pytest.mark.asyncio
@pytest.mark.parametrize('fallback',[False,True])
async def test_only_explicit_reject_flag_allows_new_mab_method(configured,monkeypatch,fallback):
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label='Synthetic',address=PEER[0],secret='synthetic-shared')]
    cfg.ports[pid].authentication.fallback_reject=fallback;engine=Engine(cfg);calls=[]
    async def eap(*args,**kwargs):calls.append('eap');return NativeObservation(AccessResult(3,(),PEER,bytes(16)),1,0,1,0,False,False)
    async def mab(*args,**kwargs):calls.append('mab');return NativeObservation(AccessResult(2,(),PEER,bytes(16)),0,0,0,0,False,False)
    monkeypatch.setattr('switchlab.radius.native_exchange',eap);monkeypatch.setattr('switchlab.radius.mab_exchange',mab)
    await engine.execute('advance',{'duration_ms':35000});await run_workers(engine);await engine.continue_advance()
    if fallback:
        assert engine.state.sim_ms==0 and engine.state.counters[pid]['in_discards']==0
        await run_workers(engine);await engine.continue_advance()
        assert calls==['eap','mab'] and engine.state.radius_sessions
    else:assert calls==['eap'] and not engine.state.radius_sessions
    await engine.close_authentication()


@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['unusable-accept','helper','certificate'])
async def test_local_outcomes_never_shop_backup_or_fall_back_to_mab(configured,monkeypatch,failure):
    cfg,pid,eid=configured
    cfg.radius.servers=[RadiusServer(label=str(n),address=f'192.0.2.{n}',secret='synthetic-shared') for n in (1,2)]
    cfg.ports[pid].authentication.fallback_reject=True;engine=Engine(cfg);calls=[]
    async def eap(*args,**kwargs):
        calls.append(args[1].id)
        if failure=='helper':raise RadiusError('eap_helper_missing')
        if failure=='certificate':raise RadiusError('local_certificate_failure')
        return NativeObservation(AccessResult(2,((11,b'unsupported'),),PEER,bytes(16)),2,0,2,1,False,False)
    async def mab(*args,**kwargs):raise AssertionError('No local-error fallback')
    monkeypatch.setattr('switchlab.radius.native_exchange',eap);monkeypatch.setattr('switchlab.radius.mab_exchange',mab)
    await engine.execute('advance',{'duration_ms':1000});await run_workers(engine)
    assert len(calls)==1 and not engine.state.radius_sessions
    assert engine.snapshot()['authentication_clients'][0]['status']=='failed'
    await engine.close_authentication()


@pytest.mark.asyncio
async def test_conflicting_eap_profiles_do_not_compete_but_mab_ignores_them(configured):
    cfg,pid,eid=configured;source=cfg.endpoints[eid].sources[0]
    other=source.model_copy(deep=True);other.id='second';other.supplicant.identity='different'
    cfg.endpoints[eid].sources.append(other)
    engine=Engine(cfg);await engine.execute('advance',{'duration_ms':1000})
    assert not engine.state.radius_attempts and not engine.state.radius_sessions
    assert engine.snapshot()['authentication_clients'][0]['reason']=='profile-conflict'
    cfg.ports[pid].authentication.method='mab';engine=Engine(cfg)
    waiting=await engine.execute('advance',{'duration_ms':1000})
    assert waiting['advance']['status']=='waiting'
    assert len(engine.state.radius_attempts)==1 and next(iter(engine.state.radius_attempts.values())).method=='mab'


@pytest.mark.asyncio
async def test_explicit_reject_fallback_is_immediate_even_without_ordinary_traffic(configured,monkeypatch):
    cfg,pid,eid=configured;cfg.endpoints[eid].active=False
    cfg.radius.servers=[RadiusServer(label='Synthetic',address=PEER[0],secret='synthetic-shared')]
    cfg.ports[pid].authentication.fallback_reject=True;engine=Engine(cfg);calls=[]
    async def eap(*args,**kwargs):calls.append('eap');return NativeObservation(AccessResult(3,(),PEER,bytes(16)),1,0,2,1,False,False)
    async def mab(*args,**kwargs):calls.append('mab');return NativeObservation(AccessResult(2,(),PEER,bytes(16)),0,0,0,0,False,False)
    monkeypatch.setattr('switchlab.radius.native_exchange',eap);monkeypatch.setattr('switchlab.radius.mab_exchange',mab)
    await engine.execute('advance',{'duration_ms':1000});await run_workers(engine)
    await run_workers(engine);await engine.continue_advance()
    assert calls==['eap','mab'] and engine.state.radius_sessions
    assert engine.state.sim_ms==1000 and not engine.state.fdb and engine.state.counters[pid]['in_ucast']==0
    await engine.close_authentication()
