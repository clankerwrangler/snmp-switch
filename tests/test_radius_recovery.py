import asyncio
import pytest
from switchlab.engine import Engine
from switchlab.models import RadiusServer,Source
from switchlab.radius import AccessResult,NativeObservation,RadiusError
from test_radius_engine import configured,begin,PEER


def exhausted(attempts=3,**kw):
    return NativeObservation(None,0,0,0,0,True,False,unanswered_retries=attempts,**kw)


@pytest.mark.asyncio
async def test_backoff_sequence_and_authenticated_reject_recovery(configured):
    cfg,pid,eid=configured;server=RadiusServer(label='Primary',address=PEER[0],secret='synthetic')
    cfg.radius.servers=[server];engine=Engine(cfg);clock=[0.0];engine._auth_clock=lambda:clock[0]
    async def fail(*args,**kwargs):return exhausted()
    for number,expected in enumerate((1,2,4,8,16,30,30)):
        capture=await begin(engine,pid,eid)
        result=await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=fail)
        assert not result['accepted']
        health=engine._server_health[server.id]
        assert health.available is False and health.probe_after-clock[0]==expected and health.probe_owner is None
        assert engine.state.radius_status[(pid,capture['mac'])]['retry_at_ms']==engine.state.sim_ms+60000
        clock[0]=health.probe_after
        await engine.continue_advance()
        if number < 6:await engine.execute('advance',{'duration_ms':60000})
    async def reject(*args,**kwargs):return NativeObservation(AccessResult(3,(),PEER,bytes(16)),1,0,0,0,False,False)
    capture=await begin(engine,pid,eid)
    await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=reject)
    assert engine._server_health[server.id].available and engine._server_health[server.id].failures==0
    assert not engine.state.radius_sessions


@pytest.mark.asyncio
async def test_one_expired_primary_probe_and_available_backup(configured):
    cfg,pid,eid=configured;cfg.ports[pid].authentication.host_mode='multi-auth'
    first=cfg.endpoints[eid].sources[0]
    second=first.model_copy(deep=True);second.id='second';second.mac='02:00:00:00:00:12';cfg.endpoints[eid].sources.append(second)
    primary=RadiusServer(label='Primary',address='192.0.2.1',secret='synthetic')
    backup=RadiusServer(label='Backup',address='192.0.2.2',secret='synthetic')
    cfg.radius.servers=[primary,backup];engine=Engine(cfg);clock=[0.0];engine._auth_clock=lambda:clock[0]
    capture=await begin(engine,pid,eid);health=engine._take_server(primary,capture['attempt_id'])
    engine._server_exhausted(primary.id,health,(pid,first.mac),capture['attempt_id'])
    assert engine._take_server(primary,capture['attempt_id']) is None
    clock[0]=1.0;entered,release=asyncio.Event(),asyncio.Event();seen=[]
    async def exchange(settings,server,*args,**kwargs):
        seen.append(server.id)
        if server.id==primary.id:
            entered.set();await release.wait()
        return NativeObservation(AccessResult(3,(),(server.address,server.port),bytes(16)),1,0,0,0,False,False)
    task=asyncio.create_task(engine.authenticate(pid,first.mac,capture['attempt_id'],exchange=exchange));await entered.wait()
    capture2=await engine.execute('radius-begin',{'port_id':pid,'mac':second.mac})
    await engine.authenticate(pid,second.mac,capture2['attempt_id'],exchange=exchange)
    assert seen==[primary.id,backup.id] and engine._server_health[backup.id].available
    release.set();await task
    assert engine._server_health[primary.id].available and health.probe_owner is None


@pytest.mark.asyncio
async def test_challenge_reachability_precedes_terminal_and_later_exhaustion(configured):
    cfg,pid,eid=configured;server=RadiusServer(label='Primary',address=PEER[0],secret='synthetic');cfg.radius.servers=[server]
    engine=Engine(cfg);capture=await begin(engine,pid,eid)
    async def exchange(*args,**kwargs):
        kwargs['on_response']()
        assert engine._server_health[server.id].available
        assert not engine.state.radius_sessions
        return NativeObservation(None,0,0,2,1,True,False,unanswered_retries=3)
    await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange)
    assert engine._server_health[server.id].available is False and engine._server_health[server.id].failures==1


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['helper','certificate','deadline','cancel'])
async def test_local_or_cancel_outcome_does_not_mark_server_down(configured,kind):
    cfg,pid,eid=configured;server=RadiusServer(label='Primary',address=PEER[0],secret='synthetic');cfg.radius.servers=[server]
    engine=Engine(cfg);capture=await begin(engine,pid,eid)
    async def exchange(*args,**kwargs):
        if kind=='helper':raise RadiusError('eap_helper_missing')
        if kind=='cancel':raise asyncio.CancelledError()
        if kind=='certificate':return NativeObservation(None,1,1,1,0,True,False,unanswered_retries=3)
        return exhausted(1)
    if kind=='cancel':
        with pytest.raises(asyncio.CancelledError):await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange)
    else:await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange)
    assert engine._server_health[server.id].available is None and engine._server_health[server.id].probe_owner is None


@pytest.mark.asyncio
async def test_closed_callback_and_replaced_generation_cannot_update_health(configured):
    cfg,pid,eid=configured;primary=RadiusServer(label='Primary',address='192.0.2.1',secret='synthetic');backup=RadiusServer(label='Backup',address='192.0.2.2',secret='synthetic')
    cfg.radius.servers=[primary,backup];engine=Engine(cfg);capture=await begin(engine,pid,eid)
    callbacks=[];entered,release=asyncio.Event(),asyncio.Event()
    async def exchange(settings,server,*args,**kwargs):
        callbacks.append(kwargs['on_response'])
        if server.id==primary.id:return exhausted()
        entered.set();await release.wait();return exhausted()
    task=asyncio.create_task(engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange));await entered.wait()
    old=engine._server_health[primary.id];callbacks[0]()
    assert old.available is False and engine._server_health[backup.id].available is None
    # Owner-level replacement fixture; no production cache or stored data seeding.
    engine.state.cfg.radius.servers[0].secret='replacement';engine._sync_server_health()
    replacement=engine._server_health[primary.id];assert replacement is not old
    callbacks[0]();assert replacement.available is None
    release.set();await task
    assert replacement.available is None
