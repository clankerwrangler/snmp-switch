import copy

import pytest
from switchlab.engine import Engine, CommandError
from switchlab.radius import AccessResult
from switchlab.storage import StorageFault
from test_radius_engine import configured, begin, PEER


@pytest.mark.asyncio
async def test_one_advance_waits_and_resumes_from_actual_time(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    revision=engine.state.revision
    waiting=await engine.execute("advance",{"duration_ms":5000},expected=revision,key="advance-one")
    op=waiting["advance"]
    assert op["status"]=="waiting" and op["start_ms"]==op["reached_ms"]==engine.state.sim_ms==0 and op["target_ms"]==5000
    assert await engine.execute("advance",{"duration_ms":5000},expected=revision,key="advance-one")==waiting
    before=engine.state
    await engine.execute("advance",{"duration_ms":100,"automatic":True})
    assert engine.state is before
    for action,payload in [("resume",{}),("advance",{"duration_ms":1})]:
        with pytest.raises(CommandError):await engine.execute(action,payload)
    await engine.execute("pause")
    assert engine.state.advance_operation["status"]=="waiting"
    await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    assert engine.state.sim_ms==0
    await engine.continue_advance()
    assert engine.state.sim_ms==5000 and engine.state.cfg.paused
    assert engine.advance_status()["status"]=="completed" and len(engine.state.fdb)==1
    repeated=await engine.execute("advance",{"duration_ms":5000},expected=revision,key="advance-one")
    assert repeated["advance"]["id"]==op["id"] and repeated["advance"]["status"]=="completed" and repeated["simulation_ms"]==5000


@pytest.mark.asyncio
async def test_scoped_cancel_preserves_time_and_independent_authentication(configured):
    cfg,pid,eid=configured;cfg.ports[pid].authentication.control="force-authorized";engine=Engine(cfg)
    await engine.execute("advance",{"duration_ms":1000})
    await engine.execute("port-edit",{"id":pid,"patch":{"authentication":{"control":"auto"}}})
    capture=await begin(engine,pid,eid)
    first=await engine.execute("advance",{"duration_ms":5000},key="old")
    before_attempt=engine.state.radius_attempts[(pid,capture["mac"])]
    await engine.execute("advance-cancel",{"id":first["advance"]["id"]})
    assert engine.state.sim_ms==1000 and engine.state.radius_attempts[(pid,capture["mac"])].id==before_attempt.id
    next_op=await engine.execute("advance",{"duration_ms":7000},key="new")
    before=engine.state
    with pytest.raises(CommandError):await engine.execute("advance-cancel",{"id":first["advance"]["id"]})
    assert engine.state is before
    old=await engine.execute("advance",{"duration_ms":5000},key="old")
    assert old["advance"]["status"]=="canceled" and old["advance"]["id"]!=next_op["advance"]["id"]
    await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    await engine.continue_advance()
    assert engine.state.sim_ms==8000


@pytest.mark.asyncio
@pytest.mark.parametrize("restart",[False,True])
async def test_old_operation_cannot_resume_or_cancel_after_boot(configured,store,restart):
    cfg,pid,eid=configured;engine=Engine(cfg,store);await begin(engine,pid,eid)
    first=await engine.execute("advance",{"duration_ms":5000},key="old")
    if restart:engine=Engine(store.load(),store)
    else:await engine.execute("reboot")
    old=await engine.execute("advance",{"duration_ms":5000},key="old")
    assert old["advance"]["status"]=="interrupted-on-boot" and not engine.state.radius_sessions
    await begin(engine,pid,eid);new=await engine.execute("advance",{"duration_ms":1000})
    assert new["advance"]["id"]!=first["advance"]["id"]
    before=engine.state
    with pytest.raises(CommandError):await engine.execute("advance-cancel",{"id":first["advance"]["id"]})
    assert engine.state is before


@pytest.mark.asyncio
async def test_storage_fault_blocks_remaining_advance_and_late_grant(configured,store):
    cfg,pid,eid=configured;engine=Engine(cfg,store);capture=await begin(engine,pid,eid)
    await engine.execute("advance",{"duration_ms":5000})
    before=engine.state;store._fault("storage_commit_unknown")
    assert engine.advance_status()["status"]=="failed-on-storage"
    with pytest.raises(StorageFault):await engine.continue_advance()
    with pytest.raises(StorageFault):await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    assert engine.state is before and not engine.state.radius_sessions


@pytest.mark.asyncio
async def test_existing_work_budget_preflight_and_later_guard_failure(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    source=engine.state.cfg.endpoints[eid].sources[0]
    fields=source.model_dump();fields["interval_ms"]=1
    await engine.execute("endpoint-edit",{"id":eid,"patch":{"sources":[fields]}})
    capture=await begin(engine,pid,eid);before=engine.state
    with pytest.raises(CommandError) as failure:await engine.execute("advance",{"duration_ms":86400000})
    assert failure.value.status==429 and engine.state is before and engine.state.advance_operation is None
    fields["interval_ms"]=30000
    await engine.execute("endpoint-edit",{"id":eid,"patch":{"sources":[fields]}})
    capture=await begin(engine,pid,eid)
    await engine.execute("advance",{"duration_ms":86400000})
    fields["interval_ms"]=1
    await engine.execute("endpoint-edit",{"id":eid,"patch":{"sources":[fields]}})
    assert not engine.state.radius_attempts
    await engine.continue_advance()
    assert engine.advance_status()["status"]=="failed-on-guard" and engine.state.sim_ms==0


@pytest.mark.asyncio
async def test_worker_holds_timeline_and_publishes_before_continuing(configured,monkeypatch):
    import asyncio
    from switchlab.models import RadiusServer
    from switchlab.radius import NativeObservation
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared")]
    engine=Engine(cfg);started,release=asyncio.Event(),asyncio.Event()
    async def exchange(*args,**kwargs):
        assert not engine.lock.locked()
        started.set();await release.wait()
        return NativeObservation(AccessResult(2,(),PEER,bytes(16)),2,0,5,2,False,False)
    monkeypatch.setattr("switchlab.radius.native_exchange",exchange)
    waiting=await engine.execute("advance",{"duration_ms":5000})
    await engine.service_authentication();await started.wait()
    before=engine.state
    await engine.execute("advance",{"duration_ms":1000,"automatic":True})
    assert engine.state is before and engine.state.sim_ms==0 and not engine.state.fdb
    release.set();await asyncio.gather(*engine._authentication_tasks.values())
    assert engine.state.sim_ms==0 and engine.state.radius_sessions
    await engine.continue_advance()
    assert engine.state.sim_ms==5000 and len(engine.state.fdb)==1
    await engine.close_authentication()


@pytest.mark.asyncio
async def test_worker_bounds_and_cancellation_do_not_hold_engine_lock(configured,monkeypatch):
    import asyncio
    from switchlab.models import RadiusServer,Source
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared")]
    cfg.ports[pid].authentication.host_mode="multi-auth"
    profile=cfg.endpoints[eid].sources[0].supplicant
    cfg.endpoints[eid].sources=[Source(mac=f"02:00:00:00:00:{n:02x}",supplicant=profile.model_copy(deep=True)) for n in range(1,10)]
    engine=Engine(cfg);entered=[];cancelled=[];all_started=asyncio.Event()
    async def exchange(*args,**kwargs):
        assert not engine.lock.locked();entered.append(args[4])
        if len(entered)==8:all_started.set()
        try:await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(.01);cancelled.append(args[4]);raise
    monkeypatch.setattr("switchlab.radius.native_exchange",exchange)
    await engine.execute("advance",{"duration_ms":5000});await engine.service_authentication();await all_started.wait()
    assert len(engine.state.radius_attempts)==len(engine._authentication_tasks)==8
    await engine.close_authentication()
    assert len(cancelled)==8 and not engine._authentication_tasks and not engine.state.radius_sessions
    with pytest.raises(CommandError):await engine.execute("advance",{"duration_ms":1})


@pytest.mark.asyncio
async def test_retry_cooldown_is_a_causal_boundary_not_wall_time(configured,monkeypatch):
    import asyncio
    from switchlab.models import RadiusServer
    from switchlab.radius import NativeObservation
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared")]
    engine=Engine(cfg);calls=[]
    async def exchange(*args,**kwargs):
        calls.append(engine.state.sim_ms)
        return NativeObservation(AccessResult(3 if len(calls)==1 else 2,(),PEER,bytes(16)),0,0,0,0,False,False)
    monkeypatch.setattr("switchlab.radius.native_exchange",exchange)
    await engine.execute("advance",{"duration_ms":65000});await engine.service_authentication()
    await asyncio.gather(*engine._authentication_tasks.values())
    assert calls==[0] and not engine.state.radius_sessions
    await engine.continue_advance()
    assert engine.state.sim_ms==60000 and engine.advance_status()["status"]=="waiting"
    await engine.service_authentication();await asyncio.gather(*engine._authentication_tasks.values())
    await engine.continue_advance()
    assert calls==[0,60000] and engine.state.sim_ms==65000 and engine.state.radius_sessions
    await engine.close_authentication()
