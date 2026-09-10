import asyncio,base64,copy,json
import pytest
from switchlab.engine import Engine
from switchlab.models import RadiusServer
from switchlab.radius import AccessResult,authorization
from test_radius_engine import configured,begin,PEER
from test_radius_timers import controls,grant


def attributes(record):return [(kind,base64.b64decode(value)) for kind,value in record['attributes']]
def number(record,kind):return int.from_bytes(next(value for k,value in attributes(record) if k==kind),'big')


@pytest.mark.asyncio
async def test_chronological_cumulative_snapshots_and_standard_start_stop_fields(configured):
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True;cfg.radius.accounting.interim_seconds=60
    cfg.radius.accounting.targets=[RadiusServer(label='Collector',address='192.0.2.5',port=1813,secret='synthetic-accounting')]
    engine=Engine(cfg);capture=await grant(engine,pid,eid,controls())
    await engine.execute('advance',{'duration_ms':180000})
    records=engine.state.accounting_outbox
    assert [r['status_type'] for r in records]==[7,1,3,3,3]
    start=records[1];assert not {42,43,46,47,48,49,52,53} & {kind for kind,value in attributes(start)}
    interims=[r for r in records if r['status_type']==3]
    assert [r['simulation_ms'] for r in interims]==[60000,120000,180000]
    assert [number(r,46) for r in interims]==[60,120,180]
    assert [number(r,47) for r in interims]==[2,4,6]
    assert [number(r,42) for r in interims]==[128,256,384]
    assert all(not {43,48,49,53} & {kind for kind,value in attributes(r)} for r in interims)
    sid=engine.state.radius_sessions[(pid,capture['mac'])].id
    await engine.execute('radius-session-action',{'id':sid,'action':'restart'})
    stop=next(r for r in engine.state.accounting_outbox if r['status_type']==2)
    assert number(stop,46)==180 and number(stop,47)==6 and number(stop,49)==6
    assert engine.state.up(pid)


@pytest.mark.asyncio
async def test_same_time_termination_prevents_post_stop_interim(configured):
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True;cfg.radius.accounting.interim_seconds=60
    cfg.radius.accounting.targets=[RadiusServer(label='Collector',address='192.0.2.5',secret='synthetic')]
    engine=Engine(cfg);await grant(engine,pid,eid,controls(lease=120))
    await engine.execute('advance',{'duration_ms':120000})
    records=[r for r in engine.state.accounting_outbox if r['status_type'] in (2,3)]
    assert [(r['status_type'],r['simulation_ms']) for r in records]==[(3,60000),(2,120000)]
    assert number(records[-1],49)==5 and not engine.state.radius_sessions


@pytest.mark.parametrize('values,expected,warning',[
    ([(85,(60).to_bytes(4,'big'))],60,None), ([(85,(59).to_bytes(4,'big'))],None,'invalid-server-interim-interval'),
    ([(85,bytes(4))],None,'invalid-server-interim-interval'), ([(85,b'x')],None,'invalid-server-interim-interval'),
    ([(85,(60).to_bytes(4,'big')),(85,(60).to_bytes(4,'big'))],None,'invalid-server-interim-interval')])
def test_server_interim_option_never_changes_access_result(configured,values,expected,warning):
    cfg,pid,eid=configured;result=AccessResult(2,tuple(values),PEER,bytes(16))
    policy=authorization(result,cfg.ports[pid],cfg.vlans)
    assert policy.vid==1 and policy.interim_seconds==expected and policy.accounting_warning==warning


@pytest.mark.asyncio
async def test_local_accounting_precedence_late_enable_and_config_cancellation(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    capture=await grant(engine,pid,eid,controls())
    await engine.execute('advance',{'duration_ms':30000})
    sid=engine.state.radius_sessions[(pid,capture['mac'])].id
    await engine.execute('accounting-target-save',{'label':'Collector','address':'192.0.2.5','secret':'synthetic'})
    await engine.execute('accounting-settings',{'enabled':True,'interim_seconds':60})
    start=engine.state.accounting_outbox[0]
    assert start['late'] and start['session_id']==sid and start['original_start_ms']==0 and start['simulation_ms']==30000
    assert start['cumulative_packets']==1 and not {46,47,42} & {k for k,v in attributes(start)}
    before_ids=[r['id'] for r in engine.state.accounting_outbox]
    target=engine.state.cfg.radius.accounting.targets[0]
    await engine.execute('accounting-target-save',{'id':target.id,'label':'Renamed','secret':''})
    assert [r['id'] for r in engine.state.accounting_outbox]==before_ids
    await engine.execute('accounting-target-save',{'id':target.id,'secret':'replacement'})
    assert not set(before_ids) & {r['id'] for r in engine.state.accounting_outbox}
    assert engine.state.accounting_drops['configuration-change']==len(before_ids)
    assert engine.state.radius_sessions[(pid,capture['mac'])].id==sid
    await engine.execute('accounting-settings',{'enabled':False})
    assert not engine.state.accounting_outbox and engine.state.radius_sessions


@pytest.mark.asyncio
async def test_wire_head_serialization_and_original_retention(configured,monkeypatch):
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True;cfg.radius.accounting.interim_seconds=60
    cfg.radius.accounting.targets=[RadiusServer(label='Collector',address='192.0.2.5',secret='synthetic')]
    engine=Engine(cfg);await grant(engine,pid,eid,controls());await engine.execute('advance',{'duration_ms':180000})
    entered=[];release=asyncio.Event()
    async def delivery(record,targets,**kwargs):
        entered.append(record['id']);await release.wait();return True,record['targets'][0]['id']
    monkeypatch.setattr('switchlab.radius.accounting_delivery',delivery)
    await engine.service_accounting();await asyncio.sleep(0)
    assert len(entered)==1 and engine.state.accounting_outbox[0]['status_type']==7
    release.set();await asyncio.gather(*engine._accounting_tasks.values())
    release=asyncio.Event();await engine.service_accounting();await asyncio.sleep(0)
    assert len(entered)==2 and len(engine._accounting_tasks)==1
    first=engine.state.accounting_outbox[0]
    engine._account_clock=lambda:first['generated_elapsed']+301
    await engine.service_accounting()
    await asyncio.gather(*engine._accounting_tasks.values(),return_exceptions=True)
    assert not engine.state.accounting_outbox and engine.state.accounting_drops['expired']>=4
    assert engine.state.radius_sessions


@pytest.mark.asyncio
@pytest.mark.parametrize('bound',['records','bytes'])
async def test_accounting_capacity_preserves_queue_and_access(configured,bound):
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True
    cfg.radius.accounting.targets=[RadiusServer(id=f'collector-{i}-'+('x'*700 if bound=='bytes' else ''),label='Collector',address='192.0.2.5',secret='synthetic') for i in range(16)]
    engine=Engine(cfg);capture=await grant(engine,pid,eid,controls())
    session=engine.state.radius_sessions[(pid,capture['mac'])]
    engine.state.queue_accounting(3,session)
    template=engine.state.accounting_outbox[-1]
    size=lambda record:len(json.dumps(record,sort_keys=True,separators=(',',':')).encode())
    records=[];used=0
    for i in range(1024):
        record={**template,'id':f'{i:036x}','sequence':i+1}
        if used+size(record)>8*1024*1024:break
        records.append(record);used+=size(record)
    assert len(records)==1024 if bound=='records' else len(records)<1024
    engine.state.accounting_outbox=records
    queued_ids=[record['id'] for record in records]
    engine.state.queue_accounting(3,session)
    assert [record['id'] for record in engine.state.accounting_outbox]==queued_ids
    assert engine.state.accounting_drops['overflow']==1
    assert engine.state.radius_sessions[(pid,capture['mac'])] is session


@pytest.mark.asyncio
async def test_accounting_delivery_policy_is_independent_captured_and_generation_checked(configured,monkeypatch):
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True
    cfg.radius.accounting.targets=[RadiusServer(label='Collector',address='192.0.2.5',secret='synthetic')]
    engine=Engine(cfg);capture=await grant(engine,pid,eid,controls())
    session_id=engine.state.radius_sessions[(pid,capture['mac'])].id
    pending=await begin(engine,pid,eid)
    ids=[record['id'] for record in engine.state.accounting_outbox]
    assert engine.state.accounting_outbox[-1]['delivery_policy']=={'response_timeout_seconds':3,'attempts':3,'retry_backoff_seconds':1}
    entered=asyncio.Event();cancelled=asyncio.Event()
    async def held(record,targets,**kwargs):
        entered.set()
        try:await asyncio.Future()
        except asyncio.CancelledError:cancelled.set();raise
    monkeypatch.setattr('switchlab.radius.accounting_delivery',held)
    await engine.service_accounting();await entered.wait()
    changes={'response_timeout_seconds':7,'attempts':2,'retry_backoff_seconds':0}
    await engine.execute('accounting-settings',changes)
    assert not set(ids)&{record['id'] for record in engine.state.accounting_outbox}
    assert engine.state.accounting_drops['configuration-change']==len(ids)
    assert engine.state.radius_sessions[(pid,capture['mac'])].id==session_id
    assert engine.state.current_attempt((pid,capture['mac']),pending['attempt_id'])
    assert engine.state.cfg.radius.response_timeout_seconds==3 and engine.state.cfg.radius.attempts==3
    assert engine.state.accounting_outbox[-1]['delivery_policy']==changes
    old_tasks=list(engine._accounting_tasks.values());await engine.service_accounting()
    await asyncio.gather(*old_tasks,return_exceptions=True);assert cancelled.is_set()
    new_ids=[record['id'] for record in engine.state.accounting_outbox]
    await engine.execute('accounting-settings',changes)
    await engine.execute('radius-settings',{'response_timeout_seconds':9})
    assert [record['id'] for record in engine.state.accounting_outbox]==new_ids
    for task in engine._accounting_tasks.values():task.cancel()
    await asyncio.gather(*engine._accounting_tasks.values(),return_exceptions=True)


@pytest.mark.asyncio
async def test_configured_accounting_attempts_timeout_backoff_and_ordered_failover(configured,monkeypatch):
    import socket
    from switchlab.radius import accounting_delivery
    from test_radius_codec import signed_response
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True
    cfg.radius.accounting.response_timeout_seconds=7;cfg.radius.accounting.attempts=2;cfg.radius.accounting.retry_backoff_seconds=4
    cfg.radius.accounting.targets=[RadiusServer(label=str(i),address=f'192.0.2.{5+i}',port=1813+i,secret='synthetic') for i in range(2)]
    engine=Engine(cfg);await grant(engine,pid,eid,controls());record=engine.state.accounting_outbox[-1]
    loop=asyncio.get_running_loop();sent=[];sleeps=[];timeouts=[];events=[]
    class UDP:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def setblocking(self,value):pass
        def bind(self,address):pass
    async def connect(udp,peer):udp.peer=peer
    async def sendto(udp,packet,peer):udp.request=packet;sent.append(peer);return len(packet)
    async def receive(udp,size):
        if udp.peer[1]==1813:raise TimeoutError()
        return signed_response(udp.request,5,(),ma=False,secret=b'synthetic')
    async def sleep(delay):sleeps.append(delay)
    real_timeout=asyncio.timeout
    def timeout(delay):timeouts.append(delay);return real_timeout(delay)
    async def event(phase,target):events.append((phase,target))
    monkeypatch.setattr(socket,'socket',lambda *args,**kwargs:UDP())
    monkeypatch.setattr(loop,'sock_connect',connect);monkeypatch.setattr(loop,'sock_sendto',sendto);monkeypatch.setattr(loop,'sock_recv',receive)
    monkeypatch.setattr(asyncio,'sleep',sleep);monkeypatch.setattr(asyncio,'timeout',timeout)
    targets={target.id:target for target in cfg.radius.accounting.targets}
    result=await accounting_delivery(record,targets,ready=lambda:True,elapsed=lambda:0,remaining=lambda:100,on_event=event)
    assert result==(True,cfg.radius.accounting.targets[1].id)
    assert sent==[('192.0.2.5',1813),('192.0.2.5',1813),('192.0.2.6',1814)]
    assert sleeps==[4] and timeouts==[100,7,7,7]
    assert [phase for phase,_ in events].count('no-valid-response')==2


@pytest.mark.asyncio
@pytest.mark.parametrize('blocked',['connect','receive','backoff'])
async def test_accounting_waits_end_at_original_retention_before_retry_or_failover(configured,monkeypatch,blocked):
    import socket,time
    from switchlab.radius import accounting_delivery
    cfg,pid,eid=configured;cfg.radius.accounting.enabled=True
    cfg.radius.accounting.targets=[RadiusServer(label=str(i),address=f'192.0.2.{5+i}',secret='synthetic') for i in range(2)]
    cfg.radius.accounting.response_timeout_seconds=60;cfg.radius.accounting.attempts=10;cfg.radius.accounting.retry_backoff_seconds=30
    engine=Engine(cfg);await grant(engine,pid,eid,controls());record=engine.state.accounting_outbox[-1]
    record['generated_elapsed']=engine._account_clock()-299.97
    record['generated_wall']=time.time()-299.97;record['expires_wall']=record['generated_wall']+300
    loop=asyncio.get_running_loop();sent=[];connected=[]
    class UDP:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def setblocking(self,value):pass
        def bind(self,address):pass
    async def connect(udp,peer):
        connected.append(peer)
        if blocked=='connect':await asyncio.Future()
    async def sendto(udp,packet,peer):sent.append(peer);return len(packet)
    async def receive(udp,size):
        if blocked=='backoff':raise TimeoutError()
        await asyncio.Future()
    async def event(*args):pass
    monkeypatch.setattr(socket,'socket',lambda *args,**kwargs:UDP())
    monkeypatch.setattr(loop,'sock_connect',connect);monkeypatch.setattr(loop,'sock_sendto',sendto);monkeypatch.setattr(loop,'sock_recv',receive)
    start=loop.time()
    result=await accounting_delivery(record,{target.id:target for target in cfg.radius.accounting.targets},ready=lambda:engine.accounting_current(record['id']) is not None,
        elapsed=lambda:engine._account_clock()-record['generated_elapsed'],remaining=lambda:engine.accounting_remaining(record),on_event=event)
    assert result is None and loop.time()-start<1
    assert len(connected)==1 and len(sent)==(0 if blocked=='connect' else 1)
    assert engine.accounting_remaining(record)==0 and engine.state.radius_sessions


@pytest.mark.asyncio
@pytest.mark.parametrize("restore", ["process", "reboot"])
@pytest.mark.parametrize("change", ["none", "secret", "delivery", "disable"])
async def test_startup_accounting_preserves_horizon_or_retires_revoked_records(configured, store, restore, change):
    cfg,pid,eid = configured
    target = RadiusServer(label="Collector",address="192.0.2.5",secret="saved-collector")
    cfg.radius.accounting.enabled=True;cfg.radius.accounting.targets=[target]
    engine=Engine(cfg,store)
    if change == "secret":
        await engine.execute("accounting-target-save",{"id":target.id,"secret":"unsaved-collector"})
    elif change == "delivery":
        await engine.execute("accounting-settings",{"attempts":2})
    elif change == "disable":
        await engine.execute("accounting-settings",{"enabled":False})
        await engine.execute("save-startup")
        await engine.execute("accounting-settings",{"enabled":True})
    await grant(engine,pid,eid,controls())
    original = copy.deepcopy(engine.state.accounting_outbox)
    assert original
    sequence = engine.state.accounting_sequence
    if restore == "process": engine=Engine(store.load(),store)
    else: await engine.execute("reboot")
    retained = {record["id"]:record for record in engine.state.accounting_outbox}
    if change == "none":
        for record in original:
            assert retained[record["id"]] == record
            assert engine.accounting_current(record["id"]) is not None
    else:
        assert not set(retained) & {r["id"] for r in original}
        assert engine.state.accounting_drops["configuration-change"] >= len(original)
    assert engine.state.accounting_sequence >= sequence
    if change != "disable":
        assert engine.state.accounting_outbox[-1]["status_type"] == 7
        assert engine.accounting_current(engine.state.accounting_outbox[-1]["id"]) is not None
    else: assert not engine.state.accounting_outbox
    assert not engine.state.radius_sessions
