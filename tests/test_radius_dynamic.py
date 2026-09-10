import asyncio,base64,copy,hashlib,json,sqlite3
import pytest
from switchlab.engine import Engine,AccessSession
from switchlab.models import initial_configuration,DynamicSender,Vlan,Port
from switchlab.radius import Authorization,NasIdentity,DynamicListener,packet_attributes
from test_radius_codec import signed_request,signed_response,SECRET

MAC='02:00:00:00:00:11'
class Transport:
    def __init__(self):self.messages=[];self.closed=False
    def sendto(self,packet,peer):self.messages.append((bytes(packet),peer))
    def close(self):self.closed=True


def configured_engine(store=None):
    cfg=initial_configuration(1);cfg.paused=True
    pid=next(iter(cfg.ports));cfg.ports[pid].mode='shared';cfg.ports[pid].shared_partner=True;cfg.ports[pid].authentication.control='auto'
    cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020)
    cfg.radius.dynamic_authorization.enabled=True
    sender=DynamicSender(label='Synthetic sender',address='192.0.2.4',secret=SECRET.decode());cfg.radius.dynamic_authorization.senders=[sender]
    engine=Engine(cfg,store);wall=[1000.0];elapsed=[10.0];engine._das_wall=lambda:wall[0];engine._das_clock=lambda:elapsed[0]
    session=AccessSession('session-one',pid,MAC,'mab',Authorization(1,'port-default'),nas_identity=NasIdentity(b'Switch Lab'),user_name=b'user')
    engine.state.radius_sessions[(pid,MAC)]=session
    protocol=DynamicListener(engine,engine._dynamic_binding());protocol.transport=Transport();engine._das_protocol=protocol
    return engine,protocol,pid,sender,wall,elapsed


def request(values=(),code=43,identifier=7,timestamp=1000):
    return signed_request(code,identifier,((31,MAC.encode()),*values,(55,timestamp.to_bytes(4,'big'))),secret=SECRET)


async def send(engine,protocol,packet,peer=('192.0.2.4',40000)):
    before=len(protocol.transport.messages)
    engine.receive_dynamic(protocol,packet,peer)
    tasks=[item['task'] for item in engine._das_pending.values()]
    if tasks:await asyncio.gather(*tasks)
    return [data for data,address in protocol.transport.messages[before:]]


def vlan(vid=20):return ((64,(13).to_bytes(4,'big')),(65,(6).to_bytes(4,'big')),(81,str(vid).encode()))


@pytest.mark.asyncio
async def test_authenticated_atomic_coa_persists_before_reply_and_replays_without_effect(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    packet=request(vlan()+((24,b'private-state'),(33,b'proxy')))
    messages=await send(engine,protocol,packet);assert len(messages)==1 and messages[0][0]==44
    assert engine.state.session_vid(engine.state.radius_sessions[(pid,MAC)])==20
    assert len(store.radius_decisions())==1 and not engine._das_pending
    expected=signed_response(packet,44,((24,b'private-state'),(33,b'proxy')),ma=True,secret=SECRET)
    assert messages[0]==expected
    before=engine.state
    messages2=await send(engine,protocol,packet+b'ignored-padding')
    assert messages2==messages and engine.state is before
    assert b'private-state' not in bytes(store.db.execute('SELECT value FROM radius_das').fetchone()[0])
    assert 'private-state' not in json.dumps(engine.snapshot())


@pytest.mark.asyncio
async def test_nak_preserves_all_runtime_and_valid_or_malformed_state(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    for i,fields in enumerate([((24,b'a'),(24,b'b')),((24,b''),),((24,b'valid'),(11,b'unsupported'))]):
        packet=request(fields+((33,b'proxy'),),identifier=20+i)
        before=engine.state;revision=store.get('revision');messages=await send(engine,protocol,packet)
        assert messages[0][0]==45 and engine.state is before and store.get('revision')==revision
        _,attrs=packet_attributes(messages[0]);cause=int.from_bytes(next(v for k,v in attrs if k==101),'big')
        assert cause==(401 if i==2 else 404)
        assert [v for k,v in attrs if k==24]==([b'valid'] if i==2 else [])
        assert [v for k,v in attrs if k==33]==[b'proxy']


@pytest.mark.asyncio
async def test_inflight_duplicate_joins_one_reservation(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);packet=request(vlan())
    await engine.lock.acquire()
    try:
        engine.receive_dynamic(protocol,packet,('192.0.2.4',40000))
        engine.receive_dynamic(protocol,packet+b'padding',('192.0.2.4',40000))
        assert len(engine._das_pending)==1 and not protocol.transport.messages
    finally:engine.lock.release()
    await asyncio.gather(*(item['task'] for item in engine._das_pending.values()))
    assert len(protocol.transport.messages)==1 and len(engine._das_cache)==1


@pytest.mark.asyncio
async def test_sender_secret_aba_keeps_old_fingerprint_retired(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);packet=request(code=40)
    engine.receive_dynamic(protocol,packet,('192.0.2.4',40000))
    await engine.execute('dynamic-sender-save',{'id':sender.id,'secret':'replacement'})
    await engine.execute('dynamic-sender-save',{'id':sender.id,'secret':SECRET.decode()})
    if engine._das_pending:await asyncio.gather(*(item['task'] for item in engine._das_pending.values()))
    assert engine.state.radius_sessions and not protocol.transport.messages
    assert len(engine._das_cache)==1 and len(store.radius_decisions())==1
    before=engine.state;assert await send(engine,protocol,packet+b'padding')==[] and engine.state is before


@pytest.mark.asyncio
async def test_restart_cached_disconnect_cannot_remove_replacement(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);packet=request(code=40)
    first=await send(engine,protocol,packet);assert first[0][0]==41 and not engine.state.radius_sessions
    restored=Engine(store.load(),store);restored._das_wall=lambda:1001.;restored._das_clock=lambda:11.
    replacement=AccessSession('replacement',pid,MAC,'mab',Authorization(1,'port-default'),nas_identity=NasIdentity(b'Switch Lab'))
    restored.state.radius_sessions[(pid,MAC)]=replacement
    p=DynamicListener(restored,restored._dynamic_binding());p.transport=Transport();restored._das_protocol=p
    before=restored.state;assert await send(restored,p,packet)==first
    assert restored.state is before and restored.state.radius_sessions[(pid,MAC)].id=='replacement'


@pytest.mark.asyncio
async def test_timestamp_equality_future_retention_and_backward_clock(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);packet=request(identifier=1,timestamp=1300)
    first=await send(engine,protocol,packet);assert first and len(engine._das_cache)==1
    wall[0]=1600.;elapsed[0]=610.;assert await send(engine,protocol,packet)==first
    wall[0]=1600.1;elapsed[0]=610.1;await engine.prune_dynamic()
    assert not engine._das_cache and store.get('radius_replay_high_water')>=1600.1
    wall[0]=1400.;before=engine.state;assert not engine.dynamic_clock_safe()
    assert await send(engine,protocol,packet)==[] and engine.state is before
    await engine.execute('switch-edit',{'location':'unrelated service remains usable'})
    assert engine.state.cfg.switch.location=='unrelated service remains usable'
    wall[0]=1600.1;assert engine.dynamic_clock_safe()
    assert await send(engine,protocol,packet)==[]


@pytest.mark.asyncio
async def test_invalid_source_integrity_time_never_allocate_or_match(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);before=engine.state
    packet=request();bad=packet[:-1]+bytes((packet[-1]^1,))
    assert await send(engine,protocol,packet,peer=('192.0.2.6',40000))==[]
    assert await send(engine,protocol,bad)==[]
    assert await send(engine,protocol,request(timestamp=699))==[]
    assert await send(engine,protocol,request(timestamp=1301))==[]
    assert not engine._das_cache and not engine._das_pending and engine.state is before


@pytest.mark.asyncio
async def test_real_sql_failure_has_no_ack_effect_or_receipt(store,monkeypatch):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);before=engine.state
    original=store._radius_metadata
    def fail(changes):
        original(changes)
        raise sqlite3.OperationalError('synthetic post-insert failure')
    monkeypatch.setattr(store,'_radius_metadata',fail)
    assert await send(engine,protocol,request(vlan()))==[]
    assert engine.state is before and not engine._das_cache and not store.radius_decisions()
    assert not store.db.in_transaction and not store.fault_reason


@pytest.mark.asyncio
async def test_expired_pending_reservation_never_gets_a_new_lifetime(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    packet=request(vlan(),timestamp=1300)
    await engine.lock.acquire()
    engine.receive_dynamic(protocol,packet,('192.0.2.4',40000))
    task=next(iter(engine._das_pending.values()))['task']
    wall[0]=1600.1;elapsed[0]=610.1;wall[0]=1000.
    engine.lock.release();await task
    assert not protocol.transport.messages
    before=engine.state
    assert await send(engine,protocol,packet)==[] and engine.state is before
    assert store.get('radius_replay_high_water')>1600 and not engine.dynamic_clock_safe()


@pytest.mark.asyncio
async def test_failed_expired_reservation_retirement_keeps_ownership(store,monkeypatch):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store);packet=request(timestamp=1300)
    await engine.lock.acquire();engine.receive_dynamic(protocol,packet,('192.0.2.4',40000))
    task=next(iter(engine._das_pending.values()))['task'];elapsed[0]=610.1
    original=store._radius_metadata
    def fail(changes):original(changes);raise sqlite3.OperationalError('synthetic retirement failure')
    monkeypatch.setattr(store,'_radius_metadata',fail)
    engine.lock.release();await task
    assert len(engine._das_pending)==1 and not engine._das_cache and not store.db.in_transaction
    assert await send(engine,protocol,packet)==[]
    monkeypatch.setattr(store,'_radius_metadata',original)
    await engine.prune_dynamic()
    assert not engine._das_pending and store.get('radius_replay_high_water')>1600


@pytest.mark.asyncio
async def test_closing_pending_request_retains_tombstone_before_waiter_removal(store):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    packet=request(code=40)
    await engine.lock.acquire()
    engine.receive_dynamic(protocol,packet,('192.0.2.4',40000))
    pending_task=next(iter(engine._das_pending.values()))['task']
    await asyncio.sleep(0)  # The handler waits ahead of close_dynamic on the lock.
    closing=asyncio.create_task(engine.close_dynamic())
    await asyncio.sleep(0)
    engine.lock.release()
    await closing
    assert protocol.transport.closed and pending_task.done() and not engine._das_pending
    assert engine.state.radius_sessions and not protocol.transport.messages
    assert len(store.radius_decisions())==1
    restored=Engine(engine.state.cfg,store);restored._das_wall=lambda:1001.;restored._das_clock=lambda:11.
    restored.state.radius_sessions[(pid,MAC)]=AccessSession('replacement',pid,MAC,'mab',Authorization(1,'port-default'),nas_identity=NasIdentity(b'Switch Lab'))
    new_protocol=DynamicListener(restored,restored._dynamic_binding());new_protocol.transport=Transport();restored._das_protocol=new_protocol
    before=restored.state
    assert await send(restored,new_protocol,packet)==[] and restored.state is before


@pytest.mark.asyncio
async def test_full_replay_cache_drops_new_work_without_evicting_cached_reply(store,monkeypatch):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    packet=request(vlan());first=await send(engine,protocol,packet)
    original=next(iter(engine._das_cache));record=engine._das_cache[original]
    for i in range(4095):engine._das_cache[f'{i:064x}']={**record,'response':None}
    assert len(engine._das_cache)==4096
    def forbidden(*args,**kwargs):raise AssertionError('Cache-full input must not reach session matching')
    monkeypatch.setattr('switchlab.radius.plan_dynamic_request',forbidden)
    before=engine.state
    assert await send(engine,protocol,request(code=40,identifier=8))==[]
    assert engine._das_drops['cache-full']==1 and not engine._das_pending and engine.state is before
    assert await send(engine,protocol,packet)==first and engine.state is before
    assert engine._das_cache[original] is record and len(engine._das_cache)==4096


@pytest.mark.asyncio
async def test_failed_close_retirement_preserves_reservation_until_successful_retry(store,monkeypatch):
    engine,protocol,pid,sender,wall,elapsed=configured_engine(store)
    await engine.lock.acquire();engine.receive_dynamic(protocol,request(code=40),('192.0.2.4',40000))
    await asyncio.sleep(0)
    original=store._radius_metadata
    def fail(changes):original(changes);raise sqlite3.OperationalError('synthetic close retirement failure')
    monkeypatch.setattr(store,'_radius_metadata',fail)
    closing=asyncio.create_task(engine.close_dynamic());await asyncio.sleep(0);engine.lock.release()
    with pytest.raises(sqlite3.OperationalError):await closing
    assert not store.db.in_transaction and not store.fault_reason
    assert len(engine._das_pending)==1 and not store.radius_decisions()
    assert not protocol.transport.messages and engine.state.radius_sessions
    monkeypatch.setattr(store,'_radius_metadata',original)
    await engine.close_dynamic()
    assert not engine._das_pending and len(store.radius_decisions())==1 and protocol.transport.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("restore", ["process", "reboot"])
async def test_startup_trust_restore_keeps_durable_replay_and_new_generation(store, restore):
    engine,protocol,pid,sender,wall,elapsed = configured_engine(store)
    packet=request(code=40)
    first=await send(engine,protocol,packet)
    assert first[0][0] == 41
    receipt=copy.deepcopy(store.radius_decisions())
    first_generation=engine._das_generations[sender.id]["generation"]
    with store.transaction():
        store.put("admin_hash","synthetic-manager-hash")
        store.put("engine_identity","40000102030405060708090a0b")
        store.put("engine_boots",9)
    await engine.execute("dynamic-sender-save",{"id":sender.id,"secret":"unsaved-trust"})
    middle_generation=engine._das_generations[sender.id]["generation"]
    assert first_generation != middle_generation
    highwater=store.get("radius_replay_high_water",0)
    if restore == "process":
        engine=Engine(store.load(),store);engine._das_wall=lambda:1001.;engine._das_clock=lambda:11.
    else: await engine.execute("reboot")
    assert engine._das_generations[sender.id]["generation"] not in (first_generation,middle_generation)
    assert engine.state.cfg.radius.dynamic_authorization.senders[0].secret == SECRET.decode()
    assert store.radius_decisions() == receipt and store.get("radius_replay_high_water",0) >= highwater
    assert store.get("admin_hash") == "synthetic-manager-hash" and store.get("engine_boots") == 9
    assert store.get("engine_identity") == "40000102030405060708090a0b"
    replacement=AccessSession("replacement",pid,MAC,"mab",Authorization(1,"port-default"),nas_identity=NasIdentity(b"Switch Lab"))
    engine.state.radius_sessions[(pid,MAC)] = replacement
    p=DynamicListener(engine,engine._dynamic_binding());p.transport=Transport();engine._das_protocol=p
    before=engine.state
    assert await send(engine,p,packet) == [] and engine.state is before
    assert engine.state.radius_sessions[(pid,MAC)].id == "replacement"
