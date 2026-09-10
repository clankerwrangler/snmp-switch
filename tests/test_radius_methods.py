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


# No real sockets: exercise the production MAB transport's stage/error boundary.
class MabSocketProbe:
    def __init__(self, monkeypatch, *, stage=None, error=None, replies=("accept",)):
        import socket
        self.trace, self.sent, self.request, self.closed = [], 0, None, False
        self.family = self.bound = None
        self.stage, self.error, self.replies = stage, error, iter(replies)
        monkeypatch.setattr(socket, "socket", self.socket)
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "sock_connect", self.connect)
        monkeypatch.setattr(loop, "sock_sendto", self.send)
        monkeypatch.setattr(loop, "sock_recv", self.receive)

    def at(self, stage):
        self.trace.append(stage)
        if self.stage == stage:
            raise self.error

    def socket(self, family, kind):
        import socket
        self.family = family
        assert kind == socket.SOCK_DGRAM
        self.at("socket")
        return self

    def __enter__(self):return self
    def __exit__(self, *args):
        self.closed = True
        self.at("close")
    def setblocking(self, blocking):
        assert blocking is False
        self.at("nonblocking")
    def bind(self, value):
        self.bound = value
        self.at("bind")
    async def connect(self, udp, address):
        assert udp is self
        self.at("connect")
    async def send(self, udp, request, address):
        assert udp is self
        self.at("send")
        self.request = request
        self.sent += 1
        return len(request)
    async def receive(self, udp, size):
        from test_radius import reply
        assert udp is self and size == 4097
        self.at("receive")
        item = next(self.replies, "timeout")
        if item == "timeout":raise TimeoutError()
        if item == "cancel":raise asyncio.CancelledError()
        return reply(self.request, code=3 if item == "reject" else 2, ma=item != "invalid")


def mab_inputs(address="192.0.2.1", source=None):
    from test_radius import SECRET
    cfg,pid,eid = plain()
    server = cfg.radius.servers[0]
    server.address, server.source_address, server.secret = address, source, SECRET.decode()
    return cfg,pid,eid


async def direct_mab(cfg,pid,eid):
    from switchlab.radius import mab_exchange,resolve_nas_identity
    return await mab_exchange(cfg.radius,cfg.radius.servers[0],None,cfg.ports[pid],
        cfg.endpoints[eid].sources[0].mac,"synthetic-session",nas_identity=resolve_nas_identity(cfg))


@pytest.mark.asyncio
@pytest.mark.parametrize("stage,number,category,sent", [
    ("socket", "EAFNOSUPPORT", "address_family_not_supported", 0),
    ("nonblocking", "EIO", "failed", 0),
    ("bind", "EADDRNOTAVAIL", "address_not_available", 0),
    ("bind", "EAFNOSUPPORT", "address_family_not_supported", 0),
    ("bind", "EACCES", "permission_denied", 0),
    ("connect", "ENETUNREACH", "unreachable", 0),
    ("connect", "EHOSTUNREACH", "unreachable", 0),
    ("send", "EPERM", "permission_denied", 0),
    ("receive", "ECONNREFUSED", "refused", 1),
    ("receive", "EIO", "failed", 1),
    ("close", "EIO", "failed", 1),
])
async def test_mab_transport_reason_preserves_safe_stage_without_exception_text(monkeypatch,stage,number,category,sent):
    import errno
    marker = "private-path-address-secret-must-not-escape"
    probe = MabSocketProbe(monkeypatch,stage=stage,error=OSError(getattr(errno,number),marker))
    cfg,pid,eid = mab_inputs(source="192.0.2.250")
    with pytest.raises(RadiusError) as caught:
        await direct_mab(cfg,pid,eid)
    public_stage = "socket" if stage == "nonblocking" else stage
    assert str(caught.value) == f"access_transport_{public_stage}_{category}"
    assert marker not in str(caught.value)
    assert caught.value.__suppress_context__
    assert probe.sent == sent and probe.trace.count("socket") == 1
    if stage != "socket":assert probe.closed
    if stage not in ("socket","nonblocking"):
        assert probe.bound == ("192.0.2.250",0)  # No silent unbound fallback.


@pytest.mark.asyncio
@pytest.mark.parametrize("address,source,bind,family", [
    ("192.0.2.1",None,"0.0.0.0",4),
    ("192.0.2.1","192.0.2.2","192.0.2.2",4),
    ("2001:db8::1",None,"::",6),
    ("2001:db8::1","2001:db8::2","2001:db8::2",6),
])
async def test_mab_blank_and_explicit_source_use_selected_family(monkeypatch,address,source,bind,family):
    import socket
    probe=MabSocketProbe(monkeypatch)
    cfg,pid,eid=mab_inputs(address,source)
    result=await direct_mab(cfg,pid,eid)
    assert result.result.code == 2 and probe.sent == 1 and probe.closed
    assert probe.bound == (bind,0)
    assert probe.family == (socket.AF_INET6 if family == 6 else socket.AF_INET)


@pytest.mark.asyncio
async def test_mab_invalid_response_keeps_correlation_then_current_reject(monkeypatch):
    probe=MabSocketProbe(monkeypatch,replies=("invalid","reject"))
    cfg,pid,eid=mab_inputs()
    result=await direct_mab(cfg,pid,eid)
    assert result.result.code == 3 and result.invalid_replies == 1
    assert probe.sent == 1 and probe.closed and not result.timed_out


@pytest.mark.asyncio
async def test_mab_timeout_and_cancellation_keep_existing_terminal_semantics(monkeypatch):
    probe=MabSocketProbe(monkeypatch,replies=("timeout",))
    cfg,pid,eid=mab_inputs()
    result=await direct_mab(cfg,pid,eid)
    assert result.result is None and result.timed_out
    assert result.unanswered_retries == cfg.radius.attempts == probe.sent and probe.closed
    cancelled=MabSocketProbe(monkeypatch,replies=("cancel",))
    with pytest.raises(asyncio.CancelledError):await direct_mab(cfg,pid,eid)
    assert cancelled.closed and cancelled.sent == 1


@pytest.mark.asyncio
async def test_mab_bind_failure_remains_local_current_engine_failure(monkeypatch):
    import errno,json
    probe=MabSocketProbe(monkeypatch,stage="bind",error=OSError(errno.EADDRNOTAVAIL,"private-source-marker"))
    cfg,pid,eid=mab_inputs(source="192.0.2.250")
    cfg.radius.servers.append(RadiusServer(label="Backup",address="192.0.2.99",secret="synthetic-backup"))
    engine=Engine(cfg)
    await engine.execute("advance",{"duration_ms":1000})
    await run_workers(engine)
    current=engine.snapshot()["authentication_clients"][0]
    assert current["reason"] == "access_transport_bind_address_not_available"
    assert current["status"] == "failed" and current["nas_code"] is None and current["response"] is None
    assert not engine.state.radius_sessions and not engine.state.radius_attempts
    assert probe.sent == 0 and probe.trace.count("socket") == 1 and probe.closed
    assert all(h.available is None and h.probe_owner is None for h in engine._server_health.values())
    assert "private-source-marker" not in json.dumps(engine.snapshot())
    assert "private-source-marker" not in json.dumps(list(engine.state.events))
    event=next(e for e in engine.state.events if e["kind"]=="authentication-failed")
    assert event["reason"] == current["reason"] and event["nas_code"] is None
    await engine.close_authentication()
