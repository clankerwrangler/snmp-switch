import asyncio
import pytest
from switchlab.engine import Engine
from switchlab.models import RadiusServer
from switchlab.radius import AccessResult,NativeObservation
from test_radius_engine import configured,begin,PEER


@pytest.mark.asyncio
async def test_state_stays_with_issuing_server_and_not_unrelated_failover(configured):
    cfg,pid,eid=configured
    primary=RadiusServer(label='Primary',address='192.0.2.1',secret='synthetic-primary')
    backup=RadiusServer(label='Backup',address='192.0.2.2',secret='synthetic-backup')
    cfg.radius.servers=[primary,backup];engine=Engine(cfg);capture=await begin(engine,pid,eid)
    opaque=b'private-original-server-state'
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,((24,opaque),(29,(1).to_bytes(4,'big'))),PEER,bytes(16)),
        'server_id':primary.id,'server_signature':engine._server_signature(primary)})
    capture=await begin(engine,pid,eid);observed=[]
    async def exchange(settings,server,*args,**kwargs):
        observed.append((server.id,kwargs['state']))
        if server.id==primary.id:
            return NativeObservation(None,0,0,0,0,True,False,unanswered_retries=3)
        return NativeObservation(AccessResult(2,(),(server.address,server.port),bytes(16)),2,0,2,1,False,False)
    result=await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange)
    assert result['accepted']
    assert observed==[(primary.id,opaque),(backup.id,None)]


@pytest.mark.asyncio
async def test_state_is_not_sent_to_same_id_with_changed_trust(configured):
    cfg,pid,eid=configured;server=RadiusServer(label='Original',address=PEER[0],secret='synthetic-original');cfg.radius.servers=[server]
    engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,((24,b'private-state'),(29,(1).to_bytes(4,'big'))),PEER,bytes(16)),
        'server_id':server.id,'server_signature':engine._server_signature(server)})
    await engine.execute('radius-server-save',{'id':server.id,'secret':'synthetic-replacement'})
    capture=await begin(engine,pid,eid);observed=[]
    async def exchange(settings,current_server,*args,**kwargs):
        observed.append((current_server.id,kwargs['state']))
        return NativeObservation(AccessResult(3,(),PEER,bytes(16)),0,0,0,0,False,False)
    result=await engine.authenticate(pid,capture['mac'],capture['attempt_id'],exchange=exchange)
    assert observed==[(server.id,None)]
    assert not result['accepted'] and result['nas_code']==3 and result['reason']=='server-reject'
    assert not engine.state.radius_attempts and not engine.state.radius_sessions
