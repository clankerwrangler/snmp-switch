import asyncio
import threading
import time

from fastapi.testclient import TestClient
from switchlab.api import create_app
from switchlab.models import RadiusServer
from switchlab.radius import AccessResult,NativeObservation
from test_radius_engine import configured,PEER
from test_api import sign_in,change


def test_clock_pending_api_preserves_auth_revision_and_scoped_cancel(configured,store,monkeypatch):
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared")]
    release=threading.Event();started=threading.Event();cancelled=threading.Event()
    async def exchange(*args,**kwargs):
        started.set()
        try:
            while not release.is_set():await asyncio.sleep(.01)
            return NativeObservation(AccessResult(2,(),PEER,bytes(16)),2,0,5,2,False,False)
        except asyncio.CancelledError:cancelled.set();raise
    monkeypatch.setattr("switchlab.radius.native_exchange",exchange)
    with TestClient(create_app(store,cfg)) as client:
        sign_in(client,store)
        first=change(client,"/clock/advance",{"duration_ms":5000},headers={"Idempotency-Key":"first"})
        assert first.status_code==202;operation=first.json()["advance"]
        assert started.wait(2)
        assert operation["status"]=="waiting" and operation["reached_ms"]==0
        repeat=change(client,"/clock/advance",{"duration_ms":5000},headers={"Idempotency-Key":"first"})
        assert repeat.status_code==202 and repeat.json()["advance"]["id"]==operation["id"]
        assert change(client,"/clock/advance",{"duration_ms":1}).status_code==409
        assert change(client,"/clock/resume").status_code==409
        assert change(client,f"/clock/advance/{operation['id']}/cancel",headers={"Origin":"https://wrong.invalid"}).status_code==403
        revision=client.get('/api/v1/state').json()['configuration_revision']
        assert client.post(f"/api/v1/clock/advance/{operation['id']}/cancel",json={"expected_configuration_revision":revision+1}).status_code==409
        cancelled_response=change(client,f"/clock/advance/{operation['id']}/cancel")
        assert cancelled_response.status_code==200 and cancelled_response.json()["advance"]["status"]=="canceled"
        assert not cancelled.is_set()
        second=change(client,"/clock/advance",{"duration_ms":7000})
        assert second.status_code==202 and second.json()["advance"]["id"]!=operation["id"]
        assert change(client,f"/clock/advance/{operation['id']}/cancel").status_code==409
        release.set()
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            state=client.get('/api/v1/state').json()
            if state['advance']['status']=='completed':break
            time.sleep(.02)
        assert state['simulation_ms']==7000 and state['paused'] and state['authentication_sessions']
        assert not state['snmp']['enabled']


def test_authenticated_safe_response_summary_and_pending_failed_history(configured,store,monkeypatch):
    import json
    from switchlab.models import Vlan
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name='Dynamic',fdb_id=1020)
    cfg.radius.servers=[RadiusServer(label='Synthetic',address=PEER[0],secret='synthetic-shared')]
    secrets=[b'private-server-user-271',b'private-state-271',b'private-class-271',b'private-filter-271']
    good=((6,(2).to_bytes(4,'big')),(64,(13).to_bytes(4,'big')),(65,(6).to_bytes(4,'big')),(81,b'0020'),
          (27,(100).to_bytes(4,'big')),(1,secrets[0]),(24,secrets[1]),(25,secrets[2]),(25,b'private-second-class'))
    bad=((6,(8).to_bytes(4,'big')),(27,b'bad'),(28,(1).to_bytes(4,'big')),(28,(2).to_bytes(4,'big')),(11,secrets[3]))
    releases=[threading.Event(),threading.Event()];starts=[threading.Event(),threading.Event()];calls=[]
    async def exchange(*args,**kwargs):
        index=len(calls);calls.append(index);starts[index].set()
        while not releases[index].is_set():await asyncio.sleep(.01)
        return NativeObservation(AccessResult(2,good if index==0 else bad,PEER,bytes(16)),2,0,0,0,False,False)
    monkeypatch.setattr('switchlab.radius.native_exchange',exchange)
    with TestClient(create_app(store,cfg)) as client:
        sign_in(client,store)
        assert client.get('/api/v1/state',headers={'Cookie':''}).status_code==401
        assert change(client,'/clock/advance',{'duration_ms':1000}).status_code==202
        assert starts[0].wait(2)
        pending=client.get('/api/v1/state').json()['authentication_clients'][0]
        assert pending['status']=='pending' and pending.get('response') is None
        releases[0].set()
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            state=client.get('/api/v1/state').json()
            if state['authentication_sessions']:break
            time.sleep(.01)
        summary=state['authentication_clients'][0]['response']
        assert summary['nas_code']==2
        attributes={a['name']:a for a in summary['attributes']}
        assert attributes['Tunnel-Private-Group-ID']=={'name':'Tunnel-Private-Group-ID','status':'present','value':20}
        assert attributes['Session-Timeout']['value']==100 and attributes['Idle-Timeout']['status']=='absent'
        omitted={a['name']:a for a in summary['omitted']}
        assert omitted['Class']=={'name':'Class','count':2} and omitted['State']=={'name':'State','count':1}
        assert state['authentication_sessions'][0]['vid']==20
        source=state['endpoints'][eid]['sources'][0]
        assert change(client,f'/endpoints/{eid}/authentication',{'source_id':source['id'],'action':'restart'}).status_code==200
        assert starts[1].wait(2);releases[1].set()
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            state=client.get('/api/v1/state').json()
            if state['authentication_clients'][0]['status']=='failed':break
            time.sleep(.01)
        assert not state['authentication_sessions'] and state['ports'][pid]['operational_up']
        failed=state['authentication_clients'][0];assert failed['response']['nas_code']==2
        attributes={a['name']:a for a in failed['response']['attributes']}
        assert attributes['Service-Type']['value']==8
        assert attributes['Session-Timeout']['status']==attributes['Idle-Timeout']['status']=='invalid'
        history=client.get('/api/v1/events').json()
        text=json.dumps([state,history,client.get('/api/v1/scenarios/export').json()])
        assert all(secret.decode() not in text for secret in secrets)
        assert 'private-second-class' not in text and 'BEGIN CERTIFICATE' not in text
        events=client.app.state.engine.state.events
        assert {'authentication-started','authentication-authorized','authentication-failed'} <= {event['kind'] for event in events}
        assert next(e for e in reversed(events) if e['kind']=='authentication-failed')['response']['nas_code']==2
