import json
import pytest
from fastapi.testclient import TestClient
from switchlab.api import create_app
from switchlab.models import initial_configuration


def session(store):
    cfg=initial_configuration(4);cfg.paused=True
    return TestClient(create_app(store,cfg))


def sign_in(client,store):
    result=client.post('/api/v1/auth/setup',json={'setup_token':store.get('setup_token'),'password':'fixture-password-123'})
    assert result.status_code==200,result.text
    client.headers['X-CSRF-Token']=result.json()['csrf_token']


def revision(client):
    return client.get('/api/v1/state').json()['configuration_revision']


def change(client,path,body=None,method='POST',**kwargs):
    return client.request(method,'/api/v1'+path,json={**(body or {}),'expected_configuration_revision':revision(client)},**kwargs)


def test_clean_public_setup_health_and_auth(store):
    with session(store) as c:
        assert c.get('/healthz').json()['ready']
        assert c.get('/api/v1/state').status_code==401
        assert c.get('/').status_code==200
        sign_in(c,store)
        s=c.get('/api/v1/state').json()
        assert s['switch']['identity']['sys_object_id'] is None
        assert s['snmp_status']['reason']=='identity_required'
        assert s['snmp_status']['ready'] is False
        assert s['endpoints']=={} and len(s['ports'])==4
        c.headers.pop('X-CSRF-Token')
        assert change(c,'/clock/advance',{'duration_ms':1000}).status_code==403


def test_api_endpoint_edits_revision_and_identity(store):
    with session(store) as c:
        sign_in(c,store)
        result=change(c,'/endpoints',{'name':'Workstation','sources':[{'mac':'0200.0000.0010','tag':200}]})
        assert result.status_code==200,result.text
        eid=result.json()['id'];pid=next(iter(c.get('/api/v1/state').json()['ports']))
        assert change(c,f'/endpoints/{eid}/attachment',{'port_id':pid},'PUT').status_code==200
        assert change(c,'/clock/advance',{'duration_ms':1000}).status_code==200
        assert change(c,f'/endpoints/{eid}',method='DELETE').status_code==409
        assert change(c,'/switch',{'identity':{'sys_object_id':'2.999.1'}},'PATCH').status_code==200
        rev=revision(c)
        assert change(c,'/switch',{'identity':{'sys_object_id':'not-an-oid'}},'PATCH').status_code==422
        assert revision(c)==rev
        assert c.patch('/api/v1/switch',json={'expected_configuration_revision':0,'name':'stale'}).status_code==409
        assert change(c,'/switch',{'identity':{'sys_object_id':''}},'PATCH').status_code==200
        assert c.get('/api/v1/state').json()['switch']['identity']['sys_object_id'] is None


def test_secrets_redacted_encrypted_and_scenario_preserved(store):
    with session(store) as c:
        sign_in(c,store)
        result=change(c,'/snmp/credentials',{'label':'Lab','community':'fixture-secret-value'})
        assert result.status_code==200,result.text
        cid=result.json()['id']
        state=c.get('/api/v1/state').text
        assert 'fixture-secret-value' not in state
        assert 'fixture-secret-value' not in c.get('/api/v1/snmp/credentials').text
        assert b'fixture-secret-value' not in b''.join(bytes(x[0]) for x in store.db.execute('SELECT value FROM kv'))
        assert change(c,f'/snmp/credentials/{cid}',{'enabled':False},'PUT').status_code==200
        assert store.load().credentials[cid].community=='fixture-secret-value'
        scenario=c.get('/api/v1/scenarios/export').json()
        assert 'credentials' not in scenario and 'identity' not in json.dumps(scenario)
        before=revision(c)
        malformed={**scenario,'identity':{'sys_object_id':'1.2'}}
        assert change(c,'/scenarios/import',{'scenario':malformed}).status_code==422
        assert revision(c)==before


def test_new_snmp_port_and_validation(store):
    with session(store) as c:
        sign_in(c,store)
        assert c.get('/api/v1/state').json()['snmp']['port']==161
        for port in (1,161,1161,65535):
            assert change(c,'/snmp/settings',{'port':port},'PATCH').status_code==200
            assert store.load().snmp.port==port
        before=revision(c)
        for port in (0,65536):
            assert change(c,'/snmp/settings',{'port':port},'PATCH').status_code==422
            assert revision(c)==before
        assert c.get('/api/v1/state').json()['snmp']['enabled'] is False


@pytest.mark.parametrize('saved_port',[1161,2161])
def test_saved_snmp_port_and_explicit_standard_port_upgrade(store,saved_port):
    cfg=initial_configuration(4).model_dump(mode='json')
    cfg['snmp']['port']=saved_port
    with store.db:store.put('configuration',cfg)
    with session(store) as c:
        sign_in(c,store)
        assert c.get('/api/v1/state').json()['snmp']['port']==saved_port
    with session(store) as c:
        login=c.post('/api/v1/auth/login',json={'password':'fixture-password-123'})
        assert login.status_code==200
        c.headers['X-CSRF-Token']=login.json()['csrf_token']
        assert c.get('/api/v1/state').json()['snmp']['port']==saved_port
        assert change(c,'/snmp/settings',{'port':161},'PATCH').status_code==200
        assert store.load().snmp.port==161
    with session(store) as c:
        assert c.post('/api/v1/auth/login',json={'password':'fixture-password-123'}).status_code==200
        snmp=c.get('/api/v1/state').json()['snmp']
        assert snmp['port']==161 and snmp['enabled'] is False


def test_notification_target_default_and_configurable_port(store):
    with session(store) as c:
        sign_in(c,store)
        credential=change(c,'/snmp/credentials',{'label':'trap fixture','purpose':'notification','community':'fixture-traps'})
        assert credential.status_code==200,credential.text
        result=change(c,'/notifications/targets',{'address':'127.0.0.1','credential_id':credential.json()['id']})
        assert result.status_code==200,result.text
        tid=result.json()['id']
        assert c.get('/api/v1/state').json()['targets'][tid]['port']==162
        assert change(c,f'/notifications/targets/{tid}',{'address':'127.0.0.1','credential_id':credential.json()['id'],'port':2162},'PUT').status_code==200
        assert c.get('/api/v1/state').json()['targets'][tid]['port']==2162
        assert store.load().targets[tid].port==2162


def test_rejected_request_no_effect_and_body_limits(store):
    with session(store) as c:
        sign_in(c,store)
        before=revision(c)
        r=change(c,'/snmp/credentials',{'label':'invalid','community':'sensitive-example','networks':['bad-cidr']})
        assert r.status_code==422 and 'sensitive-example' not in r.text
        assert revision(c)==before
        assert change(c,'/vlans/1',method='DELETE').status_code==409
        assert change(c,'/clock/advance',{'duration_ms':0}).status_code==422
        assert c.patch('/api/v1/switch',json={'name':'missing revision'}).status_code==422
        assert change(c,'/switch',{'unknown':1},'PATCH').status_code==422
        assert change(c,'/clock/pause',headers={'Origin':'https://attacker.invalid'}).status_code==403


def test_api_idempotency(store):
    with session(store) as c:
        sign_in(c,store)
        rev=revision(c)
        body={'name':'Once','expected_configuration_revision':rev}
        first=c.post('/api/v1/endpoints',json=body,headers={'Idempotency-Key':'once'})
        second=c.post('/api/v1/endpoints',json=body,headers={'Idempotency-Key':'once'})
        assert first.status_code==second.status_code==200 and first.json()['id']==second.json()['id']
        assert len(c.get('/api/v1/state').json()['endpoints'])==1


def test_explicit_development_overlay_and_persistence(store,tmp_path,monkeypatch):
    overlay=tmp_path/'development.json'
    overlay.write_text('{"identity":{"sys_object_id":"1.3.6.1.4.1.32473.1"}}')
    monkeypatch.setenv('SWITCHLAB_CONFIG',str(overlay))
    with session(store) as c:
        sign_in(c,store)
        assert c.get('/api/v1/state').json()['snmp_status']['documentation_identity']
        assert change(c,'/switch',{'identity':{'sys_object_id':None}},'PATCH').status_code==200
    with session(store) as c:
        login=c.post('/api/v1/auth/login',json={'password':'fixture-password-123'})
        c.headers['X-CSRF-Token']=login.json()['csrf_token']
        assert c.get('/api/v1/state').json()['switch']['identity']['sys_object_id'] is None


def test_malformed_saved_identity_keeps_setup_available(store):
    cfg=initial_configuration(4).model_dump(mode='json')
    cfg['switch']['identity']['sys_object_id']='malformed'
    with store.db:store.put('configuration',cfg)
    with session(store) as c:
        sign_in(c,store)
        result=c.get('/api/v1/state').json()
        assert result['snmp_status']['reason']=='identity_required' and result['warning']
        assert c.get('/healthz').json()['ready']


def test_retrying_reboot_does_not_restart_security_engine_twice(store):
    from test_wire import free_port
    with session(store) as c:
        sign_in(c,store)
        assert change(c,'/switch',{'identity':{'sys_object_id':'1.3.999.123'}},'PATCH').status_code==200
        assert change(c,'/snmp/credentials',{'label':'fixture','community':'reboot-fixture'}).status_code==200
        assert change(c,'/snmp/settings',{'enabled':True,'port':free_port()},'PATCH').status_code==200
        body={'expected_configuration_revision':revision(c)}
        result=c.post('/api/v1/switch/reboot',json=body,headers={'Idempotency-Key':'reboot-once'})
        assert result.status_code==200
        boots=c.get('/api/v1/snmp/status').json()['engine_boots']
        retry=c.post('/api/v1/switch/reboot',json=body,headers={'Idempotency-Key':'reboot-once'})
        assert retry.status_code==200
        assert c.get('/api/v1/snmp/status').json()['engine_boots']==boots


@pytest.mark.parametrize("base_url,secure", [
    ("http://192.0.2.10:8000", False),
    ("http://switchlab.example:8000", False),
    ("https://switchlab.example", True),
])
def test_lan_origin_session_and_csrf(store, monkeypatch, base_url, secure):
    monkeypatch.setenv("SWITCHLAB_SECURE_COOKIES", "1" if secure else "0")
    cfg = initial_configuration(4)
    cfg.paused = True
    with TestClient(create_app(store, cfg), base_url=base_url) as client:
        client.headers["Origin"] = base_url
        assert client.get("/").status_code == 200
        assert client.get("/api/v1/state").status_code == 401
        setup = client.post("/api/v1/auth/setup", json={
            "setup_token": store.get("setup_token"), "password": "fixture-password-123"})
        assert setup.status_code == 200
        cookie = setup.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
        assert "domain=" not in cookie
        assert ("; secure" in cookie) == secure
        assert client.get("/api/v1/auth/status").json()["authenticated"]
        before = revision(client)
        assert change(client, "/clock/advance", {"duration_ms": 1000}).status_code == 403
        client.headers["X-CSRF-Token"] = setup.json()["csrf_token"]
        rejected = change(client, "/clock/advance", {"duration_ms": 1000},
                          headers={"Origin": "http://other-host.example:8000"})
        assert rejected.status_code == 403
        assert "access-control-allow-origin" not in rejected.headers
        assert revision(client) == before
        assert change(client, "/clock/advance", {"duration_ms": 1000}).status_code == 200
        assert client.get("/api/v1/state").json()["simulation_ms"] == 1000
