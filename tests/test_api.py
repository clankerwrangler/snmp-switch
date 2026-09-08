import json
import pytest
from fastapi.testclient import TestClient
from switchlab.api import create_app
from switchlab.models import initial_configuration


def session(store):
    cfg=initial_configuration(4);cfg.paused=True
    return TestClient(create_app(store,cfg))


def sign_in(client,store):
    result=client.post('/api/v1/auth/setup',json={'password':'fixture-password-123'})
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
            "password": "fixture-password-123"})
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


@pytest.mark.parametrize("password", ["x", " ", "é"])
def test_direct_setup_accepts_nonempty_password_and_preserves_login(store, password):
    with session(store) as c:
        assert c.get('/api/v1/auth/status').json()['setup_required']
        result = c.post('/api/v1/auth/setup', json={'password': password})
        assert result.status_code == 200
        assert store.get('admin_hash').startswith('$argon2id$')
        saved = store.get('admin_hash')
        assert c.post('/api/v1/auth/setup', json={'password': 'replacement'}).status_code == 409
        assert store.get('admin_hash') == saved
        c.cookies.clear()
        assert c.post('/api/v1/auth/login', json={'password': password + 'wrong'}).status_code == 401
        assert c.post('/api/v1/auth/login', json={'password': password}).status_code == 200
    with session(store) as c:
        assert not c.get('/api/v1/auth/status').json()['setup_required']
        assert c.post('/api/v1/auth/login', json={'password': password}).status_code == 200


def test_setup_validation_origin_and_auth_rate_limit(store):
    with session(store) as c:
        for password in ('', 'x' * 1025):
            assert c.post('/api/v1/auth/setup', json={'password': password}).status_code == 422
        assert c.post('/api/v1/auth/setup', json={'password': 'x'},
                      headers={'Origin': 'http://other-host.invalid'}).status_code == 403
        assert store.get('admin_hash') is None
        assert c.post('/api/v1/auth/setup', json={'password': 'x'}).status_code == 200
        c.cookies.clear()
        for _ in range(16):
            assert c.post('/api/v1/auth/login', json={'password': 'wrong'}).status_code == 401
        assert c.post('/api/v1/auth/login', json={'password': 'x'}).status_code == 429


def test_setup_is_atomic_across_independent_connections(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from argon2 import PasswordHasher
    from cryptography.fernet import Fernet
    from switchlab.storage import Store

    path, key = str(tmp_path / 'setup.db'), Fernet.generate_key()
    stores = [Store(path, key), Store(path, key)]
    hashes = [PasswordHasher().hash(password) for password in ('a', 'b')]
    barrier = Barrier(2)
    try:
        def create(index):
            barrier.wait(timeout=5)
            return stores[index].create_administrator(hashes[index])
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(create, (0, 1)))
        assert sorted(outcomes) == [False, True]
        winner = outcomes.index(True)
        assert stores[0].get('admin_hash') == stores[1].get('admin_hash') == hashes[winner]
        assert not stores[1 - winner].create_administrator(hashes[1 - winner])
        assert stores[0].get('admin_hash') == hashes[winner]
        with session(stores[0]) as c:
            assert c.post('/api/v1/auth/setup', json={'password': 'replacement'}).status_code == 409
            assert c.post('/api/v1/auth/login', json={'password': ('a', 'b')[winner]}).status_code == 200
            assert c.post('/api/v1/auth/login', json={'password': ('b', 'a')[winner]}).status_code == 401
    finally:
        for store in stores:
            store.close()


def test_legacy_setup_token_cleanup_preserves_active_data(tmp_path):
    from cryptography.fernet import Fernet
    from switchlab.storage import Store

    path, key = str(tmp_path / 'legacy.db'), Fernet.generate_key()
    store = Store(path, key)
    with session(store) as c:
        sign_in(c, store)
        change(c, '/snmp/credentials', {'label': 'saved', 'community': 'legacy-community',
                                      'networks': ['127.0.0.0/8', '::1/128']})
    with store.db:
        store.put('setup_token', 'obsolete-fixture-token')
        store.put('unrelated', {'preserved': True})
    saved_hash = store.db.execute("SELECT value FROM kv WHERE key='admin_hash'").fetchone()[0]
    saved_config = store.get('configuration')
    store.close()
    store = Store(path, key)
    try:
        assert store.db.execute("SELECT value FROM kv WHERE key='setup_token'").fetchone() is None
        assert store.db.execute("SELECT value FROM kv WHERE key='admin_hash'").fetchone()[0] == saved_hash
        assert store.get('configuration') == saved_config
        assert store.get('unrelated') == {'preserved': True}
        with session(store) as c:
            assert c.post('/api/v1/auth/login', json={'password': 'fixture-password-123'}).status_code == 200
            assert c.get('/api/v1/state').json()['snmp']['enabled'] is False
    finally:
        store.close()


def test_optional_networks_and_saved_filters(store):
    with session(store) as c:
        sign_in(c, store)
        created = change(c, '/snmp/credentials', {'label': 'unrestricted', 'community': 'networks-fixture'})
        assert created.status_code == 200
        cid = created.json()['id']
        assert store.load().credentials[cid].networks == []
        explicit = ['127.0.0.0/8', '::1/128']
        assert change(c, f'/snmp/credentials/{cid}', {'networks': explicit}, 'PUT').status_code == 200
        assert change(c, f'/snmp/credentials/{cid}', {'label': 'renamed'}, 'PUT').status_code == 200
        assert store.load().credentials[cid].networks == explicit
        before = revision(c)
        assert change(c, f'/snmp/credentials/{cid}', {'networks': ['']}, 'PUT').status_code == 422
        assert revision(c) == before and store.load().credentials[cid].networks == explicit
        assert change(c, f'/snmp/credentials/{cid}', {'networks': []}, 'PUT').status_code == 200
        assert store.load().credentials[cid].networks == []


def test_protocol_fields_redaction_and_explicit_version_change(store):
    with session(store) as c:
        sign_in(c, store)
        created = change(c, '/snmp/credentials', {'label': 'versions', 'community': 'v2-fixture',
                         'username': 'unused', 'auth_key': 'unused-auth', 'priv_key': 'unused-priv'})
        assert created.status_code == 200
        cid = created.json()['id']
        def public():
            state = c.get('/api/v1/state').json()['credentials'][cid]
            assert c.get('/api/v1/snmp/credentials').json()['data'][cid] == state
            assert not {'community', 'auth_key', 'priv_key'} & state.keys()
            return state
        assert public()['has_community']
        assert not {'username', 'security_level', 'has_auth_key', 'has_priv_key'} & public().keys()
        saved = store.load().credentials[cid]
        assert saved.username == '' and saved.auth_key is None and saved.priv_key is None
        assert change(c, f'/snmp/credentials/{cid}', {'community': '', 'label': 'same version'}, 'PUT').status_code == 200
        assert store.load().credentials[cid].community == 'v2-fixture'
        before = revision(c)
        assert change(c, f'/snmp/credentials/{cid}', {'version': '3'}, 'PUT').status_code == 422
        assert revision(c) == before
        v3 = {'version': '3', 'username': 'v3-fixture', 'security_level': 'authPriv',
              'auth_key': 'auth-fixture', 'priv_key': 'priv-fixture'}
        assert change(c, f'/snmp/credentials/{cid}', v3, 'PUT').status_code == 200
        assert 'has_community' not in public() and public()['has_auth_key'] and public()['has_priv_key']
        assert store.load().credentials[cid].community is None
        assert change(c, f'/snmp/credentials/{cid}', {'auth_key': '', 'priv_key': '', 'label': 'v3 edit'}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.auth_key == 'auth-fixture' and saved.priv_key == 'priv-fixture'
        before = revision(c)
        assert change(c, f'/snmp/credentials/{cid}', {'version': '2c'}, 'PUT').status_code == 422
        assert revision(c) == before
        assert change(c, f'/snmp/credentials/{cid}', {'version': '2c', 'community': 'new-v2-fixture'}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.username == '' and saved.security_level == 'noAuthNoPriv'
        assert saved.auth_key is None and saved.priv_key is None
        assert not {'username', 'security_level', 'has_auth_key', 'has_priv_key'} & public().keys()
        assert change(c, f'/snmp/credentials/{cid}', {'version': '3', 'username': 'plain-v3'}, 'PUT').status_code == 200
        assert not {'has_community', 'has_auth_key', 'has_priv_key'} & public().keys()
        assert change(c, f'/snmp/credentials/{cid}', {'security_level': 'authNoPriv', 'auth_key': 'short'}, 'PUT').status_code == 422
        assert change(c, f'/snmp/credentials/{cid}', {'security_level': 'authNoPriv', 'auth_key': 'new-auth-fixture'}, 'PUT').status_code == 200
        assert public()['has_auth_key'] and 'has_priv_key' not in public()


def test_legacy_inactive_fields_stay_inert_until_version_change(store):
    cfg = initial_configuration(4).model_dump(mode='json')
    cfg['credentials']['legacy'] = {'id': 'legacy', 'label': 'legacy', 'community': 'legacy-v2',
        'username': 'hidden-old-user', 'auth_key': 'hidden-old-auth', 'priv_key': 'hidden-old-priv',
        'networks': ['127.0.0.0/8', '::1/128']}
    with store.db:
        store.put('configuration', cfg)
    with session(store) as c:
        sign_in(c, store)
        public = c.get('/api/v1/state').json()['credentials']['legacy']
        assert 'username' not in public and 'has_auth_key' not in public
        assert change(c, '/snmp/credentials/legacy', {'label': 'renamed'}, 'PUT').status_code == 200
        assert store.load().credentials['legacy'].networks == ['127.0.0.0/8', '::1/128']
        assert store.load().credentials['legacy'].auth_key == 'hidden-old-auth'
        assert change(c, '/snmp/credentials/legacy', {'version': '3', 'security_level': 'authPriv'}, 'PUT').status_code == 422
        assert store.load().credentials['legacy'].community == 'legacy-v2'


@pytest.mark.parametrize("default_host,expected", [
    (None, "127.0.0.1"), ("", "127.0.0.1"), ("0.0.0.0", "0.0.0.0"),
    ("127.0.0.2", "127.0.0.2"), ("::1", "::1"),
])
def test_fresh_listener_default(store, monkeypatch, default_host, expected):
    monkeypatch.delenv('SWITCHLAB_CONFIG', raising=False)
    monkeypatch.delenv('SWITCHLAB_SNMP_DEFAULT_HOST', raising=False)
    if default_host is not None:
        monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', default_host)
    with TestClient(create_app(store)) as c:
        sign_in(c, store)
        state = c.get('/api/v1/state').json()
        assert state['snmp']['host'] == expected and state['snmp']['port'] == 161
        assert state['snmp']['enabled'] is False
        assert state['switch']['identity']['sys_object_id'] is None
        assert state['snmp_status']['ready'] is False


def test_supplied_listener_configuration_overrides_image_default(store, monkeypatch):
    monkeypatch.delenv('SWITCHLAB_CONFIG', raising=False)
    monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', '0.0.0.0')
    cfg = initial_configuration(4)
    cfg.snmp.host, cfg.snmp.port = '127.0.0.2', 2161
    with TestClient(create_app(store, cfg)) as c:
        sign_in(c, store)
        state = c.get('/api/v1/state').json()
        assert state['snmp']['host'] == '127.0.0.2' and state['snmp']['port'] == 2161
        assert state['snmp']['enabled'] is False
        assert state['switch']['identity']['sys_object_id'] is None
        assert not state['snmp_status']['ready']


@pytest.mark.parametrize("supplied,overlay,expected_host,expected_port", [
    (False, {'snmp': {'host': '127.0.0.2', 'port': 2161}}, '127.0.0.2', 2161),
    (False, {'identity': {'sys_descr': 'Fixture identity'}}, '0.0.0.0', 161),
    (True, {'snmp': {'host': '127.0.0.3', 'port': 1161}}, '127.0.0.3', 1161),
    (True, {'identity': {'sys_descr': 'Fixture identity'}}, '127.0.0.2', 2161),
])
def test_fresh_listener_overlay_precedence(store, tmp_path, monkeypatch, supplied,
                                           overlay, expected_host, expected_port):
    path = tmp_path / 'startup.json'
    path.write_text(json.dumps(overlay))
    monkeypatch.setenv('SWITCHLAB_CONFIG', str(path))
    monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', '0.0.0.0')
    cfg = initial_configuration(4) if supplied else None
    if cfg is not None:
        cfg.snmp.host, cfg.snmp.port = '127.0.0.2', 2161
    with TestClient(create_app(store, cfg)) as c:
        sign_in(c, store)
        state = c.get('/api/v1/state').json()
        assert state['snmp']['host'] == expected_host and state['snmp']['port'] == expected_port
        assert state['snmp']['enabled'] is False
        assert state['switch']['identity']['sys_object_id'] is None
        assert not state['snmp_status']['ready']


@pytest.mark.parametrize("host,port", [
    ('127.0.0.1', 1161), ('0.0.0.0', 161), ('127.0.0.2', 2161), ('::1', 2161),
])
def test_saved_listener_binding_overrides_startup_inputs(store, tmp_path, monkeypatch, host, port):
    cfg = initial_configuration(4)
    cfg.snmp.host, cfg.snmp.port = host, port
    with store.db:
        store.put('configuration', cfg.model_dump(mode='json'))
    path = tmp_path / 'startup.json'
    path.write_text(json.dumps({'snmp': {'host': '127.0.0.3', 'port': 3161}}))
    monkeypatch.setenv('SWITCHLAB_CONFIG', str(path))
    monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', '0.0.0.0')
    with TestClient(create_app(store, initial_configuration(8))) as c:
        sign_in(c, store)
        state = c.get('/api/v1/state').json()
        assert state['snmp']['host'] == host and state['snmp']['port'] == port
        assert len(state['ports']) == 4
        assert state['snmp']['enabled'] is False
        assert state['switch']['identity']['sys_object_id'] is None
        assert not state['snmp_status']['ready']


def test_listener_edit_survives_startup_defaults(store, tmp_path, monkeypatch):
    monkeypatch.delenv('SWITCHLAB_CONFIG', raising=False)
    monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', '0.0.0.0')
    with TestClient(create_app(store)) as c:
        sign_in(c, store)
        assert c.get('/api/v1/state').json()['snmp']['host'] == '0.0.0.0'
        assert change(c, '/snmp/settings', {'host': '127.0.0.2', 'port': 2161}, 'PATCH').status_code == 200
    path = tmp_path / 'startup.json'
    path.write_text(json.dumps({'snmp': {'host': '127.0.0.3', 'port': 3161}}))
    monkeypatch.setenv('SWITCHLAB_CONFIG', str(path))
    monkeypatch.setenv('SWITCHLAB_SNMP_DEFAULT_HOST', '127.0.0.4')
    with TestClient(create_app(store)) as c:
        assert c.post('/api/v1/auth/login', json={'password': 'fixture-password-123'}).status_code == 200
        state = c.get('/api/v1/state').json()
        assert state['snmp']['host'] == '127.0.0.2' and state['snmp']['port'] == 2161
        assert state['snmp']['enabled'] is False
        assert state['switch']['identity']['sys_object_id'] is None
        assert not state['snmp_status']['ready']
