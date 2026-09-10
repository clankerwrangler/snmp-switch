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
        credential=change(c,'/snmp/credentials',{'label':'trap fixture','community':'fixture-traps'})
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
        r=change(c,'/snmp/credentials',{'label':'invalid','community':'sensitive-example','polling':{'networks':['bad-cidr']}})
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
        assert change(c,'/snmp/credentials',{'label':'fixture','community':'reboot-fixture','polling':{'enabled':True}}).status_code==200
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
                                      'polling': {'networks': ['127.0.0.0/8', '::1/128']}})
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
        assert store.load().credentials[cid].polling.networks == []
        explicit = ['127.0.0.0/8', '::1/128']
        assert change(c, f'/snmp/credentials/{cid}', {'polling': {'networks': explicit}}, 'PUT').status_code == 200
        assert change(c, f'/snmp/credentials/{cid}', {'label': 'renamed'}, 'PUT').status_code == 200
        assert store.load().credentials[cid].polling.networks == explicit
        before = revision(c)
        assert change(c, f'/snmp/credentials/{cid}', {'polling': {'networks': ['']}}, 'PUT').status_code == 422
        assert revision(c) == before and store.load().credentials[cid].polling.networks == explicit
        assert change(c, f'/snmp/credentials/{cid}', {'polling': {'networks': []}}, 'PUT').status_code == 200
        assert store.load().credentials[cid].polling.networks == []


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
              'auth_key': 'auth-fixture', 'priv_key': 'priv-fixture', 'access_transfer': 'none'}
        assert change(c, f'/snmp/credentials/{cid}', v3, 'PUT').status_code == 200
        assert 'has_community' not in public() and public()['has_auth_key'] and public()['has_priv_key']
        assert store.load().credentials[cid].community is None
        assert change(c, f'/snmp/credentials/{cid}', {'auth_key': '', 'priv_key': '', 'label': 'v3 edit'}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.auth_key == 'auth-fixture' and saved.priv_key == 'priv-fixture'
        before = revision(c)
        assert change(c, f'/snmp/credentials/{cid}', {'version': '2c'}, 'PUT').status_code == 422
        assert revision(c) == before
        assert change(c, f'/snmp/credentials/{cid}', {'version': '2c', 'community': 'new-v2-fixture', 'access_transfer': 'none'}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.username == '' and saved.security_level == 'noAuthNoPriv'
        assert saved.auth_key is None and saved.priv_key is None
        assert not {'username', 'security_level', 'has_auth_key', 'has_priv_key'} & public().keys()
        assert change(c, f'/snmp/credentials/{cid}', {'version': '3', 'username': 'plain-v3', 'security_level': 'noAuthNoPriv', 'access_transfer': 'none'}, 'PUT').status_code == 200
        assert not {'has_community', 'has_auth_key', 'has_priv_key'} & public().keys()
        assert change(c, f'/snmp/credentials/{cid}', {'security_level': 'authNoPriv', 'auth_key': 'short'}, 'PUT').status_code == 422
        assert change(c, f'/snmp/credentials/{cid}', {'security_level': 'authNoPriv', 'auth_key': 'new-auth-fixture'}, 'PUT').status_code == 200
        assert public()['has_auth_key'] and 'has_priv_key' not in public()


def test_legacy_inactive_fields_stay_inert_until_version_change(store):
    cfg = initial_configuration(4).model_dump(mode='json')
    cfg.pop('radius')
    for port in cfg['ports'].values():port.pop('authentication')
    cfg.pop('groups')
    cfg['schema_version'] = 1
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
        assert store.load().credentials['legacy'].polling.networks == ['127.0.0.0/8', '::1/128']
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


@pytest.mark.parametrize("purpose", ["polling", "notification", None])
@pytest.mark.parametrize("enabled", [True, False])
def test_legacy_credential_access_migration(store, purpose, enabled):
    import copy
    from switchlab.models import Configuration
    raw = initial_configuration(4).model_dump(mode="json")
    raw.pop("radius")
    for port in raw["ports"].values():port.pop("authentication")
    raw.pop("groups")
    raw["schema_version"] = 1
    legacy = {"id": "legacy", "label": "Legacy", "version": "3", "enabled": enabled,
              "username": "legacy-user", "security_level": "authPriv",
              "auth_key": "synthetic-auth", "priv_key": "synthetic-priv", "community": "inert-community",
              "view_id": "interfaces", "networks": ["127.0.0.0/8", "::1/128"]}
    if purpose is not None:
        legacy["purpose"] = purpose
    raw["credentials"] = {"legacy": legacy}
    if purpose == "notification":
        raw["targets"] = {"target": {"id": "target", "credential_id": "legacy", "address": "127.0.0.1",
                                     "port": 2162, "enabled": enabled, "types": ["coldStart"]},
                          "second": {"id": "second", "credential_id": "legacy", "address": "127.0.0.2",
                                     "port": 3162, "enabled": False, "types": ["linkUp"]}}
    original = copy.deepcopy(raw)
    cfg = Configuration.model_validate(raw)
    assert raw == original and cfg.schema_version == 4
    with store.db:
        store.put("configuration", raw)
        store.put("engine_identity", "40000102030405060708090a0b")
        store.put("engine_boots", 9)
    with TestClient(create_app(store)) as c:
        sign_in(c, store)
        state = c.get('/api/v1/state').json()
        migrated = state["credentials"]["legacy"]
        group = state["groups"][migrated["group_id"]]
        assert group["minimum_security_level"] == legacy["security_level"]
        assert group["polling"] == {"enabled": purpose != "notification", "view_id": "interfaces",
                                       "networks": legacy["networks"]}
        assert migrated["enabled"] == enabled and "purpose" not in migrated
        assert group["writing"] == {"enabled": False, "view_id": None, "networks": []}
        assert not {"view_id", "networks", "community", "auth_key", "priv_key"} & migrated.keys()
        saved = store.load()
        credential = saved.credentials["legacy"]
        assert credential.auth_key == legacy["auth_key"] and credential.priv_key == legacy["priv_key"]
        assert credential.community == legacy["community"]
        assert saved.targets == cfg.targets
        scenario = c.get('/api/v1/scenarios/export').json()
        assert scenario["schema_version"] == 1
        before = saved.model_dump()
        assert change(c, '/scenarios/import', {"scenario": scenario}).status_code == 200
        assert store.load().model_dump() == before
        assert store.get("configuration")["schema_version"] == 4
        assert store.get("engine_identity") == "40000102030405060708090a0b" and store.get("engine_boots") == 9
        assert state["snmp"]["enabled"] is False and state["switch"]["identity"]["sys_object_id"] is None
    assert store.load().groups[credential.group_id].polling == saved.groups[credential.group_id].polling


@pytest.mark.parametrize("version,credential", [
    (5, {"label": "future", "community": "synthetic"}),
    (True, {"label": "invalid tag", "community": "synthetic"}),
    (1, {"label": "mixed", "community": "synthetic", "polling": {"enabled": True}}),
    (2, {"label": "mixed", "community": "synthetic", "purpose": "notification"}),
    (2, {"label": "mixed", "community": "synthetic", "networks": []}),
    (1, {"label": "invalid", "community": "synthetic", "purpose": "both"}),
])
def test_configuration_schema_rejects_ambiguous_credentials(version, credential):
    from pydantic import ValidationError
    from switchlab.models import Configuration
    raw = initial_configuration(4).model_dump(mode="json")
    raw.pop("radius")
    for port in raw["ports"].values():port.pop("authentication")
    raw.pop("groups")
    raw.update(schema_version=version, credentials={"fixture": credential})
    with pytest.raises(ValidationError):
        Configuration.model_validate(raw)


def test_shared_credentials_and_partial_polling_access(store):
    with session(store) as c:
        sign_in(c, store)
        created = change(c, '/snmp/credentials', {"label": "Shared", "community": "synthetic-shared"})
        assert created.status_code == 200
        cid = created.json()["id"]
        assert store.load().credentials[cid].polling.enabled is False
        access = {"enabled": True, "view_id": "interfaces", "networks": ["127.0.0.0/8"]}
        assert change(c, f'/snmp/credentials/{cid}', {"polling": access}, 'PUT').status_code == 200
        target = change(c, '/notifications/targets', {"address": "127.0.0.1", "credential_id": cid})
        assert target.status_code == 200
        tid = target.json()["id"]
        assert change(c, f'/snmp/credentials/{cid}', {"label": "Renamed", "community": ""}, 'PUT').status_code == 200
        assert store.load().credentials[cid].polling.model_dump() == access
        assert change(c, f'/snmp/credentials/{cid}', {"polling": {"enabled": False}}, 'PUT').status_code == 200
        assert store.load().credentials[cid].polling.model_dump() == {**access, "enabled": False}
        assert store.load().targets[tid].enabled and store.load().credentials[cid].enabled
        assert change(c, f'/snmp/credentials/{cid}', {"polling": {"networks": []}}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.polling.networks == [] and saved.polling.view_id == 'interfaces' and saved.polling.enabled is False
        assert saved.community == 'synthetic-shared'
        assert change(c, f'/snmp/credentials/{cid}', method='DELETE').status_code == 422
        assert change(c, f'/notifications/targets/{tid}', method='DELETE').status_code == 200
        assert cid in store.load().credentials
        assert change(c, f'/snmp/credentials/{cid}', method='DELETE').status_code == 200


@pytest.mark.parametrize("extra", [{"polling": {"enabled": True}}, {"enabled": True}, {"id": "chosen"},
                                   {"purpose": "polling"}, {"networks": []}, {"view_id": "all"}])
def test_inline_target_rejects_privilege_fields(store, extra):
    with session(store) as c:
        sign_in(c, store)
        before = store.get('configuration')
        result = change(c, '/notifications/targets', {"address": "127.0.0.1",
                        "new_credential": {"label": "Inline", "community": "synthetic-inline", **extra}})
        assert result.status_code == 422
        assert store.get('configuration') == before
        assert 'synthetic-inline' not in result.text


def test_inline_target_atomic_creation_and_replacement(store):
    with session(store) as c:
        sign_in(c, store)
        payload = {"address": "127.0.0.1", "new_credential": {"label": "Inline", "community": "synthetic-inline"},
                   "expected_configuration_revision": revision(c)}
        response = c.post('/api/v1/notifications/targets', json=payload, headers={"Idempotency-Key": "inline-once"})
        assert response.status_code == 200
        result = response.json(); cid, tid = result['credential_id'], result['id']
        replay = c.post('/api/v1/notifications/targets', json=payload, headers={"Idempotency-Key": "inline-once"})
        assert replay.status_code == 200 and replay.json() == result
        cfg = store.load()
        assert len(cfg.credentials) == len(cfg.targets) == 1 and cfg.targets[tid].credential_id == cid
        assert cfg.credentials[cid].enabled and not cfg.credentials[cid].polling.enabled
        assert change(c, f'/snmp/credentials/{cid}', {"enabled": False}, 'PUT').status_code == 200
        assert change(c, f'/notifications/targets/{tid}', {"address": "127.0.0.2", "credential_id": cid}, 'PUT').status_code == 200
        assert store.load().credentials[cid].enabled is False
        replacement = change(c, f'/notifications/targets/{tid}', {"address": "127.0.0.2", "new_credential": {
            "label": "Replacement", "version": "3", "username": "inline-v3", "security_level": "authPriv",
            "auth_key": "synthetic-auth", "priv_key": "synthetic-priv"}}, 'PUT')
        assert replacement.status_code == 200
        new_cid = replacement.json()['credential_id']
        assert new_cid != cid and len(store.load().credentials) == 2
        assert store.load().targets[tid].credential_id == new_cid
        assert store.load().credentials[new_cid].group_id is None
        assert 'synthetic-' not in c.get('/api/v1/state').text
        assert 'synthetic-' not in c.get('/api/v1/events').text


def test_inline_target_failure_has_no_partial_records(store):
    with session(store) as c:
        sign_in(c, store)
        existing = change(c, '/snmp/credentials', {"label": "Existing", "community": "synthetic-duplicate"}).json()['id']
        before, events, idem = store.get('configuration'), store.events(), store.get('idempotency')
        attempts = [
            {"address": "127.0.0.1"},
            {"address": "127.0.0.1", "credential_id": existing, "new_credential": {"label": "Both", "community": "synthetic-new"}},
            {"address": "not-an-ip", "new_credential": {"label": "Bad IP", "community": "synthetic-new"}},
            {"address": "127.0.0.1", "source_address": "::1", "new_credential": {"label": "Bad family", "community": "synthetic-new"}},
            {"address": "127.0.0.1", "new_credential": {"label": "Duplicate", "community": "synthetic-duplicate"}},
        ]
        for payload in attempts:
            result = change(c, '/notifications/targets', payload, headers={"Idempotency-Key": "rejected"})
            assert result.status_code == 422
            assert store.get('configuration') == before and store.events() == events and store.get('idempotency') == idem
        stale = c.post('/api/v1/notifications/targets', json={"address": "127.0.0.1",
            "new_credential": {"label": "Stale", "community": "synthetic-new"}, "expected_configuration_revision": 0})
        assert stale.status_code == 409 and store.get('configuration') == before


@pytest.mark.parametrize("auth", [
    {"community": "duplicate-community"},
    {"version": "3", "username": "duplicate-user", "security_level": "authPriv",
     "auth_key": "synthetic-auth", "priv_key": "synthetic-priv"},
])
def test_shared_identity_uniqueness_and_disabled_references(store, auth):
    with session(store) as c:
        sign_in(c, store)
        first = change(c, '/snmp/credentials', {"label": "First", **auth}).json()['id']
        second = change(c, '/snmp/credentials', {"label": "Disabled duplicate", "enabled": False, **auth}).json()['id']
        created = change(c, '/notifications/targets', {"address": "127.0.0.1", "credential_id": second, "enabled": False})
        assert created.status_code == 200
        tid = created.json()['id']
        before = store.load().model_dump()
        assert change(c, f'/snmp/credentials/{second}', {"enabled": True}, 'PUT').status_code == 422
        assert store.load().model_dump() == before
        assert change(c, f'/snmp/credentials/{second}', method='DELETE').status_code == 422
        assert change(c, f'/snmp/credentials/{first}', {"enabled": False}, 'PUT').status_code == 200
        assert change(c, f'/snmp/credentials/{second}', {"enabled": True}, 'PUT').status_code == 200
        assert store.load().targets[tid].enabled is False
        credential = store.load().credentials[second]
        assert credential.group_id is None if credential.version == "3" else not credential.polling.enabled


@pytest.mark.parametrize("reference", ["legacy", ["legacy"]])
def test_legacy_target_cannot_change_polling_privileges(reference):
    import copy
    from pydantic import ValidationError
    from switchlab.models import Configuration
    raw = initial_configuration(4).model_dump(mode="json")
    raw.pop("radius"); raw.pop("groups")
    for port in raw["ports"].values():port.pop("authentication")
    raw.update(schema_version=1, credentials={"legacy": {"id": "legacy", "label": "Legacy polling",
        "community": "synthetic", "purpose": "polling"}}, targets={"target": {
        "id": "target", "address": "127.0.0.1", "credential_id": reference}})
    original = copy.deepcopy(raw)
    with pytest.raises(ValidationError):
        Configuration.model_validate(raw)
    assert raw == original


@pytest.mark.parametrize("globally_enabled", [True, False])
def test_trap_credentials_do_not_require_inactive_read_views(store, globally_enabled):
    with session(store) as c:
        sign_in(c, store)
        for vid in list(store.load().views):
            assert change(c, f'/snmp/views/{vid}', method='DELETE').status_code == 200
        assert store.load().views == {}
        response = change(c, '/notifications/targets', {"address": "127.0.0.1", "new_credential": {
            "label": "No polling view", "community": "synthetic-no-view"}})
        assert response.status_code == 200
        cid, tid = response.json()['credential_id'], response.json()['id']
        access = {"enabled": False, "view_id": "all", "networks": ["127.0.0.0/8", "::1/128"]}
        assert change(c, f'/snmp/credentials/{cid}', {
            "enabled": globally_enabled, "polling": {"networks": access['networks']}}, 'PUT').status_code == 200
        cfg = store.load()
        assert cfg.credentials[cid].polling.model_dump() == access
        target = cfg.targets[tid].model_dump()
        assert target['enabled'] and target['credential_id'] == cid
        before, events, idem, rev = store.get('configuration'), store.events(), store.get('idempotency'), revision(c)
        response = change(c, f'/snmp/credentials/{cid}', {"polling": {"enabled": True}}, 'PUT',
                          headers={"Idempotency-Key": "missing-view"})
        assert response.status_code == 422 and 'Unknown read view' in response.text
        assert store.get('configuration') == before and store.events() == events
        assert store.get('idempotency') == idem and revision(c) == rev
        response = change(c, '/snmp/views', {"name": "New read view", "includes": ["1.3.6.1.2.1.2"]})
        assert response.status_code == 200
        vid = response.json()['id']
        assert change(c, f'/snmp/credentials/{cid}', {
            "polling": {"enabled": True, "view_id": vid}}, 'PUT').status_code == 200
        before = store.get('configuration')
        assert change(c, f'/snmp/views/{vid}', method='DELETE').status_code == 422
        assert store.get('configuration') == before
        assert change(c, f'/snmp/credentials/{cid}', {"polling": {"enabled": False}}, 'PUT').status_code == 200
        assert change(c, f'/snmp/views/{vid}', method='DELETE').status_code == 200
        cfg = store.load()
        assert cfg.views == {} and cfg.credentials[cid].polling.model_dump() == {**access, "view_id": vid}
        assert cfg.credentials[cid].enabled == globally_enabled and cfg.targets[tid].model_dump() == target
        assert cfg.credentials[cid].community == 'synthetic-no-view'
        assert change(c, f'/snmp/credentials/{cid}', method='DELETE').status_code == 422
        assert cfg.snmp.enabled is False and cfg.switch.identity.sys_object_id is None


@pytest.mark.parametrize("enabled", [True, False])
def test_set_access_independent_sparse_permissions_and_reference_guards(store, enabled):
    with session(store) as c:
        sign_in(c, store)
        result = change(c, '/snmp/credentials', {"label": "Shared writer", "community": "synthetic-writer",
                                               "enabled": enabled, "polling": {"enabled": True}})
        assert result.status_code == 200
        cid = result.json()['id']
        default = {"enabled": False, "view_id": None, "networks": []}
        assert store.load().credentials[cid].writing.model_dump() == default
        before, rev = store.get('configuration'), revision(c)
        for write in ({"enabled": True}, {"enabled": True, "view_id": "missing"}):
            denied = change(c, f'/snmp/credentials/{cid}', {"writing": write}, 'PUT')
            assert denied.status_code == 422 and store.get('configuration') == before and revision(c) == rev
        response = change(c, '/snmp/views', {"id": "set-only", "name": "SET only", "includes": ["1.3.6.1.2.1.17"]})
        assert response.status_code == 200
        access = {"enabled": True, "view_id": "set-only", "networks": ["192.0.2.0/24", "2001:db8::/32"]}
        assert change(c, f'/snmp/credentials/{cid}', {"writing": access}, 'PUT').status_code == 200
        assert change(c, '/snmp/views/set-only', method='DELETE').status_code == 422
        assert change(c, f'/snmp/credentials/{cid}', {"polling": {"enabled": False}, "community": ""}, 'PUT').status_code == 200
        saved = store.load().credentials[cid]
        assert saved.writing.model_dump() == access and saved.community == 'synthetic-writer'
        assert saved.enabled == enabled and not saved.polling.enabled
        assert change(c, f'/snmp/credentials/{cid}', {"writing": {"networks": []}}, 'PUT').status_code == 200
        assert store.load().credentials[cid].writing.model_dump() == {**access, "networks": []}
        assert change(c, f'/snmp/credentials/{cid}', {"writing": {"enabled": False}}, 'PUT').status_code == 200
        assert change(c, '/snmp/views/set-only', method='DELETE').status_code == 200
        assert store.load().credentials[cid].writing.model_dump() == {**access, "enabled": False, "networks": []}
        assert change(c, f'/snmp/credentials/{cid}', {"writing": {"view_id": None}}, 'PUT').status_code == 200
        assert store.load().credentials[cid].writing.model_dump() == default
        assert 'synthetic-writer' not in c.get('/api/v1/state').text
        assert 'synthetic-writer' not in c.get('/api/v1/events').text
        assert c.get('/api/v1/state').json()['switch']['identity']['sys_object_id'] is None


def test_set_access_api_auth_revision_origin_and_invalid_cidrs(store):
    with session(store) as c:
        assert c.post('/api/v1/snmp/credentials', json={}).status_code == 401
        sign_in(c, store)
        cid = change(c, '/snmp/credentials', {"label": "Restricted", "community": "synthetic-restricted"}).json()['id']
        path = f'/api/v1/snmp/credentials/{cid}'
        before = store.get('configuration')
        payload = {"expected_configuration_revision": revision(c), "writing": {"enabled": True, "view_id": "all"}}
        assert c.put(path, json={**payload, "expected_configuration_revision": 0}).status_code == 409
        assert c.put(path, json=payload, headers={"Origin": "https://other.invalid"}).status_code == 403
        csrf = c.headers.pop('X-CSRF-Token')
        assert c.put(path, json=payload).status_code == 403
        c.headers['X-CSRF-Token'] = csrf
        assert c.put(path, json={**payload, "writing": {"networks": ["not-a-cidr"]}}).status_code == 422
        assert store.get('configuration') == before
        assert c.put(path, json=payload).status_code == 200
        assert store.load().credentials[cid].writing.enabled and not store.load().credentials[cid].polling.enabled


def test_inline_trap_does_not_grant_set_access(store):
    with session(store) as c:
        sign_in(c, store)
        payload = {"address": "127.0.0.1", "new_credential": {"label": "Inline", "community": "synthetic-inline"}}
        denied = change(c, '/notifications/targets', {**payload, "new_credential": {
            **payload['new_credential'], "writing": {"enabled": True, "view_id": "all"}}})
        assert denied.status_code == 422 and not store.load().credentials and not store.load().targets
        created = change(c, '/notifications/targets', payload)
        assert created.status_code == 200
        credential = store.load().credentials[created.json()['credential_id']]
        assert not credential.polling.enabled and not credential.writing.enabled and credential.writing.view_id is None


def test_api_port_independent_vlan_fields_preserve_empty_and_native_defaults(store):
    with session(store) as c:
        sign_in(c, store)
        pid = next(iter(store.load().ports))
        for vid in (10, 20):
            assert change(c, '/vlans', {"vid": vid}).status_code == 200
        path = f'/ports/{pid}'
        assert change(c, path, {"admitted": [1, 10], "untagged": [], "forbidden": [20]}, 'PATCH').status_code == 200
        assert change(c, path, {"alias": "Unrelated", "pvid": 1}, 'PATCH').status_code == 200
        port = store.load().ports[pid]
        assert not port.untagged and port.forbidden == [20]
        assert change(c, path, {"pvid": 10}, 'PATCH').status_code == 200
        assert store.load().ports[pid].untagged == [10]
        assert change(c, path, {"pvid": 1, "untagged": [1, 10]}, 'PATCH').status_code == 200
        assert store.load().ports[pid].untagged == [1, 10]
        before = store.get('configuration')
        for patch in ({"forbidden": [1]}, {"untagged": [20]}, {"forbidden": [30]}, {"untagged": [1, 1]}):
            assert change(c, path, patch, 'PATCH').status_code == 422
            assert store.get('configuration') == before


@pytest.mark.parametrize("stage", ["rollback", "commit-after", "commit-rolled-back"])
def test_storage_fault_api_background_auth_and_existing_restart(tmp_path, monkeypatch, stage):
    import time
    from cryptography.fernet import Fernet
    from switchlab.storage import Store, StorageFault
    from test_snmp_lifetime import TransactionFault
    path, key = str(tmp_path / "api-recovery.db"), Fernet.generate_key()
    store = Store(path, key)
    cfg = initial_configuration(4); cfg.paused = True
    try:
        app = create_app(store, cfg)
        with TestClient(app) as c:
            sign_in(c, store)
            identity, boots = store.engine_boot()
            assert change(c, '/clock/resume').status_code == 200
            e = app.state.engine
            original_commit, connection = store.commit, store.db
            proxy = TransactionFault(connection, stage)
            # Fault the requested durable API mutation, not a concurrent normal
            # non-durable clock tick that precedes it.
            def commit(state, idempotency, durable=True):
                if not durable:
                    return original_commit(state, idempotency, durable)
                store.db = proxy
                try:
                    return original_commit(state, idempotency, durable)
                finally:
                    store.db = connection
            with monkeypatch.context() as patcher:
                patcher.setattr(store, "commit", commit)
                response = change(c, '/switch', {"contact": "Unconfirmed primary"}, 'PATCH')
            assert response.status_code == 503
            reason = "storage_rollback_failed" if stage == "rollback" else "storage_commit_unknown"
            assert response.json()['storage_status'] == {"healthy": False, "reason": reason, "snapshot": "last_confirmed"}
            confirmed = e.state
            assert confirmed.cfg.switch.contact == ""
            # The same incarnation cannot use no-op/replayed/config/runtime or
            # direct storage helper paths to commit stale published state.
            for route, body, method in [('/switch', {"location": "Secondary"}, 'PATCH'),
                    ('/clock/pause', {}, 'POST'), ('/clock/advance', {"duration_ms": 1}, 'POST'),
                    ('/switch/reboot', {}, 'POST'), ('/endpoints', {"name": "Blocked"}, 'POST')]:
                assert change(c, route, body, method).status_code == 503
                assert e.state is confirmed
            for operation in (lambda: store.put("blocked", True), store.engine_boot,
                              lambda: store.create_administrator("unconfirmed"), store.load):
                with pytest.raises(StorageFault):
                    operation()
            time.sleep(.25)
            assert e.state is confirmed  # Automatic clock stops while storage is faulted.
            state = c.get('/api/v1/state').json()
            assert state['switch']['contact'] == "" and state['storage_status']['snapshot'] == 'last_confirmed'
            assert reason in state['warning']
            assert c.get('/api/v1/events').json()['events'] == confirmed.events
            assert c.get('/api/v1/scenarios/export').status_code == 200
            assert c.get('/api/v1/snmp/status').json()['storage_status']['healthy'] is False
            assert c.post('/api/v1/auth/logout').status_code == 200
            assert c.get('/api/v1/auth/status').json()['setup_required'] is False
            login = c.post('/api/v1/auth/login', json={"password": "fixture-password-123"})
            assert login.status_code == 200
            c.headers['X-CSRF-Token'] = login.json()['csrf_token']
            assert c.get('/api/v1/state').json()['storage_status']['reason'] == reason
        store.close()
        # Existing startup reloads actual durable bytes, not the old object's
        # cache or the failed candidate. No recovery endpoint or reset is used.
        store = Store(path, key)
        with TestClient(create_app(store, initial_configuration(8))) as c:
            login = c.post('/api/v1/auth/login', json={"password": "fixture-password-123"})
            assert login.status_code == 200
            c.headers['X-CSRF-Token'] = login.json()['csrf_token']
            state = c.get('/api/v1/state').json()
            assert len(state['ports']) == 4
            assert state['switch']['contact'] == ("Unconfirmed primary" if stage == "commit-after" else "")
            assert state['switch']['location'] == "" and state['storage_status']['healthy'] is True
            assert store.get('engine_identity') == identity.hex() and store.get('engine_boots') == boots
            assert change(c, '/switch', {"location": "Fresh secondary"}, 'PATCH').status_code == 200
            assert store.load().switch.contact == state['switch']['contact']
            assert store.load().switch.location == "Fresh secondary"
    finally:
        if not store.closed:
            store.close()


@pytest.mark.parametrize("owner", ["setup", "engine_boot"])
@pytest.mark.parametrize("stage", ["rollback", "commit-after", "commit-rolled-back"])
def test_direct_storage_helper_faults_keep_confirmed_auth_and_block_writes(store, owner, stage, monkeypatch):
    from switchlab.storage import StorageFault, RollbackFailed, CommitUncertain
    from test_snmp_lifetime import TransactionFault
    connection = store.db
    operation = (lambda: store.create_administrator("synthetic-unconfirmed-hash")) if owner == "setup" else store.engine_boot
    with monkeypatch.context() as patcher:
        patcher.setattr(store, 'db', TransactionFault(connection, stage))
        with pytest.raises(RollbackFailed if stage == "rollback" else CommitUncertain):
            operation()
    assert store.administrator_hash() is None
    assert store.fault_reason == ("storage_rollback_failed" if stage == "rollback" else "storage_commit_unknown")
    for blocked in (lambda: store.create_administrator("another"), store.engine_boot, lambda: store.put("anything", True)):
        with pytest.raises(StorageFault):
            blocked()
    # A failed close does not clear the fault or declare the connection closed.
    class CloseFailure:
        def close(self):
            raise OSError("Synthetic close failure")
    with monkeypatch.context() as patcher:
        patcher.setattr(store, 'db', CloseFailure())
        with pytest.raises(OSError):
            store.close()
    assert not store.closed and store.fault_reason is not None
    connection.rollback()
    with pytest.raises(StorageFault):
        store.put("still-blocked", True)


@pytest.mark.parametrize("failure", ["invalid", "unavailable", "wrong-key"])
def test_failed_owned_startup_closes_without_replacing_durable_configuration(tmp_path, monkeypatch, failure):
    import sqlite3
    from cryptography.fernet import Fernet, InvalidToken
    from pydantic import ValidationError
    import switchlab.api as api_module
    from switchlab.storage import Store
    path, key = str(tmp_path / "startup.db"), Fernet.generate_key()
    saved = initial_configuration(4).model_dump(mode='json')
    if failure == "invalid":
        saved['schema_version'] = 999
    store = Store(path, key)
    with store.transaction():
        store.put('configuration', saved)
    encrypted = store.db.execute("SELECT value FROM kv WHERE key='configuration'").fetchone()[0]
    store.close()
    key_path = tmp_path / 'key'
    key_path.write_bytes(Fernet.generate_key() if failure == 'wrong-key' else key)
    instances = []
    class ObservedStore(Store):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)
        def load(self):
            if failure == 'unavailable':
                raise OSError("Synthetic unavailable storage")
            return super().load()
    monkeypatch.setattr(api_module, 'Store', ObservedStore)
    monkeypatch.setenv('SWITCHLAB_DB', path)
    monkeypatch.setenv('SWITCHLAB_KEY_FILE', str(key_path))
    with pytest.raises((ValidationError, OSError, InvalidToken)):
        with TestClient(create_app()):
            pytest.fail('Failed startup became a usable application')
    assert len(instances) == 1 and instances[0].closed
    db = sqlite3.connect(path)
    try:
        assert db.execute("SELECT value FROM kv WHERE key='configuration'").fetchone()[0] == encrypted
    finally:
        db.close()


@pytest.mark.parametrize("intent", [{"access_transfer": "keep"}, {"access_transfer": "none"}, {"group_id": None}])
def test_api_conversion_missing_profile_is_atomic(store, intent):
    with session(store) as c:
        sign_in(c, store)
        cid = change(c, "/snmp/credentials", {"label": "Before", "community": "synthetic-old"}).json()["id"]
        before = c.get("/api/v1/state").json()
        saved = store.get("configuration")
        result = change(c, f"/snmp/credentials/{cid}", {"label": "After", "version": "3", "username": "new-user",
            "auth_key": "synthetic-new-auth", "priv_key": "synthetic-new-priv", **intent}, "PUT")
        assert result.status_code == 422 and "explicit protection profile" in result.text
        assert "synthetic-new" not in result.text
        after = c.get("/api/v1/state").json()
        assert after["configuration_revision"] == before["configuration_revision"]
        assert after["credentials"] == before["credentials"] and after["groups"] == before["groups"]
        assert store.get("configuration") == saved


def test_api_groups_combined_sparse_auth_and_policy_ownership(store):
    with session(store) as c:
        sign_in(c, store)
        created = change(c, "/snmp/groups", {"label": "Group"})
        assert created.status_code == 200
        gid = created.json()["id"]
        initial = c.get("/api/v1/snmp/groups").json()["data"][gid]
        assert initial["minimum_security_level"] == "authPriv" and not initial["polling"]["enabled"] and not initial["writing"]["enabled"]
        cid = change(c, "/snmp/credentials", {"label": "User", "version": "3", "username": "user",
            "auth_key": "synthetic-auth", "priv_key": "synthetic-priv"}).json()["id"]
        saved = store.load().credentials[cid]
        assert saved.security_level == "authPriv" and saved.group_id is None
        # One credential save can update authentication and group membership atomically.
        assert change(c, f"/snmp/credentials/{cid}", {"group_id": gid, "auth_key": "synthetic-replacement"}, "PUT").status_code == 200
        assert change(c, f"/snmp/credentials/{cid}", {"label": "Renamed", "auth_key": "", "priv_key": ""}, "PUT").status_code == 200
        assert store.load().credentials[cid].auth_key == "synthetic-replacement"
        before = store.get("configuration")
        for fields in ({"polling": {"enabled": True}}, {"writing": {}}, {"group_id": "missing", "auth_key": "unsaved-key"}):
            response = change(c, f"/snmp/credentials/{cid}", fields, "PUT")
            assert response.status_code == 422 and "unsaved-key" not in response.text
            assert store.get("configuration") == before
        assert change(c, f"/snmp/groups/{gid}", {"polling": {"view_id": "interfaces", "networks": ["192.0.2.1/24"]},
            "writing": {"view_id": "all", "networks": ["2001:db8::/32"]}}, "PUT").status_code == 200
        assert change(c, f"/snmp/groups/{gid}", {"polling": {"enabled": True}, "writing": {"enabled": True}}, "PUT").status_code == 200
        group = store.load().groups[gid]
        assert group.polling.view_id == "interfaces" and group.polling.networks == ["192.0.2.0/24"]
        assert group.writing.view_id == "all" and group.writing.networks == ["2001:db8::/32"]
        before = store.get("configuration")
        assert change(c, f"/snmp/groups/{gid}", {"polling": {"networks": []}, "writing": {"view_id": None}}, "PUT").status_code == 422
        assert store.get("configuration") == before
        # A lower-profile member is permitted without changing group minimum or stored keys.
        assert change(c, f"/snmp/credentials/{cid}", {"security_level": "noAuthNoPriv", "enabled": False}, "PUT").status_code == 200
        assert store.load().groups[gid] == group
        assert store.load().credentials[cid].priv_key == "synthetic-priv"
        assert change(c, f"/snmp/groups/{gid}", method="DELETE").status_code == 422
        assert change(c, f"/snmp/credentials/{cid}", {"group_id": None}, "PUT").status_code == 200
        assert change(c, f"/snmp/groups/{gid}", method="DELETE").status_code == 200
        assert c.get("/api/v1/snmp/groups").json()["data"] == {}
        final = c.get("/api/v1/state").json()
        assert final["snmp"]["enabled"] is False and final["switch"]["identity"]["sys_object_id"] is None


@pytest.mark.parametrize("transfer", ["keep", "none"])
def test_api_user_to_community_explicit_choice_and_retained_group_members(store, transfer):
    with session(store) as c:
        sign_in(c, store)
        gid = change(c, "/snmp/groups", {"label": "Stronger group", "polling": {"enabled": True},
            "writing": {"enabled": True, "view_id": "interfaces"}}).json()["id"]
        ids = [change(c, "/snmp/credentials", {"label": str(n), "version": "3", "username": str(n),
            "security_level": "noAuthNoPriv", "group_id": gid}).json()["id"] for n in (1, 2)]
        cid = ids[0]
        tid = change(c, "/notifications/targets", {"address": "127.0.0.1", "credential_id": cid}).json()["id"]
        before = store.load()
        assert change(c, f"/snmp/credentials/{cid}", {"version": "2c", "community": "synthetic-new"}, "PUT").status_code == 422
        assert change(c, f"/snmp/credentials/{cid}", {"version": "2c", "community": "synthetic-new",
            "access_transfer": transfer}, "PUT").status_code == 200
        cfg = store.load()
        assert cfg.targets[tid] == before.targets[tid] and cfg.groups == before.groups
        assert cfg.credentials[ids[1]] == before.credentials[ids[1]]
        assert cfg.credentials[cid].polling.enabled == (transfer == "keep")
        assert cfg.credentials[cid].writing.enabled == (transfer == "keep")
        assert cfg.credentials[cid].auth_key is None and cfg.credentials[cid].priv_key is None


def test_api_inline_user_defaults_and_selected_target_isolation(store):
    with session(store) as c:
        sign_in(c, store)
        cid = change(c, "/snmp/credentials", {"label": "Existing", "community": "synthetic-old"}).json()["id"]
        ids = [change(c, "/notifications/targets", {"address": "127.0.0.1", "port": 162+n,
            "credential_id": cid, "enabled": bool(n)}).json()["id"] for n in (0, 1)]
        before = store.load()
        fields = {"label": "Inline", "version": "3", "username": "inline-user",
                  "auth_key": "synthetic-auth", "priv_key": "synthetic-priv"}
        result = change(c, f"/notifications/targets/{ids[0]}", {"address": "127.0.0.2", "new_credential": fields}, "PUT")
        assert result.status_code == 200
        after = store.load()
        new_id = result.json()["credential_id"]
        assert after.targets[ids[1]] == before.targets[ids[1]]
        assert after.targets[ids[0]].credential_id == new_id
        assert after.credentials[new_id].security_level == "authPriv" and after.credentials[new_id].group_id is None
        assert after.groups == before.groups and after.credentials[cid] == before.credentials[cid]
        for extra in ({"group_id": None}, {"access_transfer": "keep"}, {"polling": {}}, {"writing": {}}):
            rejected = change(c, "/notifications/targets", {"address": "127.0.0.1", "new_credential": {**fields, **extra}})
            assert rejected.status_code == 422
            assert store.load() == after
