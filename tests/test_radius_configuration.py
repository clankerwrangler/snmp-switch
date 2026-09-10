import copy,json
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from switchlab.api import create_app
from switchlab.engine import Engine
from switchlab.models import initial_configuration
from switchlab.radius import AccessResult
from test_api import sign_in,change
from test_radius_engine import configured,begin,PEER


def test_radius_server_order_sparse_secret_and_redaction(store):
    cfg=initial_configuration(2);cfg.paused=True
    with TestClient(create_app(store,cfg)) as client:
        sign_in(client,store)
        one=change(client,'/radius/servers',{'label':'Primary','address':'192.0.2.1','secret':'synthetic-one'}).json()['id']
        two=change(client,'/radius/servers',{'label':'Backup','address':'192.0.2.2','secret':'synthetic-two'}).json()['id']
        response=change(client,'/radius/servers',{'id':two,'label':'First','position':0,'secret':''})
        assert response.status_code==200
        saved=client.app.state.engine.state.cfg;assert [s.id for s in saved.radius.servers]==[two,one]
        assert saved.radius.servers[0].secret=='synthetic-two'
        state=client.get('/api/v1/state').json();text=json.dumps(state)
        assert 'synthetic-one' not in text and 'synthetic-two' not in text
        assert all(s['has_secret'] and 'secret' not in s for s in state['radius']['servers'])
        before=client.app.state.engine.state.cfg.model_dump(mode='json')
        bad=change(client,'/radius/settings',{'nas_identifier':''},method='PATCH')
        assert bad.status_code==422 and client.app.state.engine.state.cfg.model_dump(mode='json')==before
        assert change(client,'/radius/settings',{'nas_identifier':'Override'},method='PATCH').status_code==200
        assert change(client,'/radius/settings',{'nas_identifier':None},method='PATCH').status_code==200
        assert client.app.state.engine.state.cfg.radius.nas_identifier is None
        assert not store.load().radius.servers
        assert change(client,'/switch/save').status_code==200
        assert [s.id for s in store.load().radius.servers]==[two,one]


def test_templates_make_independent_copies_and_material_references_are_protected(configured,store):
    supplied,pid,eid=configured;cfg=initial_configuration(2);cfg.paused=True
    materials=list(supplied.radius.materials.values());trust=next(m for m in materials if m.kind=='ca');key=next(m for m in materials if m.kind=='client')
    with TestClient(create_app(store,cfg)) as client:
        sign_in(client,store)
        for material in materials:
            assert change(client,'/radius/materials',material.model_dump()).status_code==200
        profile={'method':'peap','identity':'outer','username':'inner-'+'x'*64,'password':'synthetic-profile-password','trust_id':trust.id,'server_name':'radius-probe.invalid'}
        template=change(client,'/radius/templates',{'label':'Profile','profile':profile});assert template.status_code==200
        tid=template.json()['id']
        endpoint=change(client,'/endpoints',{'name':'Client','sources':[{'mac':'02:00:00:00:00:21'}]}).json()['id']
        source_id=client.get('/api/v1/state').json()['endpoints'][endpoint]['sources'][0]['id']
        assert change(client,f'/endpoints/{endpoint}/supplicant',{'source_id':source_id,'template_id':tid}).status_code==200
        assert change(client,f'/endpoints/{endpoint}/supplicant',{'source_id':source_id,'profile':{'username':'custom'}}).status_code==200
        assert change(client,'/radius/templates',{'id':tid,'profile':{'password':'replacement'}}).status_code==200
        saved=store.load()
        assert saved.endpoints[endpoint].sources[0].supplicant.password=='synthetic-profile-password'
        assert saved.endpoints[endpoint].sources[0].supplicant.username=='custom'
        assert saved.radius.templates[tid].profile.password=='replacement' and saved.radius.templates[tid].revision==1
        assert change(client,f'/radius/materials/{trust.id}',method='DELETE').status_code==422
        before=client.app.state.engine.state.cfg.model_dump(mode='json')
        assert change(client,f'/endpoints/{endpoint}/supplicant',{'source_id':source_id,'profile':{'trust_id':'missing'}}).status_code==422
        assert client.app.state.engine.state.cfg.model_dump(mode='json')==before
        state=client.get('/api/v1/state').json();text=json.dumps(state)
        assert 'synthetic-profile-password' not in text and 'replacement' not in text and 'BEGIN CERTIFICATE' not in text and 'PRIVATE KEY' not in text
        assert state['endpoints'][endpoint]['sources'][0]['supplicant']['has_password']
        clone=change(client,f'/endpoints/{endpoint}/clone',{}).json()['id']
        saved=store.load();assert saved.endpoints[clone].sources[0].mac!=saved.endpoints[endpoint].sources[0].mac
        assert saved.endpoints[clone].sources[0].supplicant==saved.endpoints[endpoint].sources[0].supplicant
        scenario=client.get('/api/v1/scenarios/export').json()
        assert 'radius' not in scenario and all('supplicant' not in s for e in scenario['endpoints'].values() for s in e['sources'])


@pytest.mark.asyncio
async def test_profile_save_preserves_grant_and_jobs_but_restart_does_not(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute('radius-result',{**capture,'result':AccessResult(2,(),PEER,bytes(16))})
    await engine.execute('advance',{'duration_ms':1000})
    session=engine.state.radius_sessions[(pid,capture['mac'])].id
    jobs=copy.deepcopy(engine.state.jobs);fdb=copy.deepcopy(engine.state.fdb);source_id=engine.state.cfg.endpoints[eid].sources[0].id
    await engine.execute('source-supplicant-save',{'id':eid,'source_id':source_id,'profile':{'identity':'future'}})
    assert engine.state.radius_sessions[(pid,capture['mac'])].id==session and engine.state.jobs==jobs and engine.state.fdb==fdb
    await engine.execute('source-supplicant-save',{'id':eid,'source_id':source_id,'profile':{'identity':'restart'},'restart':True})
    assert not engine.state.radius_sessions and not engine.state.fdb and engine.state.up(pid)
    assert engine.state.radius_attempts[(pid,capture['mac'])].id!=capture['attempt_id']
    assert engine.state.jobs==jobs


@pytest.mark.asyncio
async def test_changed_pending_profile_rejects_late_result_and_noop_port_save_preserves_work(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    jobs=copy.deepcopy(engine.state.jobs);gens=copy.deepcopy(engine.state.pgens)
    fields=engine.state.cfg.ports[pid].model_dump();fields={k:v for k,v in fields.items() if k not in ('id','if_index','bridge_port')}
    await engine.execute('port-edit',{'id':pid,'patch':fields})
    assert engine.state.jobs==jobs and engine.state.pgens==gens
    assert engine.state.current_attempt((pid,capture['mac']),capture['attempt_id'])
    source_id=engine.state.cfg.endpoints[eid].sources[0].id
    await engine.execute('source-supplicant-save',{'id':eid,'source_id':source_id,'profile':{'identity':'changed'}})
    before=engine.state
    assert not (await engine.execute('radius-result',{**capture,'result':AccessResult(2,(),PEER,bytes(16))}))['accepted']
    assert engine.state is before and not engine.state.radius_sessions


@pytest.mark.asyncio
async def test_populated_encrypted_v3_store_migration_preserves_baseline_and_reloads(tmp_path):
    from cryptography.fernet import Fernet
    from switchlab.storage import Store
    cfg=initial_configuration(2);cfg.paused=True
    engine=Engine(cfg);ports=list(cfg.ports)
    await engine.execute('vlan-create',{'vid':20,'name':'Preserved VLAN','fdb_id':3020})
    await engine.execute('port-edit',{'id':ports[1],'patch':{'mode':'shared','shared_partner':True,'pvid':20,'admitted':[1,20],'untagged':[20],'alias':'Preserved port'}})
    one=(await engine.execute('endpoint-create',{'name':'Preserved one','metadata':{'fixture':'baseline'},'sources':[{'mac':'02:00:00:00:00:11'},{'mac':'02:00:00:00:00:12','tag':20}]}))['id']
    two=(await engine.execute('endpoint-create',{'name':'Preserved two','sources':[{'mac':'02:00:00:00:00:21','tag':20}]}))['id']
    await engine.execute('attach',{'id':one,'port_id':ports[0]});await engine.execute('attach',{'id':two,'port_id':ports[1]})
    community=(await engine.execute('credential-save',{'label':'Preserved community','community':'synthetic-v3-baseline-community','polling':{'enabled':True,'view_id':'all','networks':['127.0.0.0/8']},'writing':{'enabled':True,'view_id':'interfaces','networks':['192.0.2.0/24']}}))['id']
    group=(await engine.execute('group-save',{'label':'Preserved group','minimum_security_level':'authPriv','polling':{'enabled':True,'view_id':'all'},'writing':{'enabled':False,'view_id':'interfaces'}}))['id']
    await engine.execute('credential-save',{'label':'Preserved user','version':'3','username':'baseline-user','security_level':'authPriv','auth_key':'synthetic-auth-key','priv_key':'synthetic-priv-key','group_id':group})
    await engine.execute('target-save',{'address':'192.0.2.8','port':2162,'credential_id':community,'enabled':False})
    legacy=engine.state.cfg.model_dump(mode='json');legacy['schema_version']=3;legacy.pop('radius')
    for port in legacy['ports'].values():port.pop('authentication')
    for endpoint in legacy['endpoints'].values():
        for source in endpoint['sources']:source.pop('supplicant')
    original=copy.deepcopy(legacy);key=Fernet.generate_key();path=tmp_path/'baseline.db'
    store=Store(str(path),key)
    with store.transaction():store.put('configuration',legacy)
    blob=store.db.execute('SELECT value FROM kv WHERE key=?',('configuration',)).fetchone()[0]
    assert b'synthetic-v3-baseline-community' not in blob and b'synthetic-auth-key' not in blob
    store.close();store=Store(str(path),key)
    try:
        loaded=store.load();assert store.get('configuration')==original
        normalized=loaded.model_dump(mode='json');normalized['schema_version']=3;normalized.pop('radius')
        for port in normalized['ports'].values():port.pop('authentication')
        for endpoint in normalized['endpoints'].values():
            for source in endpoint['sources']:source.pop('supplicant')
        assert normalized==original and loaded.schema_version==4
        assert all(port.authentication.control=='force-authorized' for port in loaded.ports.values())
        assert not loaded.radius.servers and not loaded.radius.dynamic_authorization.senders
        assert not loaded.radius.accounting.enabled and not loaded.radius.dynamic_authorization.enabled
        assert all(source.supplicant is None for endpoint in loaded.endpoints.values() for source in endpoint.sources)
        migrated=Engine(loaded,store);await migrated.execute('advance',{'duration_ms':1000})
        assert migrated.state.fdb and not migrated.state.radius_attempts and not migrated.state.radius_sessions
        await migrated.execute('switch-edit',{'location':loaded.switch.location})
        saved=migrated.state.cfg.model_dump(mode='json')
    finally:store.close()
    store=Store(str(path),key)
    try:assert store.load().model_dump(mode='json')==saved and store.get('startup_configuration')['schema_version']==4 and store.get('configuration') is None
    finally:store.close()
