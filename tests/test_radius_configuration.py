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


async def test_operation_validation_does_not_reparse_untouched_material(configured, store, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from switchlab.models import Configuration
    from test_engine import set_binding, a, stored_state
    cfg,pid,eid=configured
    cfg.ports[pid].authentication.control="force-authorized"
    cfg.endpoints[eid].active=False
    engine=Engine(cfg,store)
    calls={"configuration":0,"certificate":0,"key":0}
    def tracked(name, original):
        def call(*args,**kwargs):
            calls[name]+=1
            return original(*args,**kwargs)
        return call
    monkeypatch.setattr(Configuration,"model_validate",tracked("configuration",Configuration.model_validate))
    monkeypatch.setattr(x509,"load_pem_x509_certificates",tracked("certificate",x509.load_pem_x509_certificates))
    monkeypatch.setattr(serialization,"load_pem_private_key",tracked("key",serialization.load_pem_private_key))
    for action,payload in [
        ("pause",{}),("resume",{}),("advance",{"duration_ms":100,"automatic":True}),
        ("notification-result",{"notification_id":0,"target_id":"absent","status":"delivered"}),
        ("radius-settings",{"discovery_seconds":4,"nas_ip_address":"192.0.2.4"}),
        ("accounting-settings",{"attempts":2}),("dynamic-settings",{"port":3798}),
        ("switch-edit",{"location":"Elsewhere"}),("port-edit",{"id":pid,"patch":{"alias":"Changed"}}),
        ("endpoint-edit",{"id":eid,"patch":{"name":"Changed"}}),
        ("credential-save",{"label":"Unrelated","community":"synthetic-operation-community"}),
    ]:
        await engine.execute(action,payload)
        assert calls=={"configuration":0,"certificate":0,"key":0}, action
    for request in ([], [set_binding("2.2.1.7.101",a.Integer32(1))],
                    [set_binding("2.2.1.7.101",a.Integer32(2))]):
        async with engine.lock:engine.set_locked(request,["1"])
        assert calls=={"configuration":0,"certificate":0,"key":0}
    before=engine.state;persisted=stored_state(store)
    for action,payload in [("radius-settings",{"nas_identifier":""}),
                           ("accounting-settings",{"interim_seconds":1}),
                           ("dynamic-settings",{"host":"not-an-ip"})]:
        with pytest.raises(ValidationError):await engine.execute(action,payload)
        assert engine.state is before and stored_state(store)==persisted
    assert calls=={"configuration":0,"certificate":0,"key":0}
    identity=next(m for m in cfg.radius.materials.values() if m.kind=="client")
    with pytest.raises(ValidationError):
        await engine.execute("radius-material-save",{"id":identity.id,"private_key":"not-a-key"})
    assert calls=={"configuration":0,"certificate":1,"key":1}
    assert engine.state is before and stored_state(store)==persisted
    # Whole replacement, unlike scalar mutation, still owns recursive validation.
    await engine.execute("import",engine.export())
    assert calls["configuration"]==1 and calls["key"]==2
    await engine.execute("reboot")
    assert calls["configuration"]==2 and calls["key"]==3


@pytest.mark.parametrize("owner",["template","source"])
@pytest.mark.parametrize("method",["tls","peap"])
@pytest.mark.parametrize("mutation",["delete","kind"])
async def test_material_reverse_dependency_includes_inactive_optional_identity(configured,owner,method,mutation):
    from switchlab.models import SupplicantTemplate, SupplicantProfile
    cfg,pid,eid=configured
    cfg.endpoints[eid].active=False
    source=cfg.endpoints[eid].sources[0]
    identity=cfg.radius.materials[source.supplicant.client_identity_id]
    fields=source.supplicant.model_dump()
    fields.update(method=method,username="synthetic",password="synthetic")
    profile=SupplicantProfile.model_validate(fields)
    if owner=="template":
        source.supplicant=None
        template=SupplicantTemplate(label="Unused",profile=profile)
        cfg.radius.templates[template.id]=template
    else:source.supplicant=profile
    engine=Engine(cfg);before=engine.state
    action="radius-material-"+("delete" if mutation=="delete" else "save")
    payload={"id":identity.id}
    if mutation=="kind":payload.update(kind="ca",private_key=None,key_password=None)
    with pytest.raises(ValidationError):await engine.execute(action,payload)
    assert engine.state is before


@pytest.mark.parametrize("family,limit",[("servers",16),("accounting",16),("senders",64),("materials",128),("templates",256)])
async def test_radius_edited_collection_bounds_without_recursive_validation(configured,monkeypatch,family,limit):
    from switchlab.models import Configuration, RadiusServer, DynamicSender, SupplicantTemplate
    cfg,pid,eid=configured
    if family in ("servers","accounting"):
        values=[RadiusServer(id=str(i),label=str(i),address="192.0.2.1",secret="synthetic") for i in range(limit)]
        if family=="servers":cfg.radius.servers=values;action="radius-server-save"
        else:cfg.radius.accounting.targets=values;action="accounting-target-save"
        payload={"id":"extra","label":"Extra","address":"192.0.2.2","secret":"synthetic"}
    elif family=="senders":
        cfg.radius.dynamic_authorization.senders=[DynamicSender(id=str(i),label=str(i),address="192.0.2.1",secret="synthetic",enabled=False) for i in range(limit)]
        action="dynamic-sender-save";payload={"id":"extra","label":"Extra","address":"192.0.2.2","secret":"synthetic"}
    elif family=="materials":
        material=next(m for m in cfg.radius.materials.values() if m.kind=="client")
        for i in range(limit-len(cfg.radius.materials)):
            cfg.radius.materials[str(i)]=material.model_copy(update={"id":str(i)})
        action="radius-material-save";payload={**material.model_dump(),"id":"extra"}
    else:
        cfg.radius.templates={str(i):SupplicantTemplate(id=str(i),label=str(i),profile=cfg.endpoints[eid].sources[0].supplicant) for i in range(limit)}
        action="radius-template-save";payload={"id":"extra","label":"Extra","profile":cfg.endpoints[eid].sources[0].supplicant.model_dump()}
    engine=Engine(cfg);before=engine.state
    def unexpected(*args,**kwargs):pytest.fail("Unrelated full validation")
    monkeypatch.setattr(Configuration,"model_validate",unexpected)
    with pytest.raises(ValidationError) as error:await engine.execute(action,payload)
    assert error.value.errors()[0]["type"]=="too_long" and engine.state is before
    # Replacement at the limit remains legal.
    payload["id"]=next(iter(cfg.radius.materials)) if family=="materials" else "0"
    if family=="materials":payload.update(cfg.radius.materials[payload["id"]].model_dump())
    await engine.execute(action,payload)


def test_resource_projection_shares_redaction_without_helper_audit(configured,store,monkeypatch):
    import switchlab.radius as radius
    from switchlab.models import Community, UsmUser
    cfg,pid,eid=configured
    cfg.ports[pid].authentication.control="force-authorized"
    for credential in [Community(id="community",label="Community",community="synthetic-secret"),
                       UsmUser(id="noauth",label="None",username="one",security_level="noAuthNoPriv"),
                       UsmUser(id="auth",label="Auth",username="two",security_level="authNoPriv",auth_key="synthetic-auth-key"),
                       UsmUser(id="priv",label="Priv",username="three",security_level="authPriv",auth_key="synthetic-auth-key",priv_key="synthetic-priv-key")]:
        cfg.credentials[credential.id]=credential
    calls=[]
    def audit():
        calls.append(None)
        return {"ready":len(calls)==1,"reason":"synthetic"}
    monkeypatch.setattr(radius,"eap_capability",audit)
    with TestClient(create_app(store,cfg)) as client:
        sign_in(client,store)
        full=client.get("/api/v1/state").json()
        assert len(calls)==1 and full["radius"]["eap_capability"]["ready"]
        for family,key in [("switch","switch"),("ports","ports"),("endpoints","endpoints"),("vlans","vlans"),("fdb","fdb"),
                           ("snmp/settings","snmp"),("snmp/credentials","credentials"),("snmp/groups","groups"),
                           ("snmp/views","views"),("notifications/targets","targets")]:
            assert client.get("/api/v1/"+family).json()=={"revision":full["revision"],"data":full[key]}
        for family,ident in [("ports",pid),("endpoints",eid),("vlans","1")]:
            assert client.get(f"/api/v1/{family}/{ident}").json()=={"revision":full["revision"],"data":full[family][ident]}
            assert client.get(f"/api/v1/{family}/missing").status_code==404
        assert client.get("/api/v1/vlans/01").status_code==404 and len(calls)==1
        assert not client.get("/api/v1/state").json()["radius"]["eap_capability"]["ready"] and len(calls)==2
