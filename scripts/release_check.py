"""Run inside the clean runtime image, using only its runtime dependencies."""
import asyncio
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
from cryptography.fernet import Fernet
from pysnmp.hlapi.v3arch.asyncio import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, get_cmd


with tempfile.TemporaryDirectory() as root:
    key=Path(root)/'key';key.write_bytes(Fernet.generate_key())
    env={**os.environ,'SWITCHLAB_KEY_FILE':str(key),'SWITCHLAB_DB':str(Path(root)/'lab.db'),'SWITCHLAB_SETUP_TOKEN':'release-fixture-token'}
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf=''
    def request(route,method='GET',data=None):
        req=urllib.request.Request('http://127.0.0.1:8000'+route,method=method,
            data=json.dumps(data).encode() if data is not None else None,
            headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
        return json.load(opener.open(req,timeout=3))
    def launch():
        process=subprocess.Popen(['uvicorn','switchlab.api:app','--host','127.0.0.1','--port','8000'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if request('/healthz')['ready']:return process
            except OSError:pass
            time.sleep(.05)
        process.kill();raise RuntimeError('Application did not become healthy')
    def stop(process):
        process.terminate();process.wait(timeout=5)
    def command(route,body,method='POST'):
        rev=request('/api/v1/state')['configuration_revision']
        return request('/api/v1'+route,method,{**body,'expected_configuration_revision':rev})
    process=launch()
    try:
        csrf=request('/api/v1/auth/setup','POST',{'setup_token':'release-fixture-token','password':'release-fixture-password'})['csrf_token']
        state=request('/api/v1/state')
        assert state['switch']['identity']['sys_object_id'] is None and not state['snmp_status']['ready']
        assert len(state['ports'])==24
        assert not Path('/app/development').exists()
        command('/clock/pause',{})
        command('/clock/advance',{'duration_ms':1000})
        assert request('/api/v1/state')['simulation_ms']>=1000
        command('/switch',{'identity':{'sys_object_id':'2.999.123'}},'PATCH')
        command('/snmp/credentials',{'label':'release-fixture','community':'release-fixture-community'})
        command('/snmp/settings',{'enabled':True},'PATCH')
        async def read_identity():
            manager=SnmpEngine()
            try:
                return await get_cmd(manager,CommunityData('release-fixture-community',mpModel=1),
                    await UdpTransportTarget.create(('127.0.0.1',1161),timeout=.2,retries=0),ContextData(),ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')))
            finally:manager.close_dispatcher()
        error,status,_,rows=asyncio.run(read_identity())
        assert not error and not status and str(rows[0][1])=='2.999.123'
        first=request('/api/v1/snmp/status')
        stop(process);process=launch()
        csrf=request('/api/v1/auth/login','POST',{'password':'release-fixture-password'})['csrf_token']
        second=request('/api/v1/snmp/status')
        assert second['engine_id']==first['engine_id'] and second['engine_boots']>first['engine_boots']
        assert request('/api/v1/state')['switch']['identity']['sys_object_id']=='2.999.123'
        command('/switch',{'identity':{'sys_object_id':None}},'PATCH')
        assert not request('/api/v1/snmp/status')['ready']
        assert asyncio.run(read_identity())[0] is not None
        stop(process);process=launch()
        csrf=request('/api/v1/auth/login','POST',{'password':'release-fixture-password'})['csrf_token']
        assert request('/api/v1/state')['switch']['identity']['sys_object_id'] is None
        assert request('/healthz')['ready']
        print(json.dumps({'clean_runtime_image':'passed','default_identity':None,'simulation_without_snmp':'passed',
            'operator_oid_roundtrip':'passed','process_restart_identity_and_usm_boots':'passed','clear_stops_polling':'passed','persist_unset_on_restart':'passed'}))
    finally:stop(process)
