"""Independent Net-SNMP compatibility checks, installed in Docker's test stage."""
import asyncio
import shutil
import pytest
from conftest import endpoint, tick
from test_wire import start

pytestmark=pytest.mark.skipif(shutil.which('snmpget') is None,reason='Net-SNMP required; run Docker test stage')


async def command(*args):
    process=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    stdout,stderr=await asyncio.wait_for(process.communicate(),10)
    assert process.returncode==0,stderr.decode()
    return stdout.decode()


@pytest.mark.parametrize('level',['noAuthNoPriv','authNoPriv','authPriv'])
async def test_independent_netsnmp_v3(engine,level):
    e=engine;a,port=await start(e,version='3',username='netsnmp-fixture',security_level=level,
                              auth_key='fixture-auth-pass',priv_key='fixture-priv-pass',community=None)
    try:
        base=['snmpget','-v3','-u','netsnmp-fixture','-l',level,'-On','-t','1','-r','1']
        if level!='noAuthNoPriv':base+=['-a','SHA-256','-A','fixture-auth-pass']
        if level=='authPriv':base+=['-x','AES','-X','fixture-priv-pass']
        address=f'127.0.0.1:{port}'
        assert '1.3.999.123' in await command(*base,address,'1.3.6.1.2.1.1.2.0')
        await e.execute('switch-edit',{'identity':{'sys_object_id':'2.999.123'}})
        assert '2.999.123' in await command(*base,address,'1.3.6.1.2.1.1.2.0')
        await endpoint(e);await tick(e)
        assert 'INTEGER: 1' in await command(*base,address,'1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.16')
        await e.execute('reboot');await a.reboot()
        assert '2.999.123' in await command(*base,address,'1.3.6.1.2.1.1.2.0')
    finally:a.close()


async def test_netsnmp_bulk_timefilter_and_walk(engine):
    e=engine;a,port=await start(e)
    try:
        base=['-v2c','-c','fixture-poll','-On','-t','1','-r','0',f'127.0.0.1:{port}']
        result=await command('snmpbulkwalk',*base,'1.3.6.1.2.1.17.7')
        assert '.1001 = Counter32: 0' in result
        assert 'No more variables' not in result
        e.state.boot_start-=2
        await e.execute('vlan-create',{'vid':10})
        result=await command('snmpget',*base,'1.3.6.1.2.1.17.7.1.4.2.1.3.100.10')
        assert 'Gauge32: 1010' in result
        result=await command('snmpgetnext',*base,'1.3.6.1.2.1.17.7.1.4.2.1.7.100.10')
        assert '1.3.6.1.2.1.17.7.1.4.3.1.1.1' in result
    finally:a.close()


async def test_live_edit_and_vlan_fallback_on_wire(engine):
    e=engine;a,port=await start(e)
    try:
        p=next(iter(e.state.cfg.ports))
        await e.execute('vlan-create',{'vid':10})
        await e.execute('port-edit',{'id':p,'patch':{'pvid':10,'admitted':[1,10]}})
        eid=await endpoint(e)
        await tick(e)
        base=['-v2c','-c','fixture-poll','-On','-t','1','-r','0',f'127.0.0.1:{port}']
        old='1.3.6.1.2.1.17.7.1.2.2.1.2.1010.2.0.0.0.0.16'
        await e.execute('endpoint-edit',{'id':eid,'patch':{'sources':[{'mac':'02:00:00:00:00:20'}]}})
        assert 'INTEGER: 1' in await command('snmpget',*base,old)
        await tick(e)
        assert (await command('snmpwalk',*base,'1.3.6.1.2.1.17.7.1.2.2.1.2')).count('INTEGER: 1')==2
        await e.execute('vlan-delete',{'vid':10})
        result=await command('snmpget',*base,'1.3.6.1.2.1.17.7.1.4.5.1.1.1','1.3.6.1.2.1.17.7.1.4.3.1.2.1',old)
        assert 'Gauge32: 1' in result and 'No Such Instance' in result
        await tick(e)
        assert 'INTEGER: 1' in await command('snmpget',*base,'1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.32')
    finally:a.close()


async def test_authenticated_notification_with_independent_snmptrapd(engine,tmp_path):
    from test_wire import free_port
    e=engine;a,port=await start(e)
    process=None
    try:
        cid=(await e.execute('credential-save',{'label':'secure trap','version':'3','purpose':'notification','username':'trap-fixture',
             'security_level':'authPriv','auth_key':'fixture-auth-pass','priv_key':'fixture-priv-pass'}))['id']
        trap_port=free_port()
        tid=(await e.execute('target-save',{'address':'127.0.0.1','port':trap_port,'credential_id':cid}))['id']
        await a.reconcile()
        config=tmp_path/'snmptrapd.conf'
        config.write_text(f'createUser -e 0x{a.engine_id.hex()} trap-fixture SHA-256 fixture-auth-pass AES fixture-priv-pass\nauthUser log trap-fixture priv\n')
        process=await asyncio.create_subprocess_exec('snmptrapd','-f','-Lo','-C','-c',str(config),'-n','-On',f'udp:127.0.0.1:{trap_port}',
            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
        await asyncio.sleep(.2)
        await e.execute('test-notification',{'target_id':tid});await a.drain_one()
        await endpoint(e);await a.drain_one()
        await asyncio.sleep(.3)
        process.terminate();output=(await asyncio.wait_for(process.communicate(),3))[0].decode()
        assert '1.3.6.1.6.3.1.1.5.1' in output and '1.3.6.1.6.3.1.1.5.4' in output,output
    finally:
        if process and process.returncode is None:process.kill();await process.wait()
        a.close()
