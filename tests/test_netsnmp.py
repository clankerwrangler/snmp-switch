"""Independent Net-SNMP compatibility checks, installed in Docker's test stage."""
import asyncio
import shutil
import pytest
from conftest import endpoint, tick
from test_wire import start, access_command

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
        assert 'INTEGER: 3' in await command(*base,address,'1.3.6.1.2.1.47.1.1.1.1.5.1')
        primary = next(iter(e.state.cfg.credentials.values()))
        gid = primary.group_id
        await e.execute('credential-save', {'label': 'Second group member', 'version': '3',
            'username': 'netsnmp-second', 'security_level': level, 'group_id': gid,
            'auth_key': 'second-auth-pass', 'priv_key': 'second-priv-pass'})
        await a.reconcile()
        second = [({'netsnmp-fixture': 'netsnmp-second', 'fixture-auth-pass': 'second-auth-pass',
                    'fixture-priv-pass': 'second-priv-pass'}).get(arg, arg) for arg in base]
        assert '1.3.999.123' in await command(*second,address,'1.3.6.1.2.1.1.2.0')
        await e.execute('group-save', {'id': gid, 'polling': {'view_id': 'interfaces'}})
        await a.reconcile()
        for manager in (base, second):
            assert 'No Such Object' in await command(*manager,address,'1.3.6.1.2.1.47.1.1.1.1.5.1')
            assert '1.3.999.123' in await command(*manager,address,'1.3.6.1.2.1.1.2.0')
        await e.execute('group-save', {'id': gid, 'polling': {'view_id': 'all'}})
        if level != 'authPriv':
            await e.execute('group-save', {'id': gid, 'minimum_security_level': 'authPriv'})
            await a.reconcile()
            for manager in (base, second):
                with pytest.raises(AssertionError, match='Timeout'):
                    await command(*manager,address,'1.3.6.1.2.1.1.2.0')
            await e.execute('group-save', {'id': gid, 'minimum_security_level': level})
        await a.reconcile()
        for manager in (base, second):
            assert 'INTEGER: 3' in await command(*manager,address,'1.3.6.1.2.1.47.1.1.1.1.5.1')
        await e.execute('switch-edit',{'identity':{'sys_object_id':'2.999.123'}})
        assert '2.999.123' in await command(*base,address,'1.3.6.1.2.1.1.2.0')
        await endpoint(e);await tick(e)
        assert 'INTEGER: 1' in await command(*base,address,'1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.16')
        await e.execute('save-startup')
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
        cid=(await e.execute('credential-save',{'label':'secure trap','version':'3','username':'trap-fixture',
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


async def test_protocol_change_replaces_wire_credentials(engine):
    e=engine;a,port=await start(e,polling={'enabled':True,'networks':['127.0.0.0/8']})
    try:
        cid=next(iter(e.state.cfg.credentials))
        address=f'127.0.0.1:{port}'
        oid='1.3.6.1.2.1.1.2.0'
        v2=['snmpget','-v2c','-c','fixture-poll','-On','-t','1','-r','0',address,oid]
        assert '1.3.999.123' in await command(*v2)
        await e.execute('credential-save',{'id':cid,'version':'3','username':'changed-v3',
            'security_level':'authPriv','auth_key':'changed-auth-pass','priv_key':'changed-priv-pass','access_transfer':'keep'})
        await a.reconcile()
        with pytest.raises(AssertionError,match='Timeout'):
            await command(*v2)
        v3=['snmpget','-v3','-u','changed-v3','-l','authPriv','-a','SHA-256','-A','changed-auth-pass',
            '-x','AES','-X','changed-priv-pass','-On','-t','1','-r','0',address,oid]
        assert '1.3.999.123' in await command(*v3)
        await e.execute('credential-save',{'id':cid,'label':'same-version edit','auth_key':'','priv_key':''})
        await a.reconcile()
        assert '1.3.999.123' in await command(*v3)
        await e.execute('credential-save',{'id':cid,'version':'2c','community':'changed-v2','access_transfer':'keep'})
        await a.reconcile()
        with pytest.raises(AssertionError,match='Timeout|Unknown user name'):
            await command(*v3)
        assert '1.3.999.123' in await command('snmpget','-v2c','-c','changed-v2','-On','-t','1','-r','0',address,oid)
        assert e.state.cfg.credentials[cid].polling.networks==['127.0.0.0/8']
    finally:a.close()


async def test_shared_v3_credential_polling_and_traps_are_independent(engine, tmp_path):
    from test_wire import free_port
    e = engine
    a, port = await start(e)
    process = None
    try:
        gid = (await e.execute('group-save', {'label': 'Shared management', 'minimum_security_level': 'authPriv',
            'polling': {'enabled': True, 'view_id': 'interfaces', 'networks': ['127.0.0.0/8']}}))['id']
        cid = (await e.execute('credential-save', {'label': 'Shared USM', 'version': '3',
            'username': 'shared-usm', 'security_level': 'authPriv', 'auth_key': 'shared-auth-pass',
            'priv_key': 'shared-priv-pass', 'group_id': gid}))['id']
        trap_port = free_port()
        tid = (await e.execute('target-save', {'address': '127.0.0.1', 'port': trap_port, 'credential_id': cid}))['id']
        await a.reconcile()
        config = tmp_path / 'shared-snmptrapd.conf'
        config.write_text(f'createUser -e 0x{a.engine_id.hex()} shared-usm SHA-256 shared-auth-pass AES shared-priv-pass\nauthUser log shared-usm priv\n')
        process = await asyncio.create_subprocess_exec('snmptrapd', '-f', '-Lo', '-C', '-c', str(config), '-n', '-On',
            f'udp:127.0.0.1:{trap_port}', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        await asyncio.sleep(.2)
        async def trap():
            await e.execute('test-notification', {'target_id': tid})
            await a.drain_one()
            async def capture():
                while True:
                    line = await process.stdout.readline()
                    assert line, 'Trap receiver exited before receiving coldStart'
                    if b'1.3.6.1.6.3.1.1.5.1' in line:
                        return
            await asyncio.wait_for(capture(), 2)
        base = ['snmpget', '-v3', '-u', 'shared-usm', '-l', 'authPriv', '-a', 'SHA-256', '-A', 'shared-auth-pass',
                '-x', 'AES', '-X', 'shared-priv-pass', '-On', '-t', '1', '-r', '0', f'127.0.0.1:{port}']
        oid = '1.3.6.1.2.1.1.2.0'
        assert '1.3.999.123' in await command(*base, oid)
        assert 'No Such Object' in await command(*base, '1.3.6.1.2.1.17.1.1.0')
        await trap()
        await e.execute(*access_command(e, cid, {'polling': {'networks': ['192.0.2.0/24']}}))
        await a.reconcile()
        with pytest.raises(AssertionError, match='Timeout'):
            await command(*base, oid)
        await trap()
        await e.execute(*access_command(e, cid, {'polling': {'enabled': False, 'networks': []}}))
        await a.reconcile()
        assert a.listening and a.status()['notifications_ready']
        with pytest.raises(AssertionError, match='Timeout'):
            await command(*base, oid)
        await trap()
        # Removing the last polling permission closes only the incoming listener.
        other = next(k for k in e.state.cfg.credentials if k != cid)
        await e.execute(*access_command(e, other, {'polling': {'enabled': False}}))
        await a.reconcile()
        assert not a.listening and a.status()['notifications_ready']
        await trap()
        await e.execute(*access_command(e, cid, {'writing': {'enabled': True, 'view_id': 'all'}}))
        await a.reconcile()
        assert a.listening and a.status()['writing_ready'] and not a.status()['ready']
        await command('snmpset', *base[1:], '1.3.6.1.2.1.2.2.1.7.101', 'i', '2')
        assert not next(iter(e.state.cfg.ports.values())).admin_up
        with pytest.raises(AssertionError, match='Timeout'):
            await command(*base, oid)
        await trap()
        await e.execute(*access_command(e, cid, {'writing': {'enabled': False}}))
        await a.reconcile()
        assert not a.listening and a.status()['notifications_ready']
        await trap()
        assert e.state.cfg.groups[gid].polling.view_id == 'interfaces'
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.communicate(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()
        a.close()


@pytest.mark.parametrize("version", ["2c", "3"])
async def test_entity_inventory_with_independent_netsnmp(engine, version):
    import re
    import uuid
    e = engine
    credential = {} if version == "2c" else dict(version="3", username="entity-fixture", community=None,
        security_level="authPriv", auth_key="entity-auth-pass", priv_key="entity-priv-pass")
    a, port = await start(e, **credential)
    try:
        access = ["-v2c", "-c", "fixture-poll"] if version == "2c" else ["-v3", "-u", "entity-fixture",
            "-l", "authPriv", "-a", "SHA-256", "-A", "entity-auth-pass", "-x", "AES", "-X", "entity-priv-pass"]
        base = [*access, "-On", "-t", "1", "-r", "1", f"127.0.0.1:{port}"]
        entity = "1.3.6.1.2.1.47"
        physical = entity + ".1.1.1.1"
        expected = {f"{physical}.{column}.{index}" for column in range(2, 20) for index in range(1, 6)}
        expected |= {f"{entity}.1.3.2.1.2.{index}.0" for index in range(2, 6)}
        expected |= {f"{entity}.1.3.3.1.1.1.{index}" for index in range(2, 6)}
        expected.add(entity + ".1.4.1.0")
        for tool in ("snmpwalk", "snmpbulkwalk"):
            output = await command(tool, *base, entity)
            rows = output.splitlines()
            terminal = f".{entity}.1.4.1.0 = No more variables left in this MIB View (It is past the end of the MIB tree)"
            # Net-SNMP can print the terminal exception after the last data row.
            if rows and rows[-1] == terminal:
                rows.pop()
            entries = [row.split(" = ", 1) for row in rows]
            assert all(len(entry) == 2 and entry[1] and not entry[1].startswith("No ") for entry in entries), output
            names = [name.lstrip(".") for name, value in entries]
            assert len(names) == 99 and set(names) == expected, output
            assert names == sorted(names, key=lambda name: tuple(map(int, name.split("."))))
        assert "OID: .0.0" in await command("snmpget", *base, physical + ".3.1")
        assert "INTEGER: -1" in await command("snmpget", *base, physical + ".6.1")
        assert "OID: .1.3.6.1.2.1.2.2.1.1.101" in await command("snmpget", *base, entity + ".1.3.2.1.2.2.0")
        for suffix, octets in ((".17.1", bytes(8)), (".19.1", uuid.UUID(e.state.cfg.switch.id).bytes)):
            output = await command("snmpget", "-Ox", *base, physical + suffix)
            assert "Hex-STRING:" in output, output
            assert bytes.fromhex(output.split("Hex-STRING:", 1)[1].strip()) == octets
        assert uuid.UUID(e.state.cfg.switch.id).urn in await command("snmpget", *base, physical + ".18.1")
        for before, after in ((physical + ".19.5", entity + ".1.3.2.1.2.2.0"),
                (entity + ".1.3.2.1.2.5.0", entity + ".1.3.3.1.1.1.2"),
                (entity + ".1.3.3.1.1.1.5", entity + ".1.4.1.0")):
            assert (await command("snmpgetnext", *base, before)).split(" = ", 1)[0].lstrip(".") == after
        # Explicit hex output checks wire UTF-8 independently of host locale.
        pid = next(iter(e.state.cfg.ports))
        for text in ("café", "交换机"):
            await e.execute("switch-edit", {"name": text, "description": text})
            await e.execute("port-edit", {"id": pid, "patch": {"name": text}})
            for suffix in (".2.1", ".7.1", ".7.2"):
                output = await command("snmpget", "-Ox", *base, physical + suffix)
                assert "Hex-STRING:" in output, output
                assert bytes.fromhex(output.split("Hex-STRING:", 1)[1].strip()) == text.encode("utf-8")
        clock = entity + ".1.4.1.0"
        e.state.boot_start -= 2
        await e.execute("switch-edit", {"name": "Entity chassis"})
        changed = await command("snmpget", *base, clock)
        assert int(re.search(r"Timeticks: \((\d+)\)", changed)[1]) >= 200
        pid = next(iter(e.state.cfg.ports))
        await e.execute("port-edit", {"id": pid, "patch": {"alias": "a" * 64}})
        assert await command("snmpget", *base, clock) == changed
        cid = next(iter(e.state.cfg.credentials))
        await e.execute(*access_command(e, cid, {'polling': {'view_id': 'interfaces'}}))
        await a.reconcile()
        assert "No Such Object" in await command("snmpget", *base, physical + ".7.1")
        assert "1.3.999.123" in await command("snmpget", *base, "1.3.6.1.2.1.1.2.0")
    finally:
        a.close()


@pytest.mark.parametrize("level", ["2c", "noAuthNoPriv", "authNoPriv", "authPriv"])
async def test_independent_netsnmp_set_vlan_admin_permissions_and_restart(engine, level):
    e = engine
    credential = {} if level == "2c" else dict(version="3", username="set-fixture", community=None,
        security_level=level, auth_key="set-auth-pass", priv_key="set-priv-pass")
    a, port = await start(e, **credential)
    try:
        access = ["-v2c", "-c", "fixture-poll"] if level == "2c" else ["-v3", "-u", "set-fixture", "-l", level]
        if level in ("authNoPriv", "authPriv"):
            access += ["-a", "SHA-256", "-A", "set-auth-pass"]
        if level == "authPriv":
            access += ["-x", "AES", "-X", "set-priv-pass"]
        base = [*access, "-On", "-t", "1", "-r", "0", f"127.0.0.1:{port}"]
        admin = "1.3.6.1.2.1.2.2.1.7.101"
        static = "1.3.6.1.2.1.17.7.1.4.3.1"
        pvid = "1.3.6.1.2.1.17.7.1.4.5.1.1.1"
        cid = next(iter(e.state.cfg.credentials))
        pid = next(iter(e.state.cfg.ports))
        before = e.state
        with pytest.raises(AssertionError, match="authorizationError"):
            await command("snmpset", *base, admin, "i", "2")
        assert e.state is before
        await e.execute(*access_command(e, cid, {'writing': {'enabled': True, 'view_id': 'all', 'networks': ['127.0.0.0/8']}}))
        await a.reconcile()
        eid = await endpoint(e)
        await tick(e)
        assert e.state.fdb
        await command("snmpset", *base, admin, "i", "2")
        assert not e.state.fdb and not e.state.cfg.ports[pid].admin_up
        assert "INTEGER: 2" in await command("snmpget", *base, "1.3.6.1.2.1.2.2.1.8.101")
        await command("snmpset", *base, admin, "i", "1")
        created = await command("snmpset", *base,
            static + ".5.10", "i", "4", static + ".1.10", "s", "研发",
            static + ".2.10", "x", "80", static + ".4.10", "x", "80",
            static + ".3.10", "x", "40", pvid, "u", "10")
        assert "INTEGER: 4" in created  # Echoed command, not the active row status.
        assert "INTEGER: 1" in await command("snmpget", *base, static + ".5.10")
        name = await command("snmpget", "-Ox", *base, static + ".1.10")
        assert bytes.fromhex(name.split("Hex-STRING:", 1)[1].strip()) == "研发".encode()
        p = e.state.cfg.ports[pid]
        assert p.pvid == 10 and set(p.untagged) == {1, 10} and set(p.admitted) == {1, 10}
        assert e.state.cfg.ports[list(e.state.cfg.ports)[1]].forbidden == [10]
        await tick(e)
        assert any(row["vid"] == 10 for row in e.state.fdb.values())
        await command("snmpset", *base, pvid, "u", "1")
        assert set(e.state.cfg.ports[pid].untagged) == {1, 10}  # Raw PVID is ingress only.
        await command("snmpset", *base, static + ".4.10", "s", "", static + ".2.10", "x", "00",
                      static + ".3.10", "x", "80")
        assert e.state.cfg.ports[pid].untagged == [1] and e.state.cfg.ports[pid].forbidden == [10]
        assert not any(row["vid"] == 10 for row in e.state.fdb.values())
        bad_cases = [
            ("1.3.6.1.2.1.2.2.1.8.101", "i", "2", "notWritable"),
            (pvid, "i", "1", "wrongType"), (admin, "i", "3", "wrongValue"),
            (static + ".1.10", "s", "x" * 33, "wrongLength"),
            (static + ".2.10", "x", "08", "wrongValue"),
            ("1.3.6.1.2.1.2.2.1.7.999", "i", "1", "noCreation"),
            (static + ".1.20", "s", "Absent", "inconsistentName"),
            (static + ".5.1", "i", "6", "inconsistentValue"),
        ]
        for name, syntax, value, status in bad_cases:
            before, startup = e.state, e.store.load()
            with pytest.raises(AssertionError) as failure:
                await command("snmpset", *base, "1.3.6.1.2.1.2.2.1.7.102", "i", "1",
                              name, syntax, value, static + ".1.1", "s", "Not committed")
            assert status in str(failure.value) and "Failed object: ." + name in str(failure.value)
            assert e.state is before and e.store.load() == startup
        await e.execute("save-startup")
        identity, boots, saved = a.engine_id, a.boots, e.state.cfg.model_dump()
        await e.execute("reboot")
        await a.reboot()
        assert a.engine_id == identity and a.boots == boots + 1
        assert e.state.cfg.model_dump() == saved and eid in e.state.cfg.endpoints
        assert "Gauge32: 1" in await command("snmpget", *base, pvid)
        await command("snmpset", *base, static + ".5.10", "i", "6")
        assert 10 not in e.state.cfg.vlans and not e.state.cfg.ports[pid].forbidden
        await command("snmpset", *base, static + ".5.20", "i", "4", static + ".2.20", "x", "80",
                      static + ".4.20", "x", "80", pvid, "u", "20")
        await command("snmpset", *base, static + ".5.20", "i", "6")
        assert e.state.cfg.ports[pid].pvid == 1 and e.state.cfg.ports[pid].untagged == [1]
        await e.execute(*access_command(e, cid, {'polling': {'enabled': False}}))
        await a.reconcile()
        assert a.listening and a.status()["writing_ready"] and not a.status()["ready"]
        with pytest.raises(AssertionError, match="Timeout"):
            await command("snmpget", *base, admin)
        await command("snmpset", *base, admin, "i", "2")
        assert not e.state.cfg.ports[pid].admin_up
        await e.execute(*access_command(e, cid, {'writing': {'enabled': False}}))
        await a.reconcile()
        assert not a.listening
    finally:
        a.close()
