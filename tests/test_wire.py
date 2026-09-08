"""Real localhost UDP; independent puresnmp/x690 client and trap decoder."""
import asyncio
import socket
import pytest
from puresnmp import Client, V2C, V3
from puresnmp.exc import ErrorResponse
from puresnmp.pdu import Trap
from x690 import decode
from x690.types import ObjectIdentifier as OID, Integer
from pysnmp.hlapi.v3arch.asyncio import (SnmpEngine, UsmUserData, UdpTransportTarget, ContextData, ObjectType,
    ObjectIdentity, get_cmd, USM_AUTH_HMAC192_SHA256, USM_PRIV_CFB128_AES)
from switchlab.snmp import SnmpAdapter
from conftest import endpoint, tick


def free_port():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def client(port,credential=None):
    c=Client('127.0.0.1',credential or V2C('fixture-poll'),port=port)
    c.configure(timeout=0.3,retries=1)
    return c


async def start(e,**credential):
    await e.execute('switch-edit',{'identity':{'sys_object_id':'1.3.999.123'}})
    await e.execute('credential-save',{'label':'fixture','community':'fixture-poll',**credential})
    port=free_port()
    await e.execute('snmp-settings',{'enabled':True,'port':port})
    a=SnmpAdapter(e,e.store)
    await a.reconcile()
    assert a.listening,a.status()
    return a,port


async def test_independent_v2_get_walk_bulk_and_set(engine):
    e=engine;a,port=await start(e)
    try:
        c=client(port)
        result=await c.get(OID('1.3.6.1.2.1.1.2.0'))
        assert isinstance(result,OID) and str(result)=='1.3.999.123'
        rows=[r async for r in c.walk(OID('1.3.6.1.2.1.2.2.1.1'))]
        assert [r.value.pythonize() for r in rows]==[101,102,103,104]
        await endpoint(e);await tick(e)
        assert (await c.get(OID('1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.16'))).pythonize()==1
        bulk=await c.bulkget([OID('1.3.6.1.2.1.1.2.0')],[OID('1.3.6.1.2.1.17.1.4.1.2')],max_list_size=4)
        assert len(bulk.listing)==4
        with pytest.raises(ErrorResponse):await c.set(OID('1.3.6.1.2.1.1.5.0'),Integer(1))
    finally:a.close()


async def test_independent_view_cidr_unknown_rotation_and_gate(engine):
    e=engine;a,port=await start(e,view_id='interfaces')
    try:
        c=client(port)
        nxt=await c.getnext(OID('1.3.6.1.2.1.2.2.1.20.104'))
        assert str(nxt.oid).startswith('1.3.6.1.2.1.31.')
        with pytest.raises(Exception):await client(port,V2C('wrong')).get(OID('1.3.6.1.2.1.1.1.0'))
        cid=next(iter(e.state.cfg.credentials))
        await e.execute('credential-save',{'id':cid,'networks':['192.0.2.0/24']});await a.reconcile()
        with pytest.raises(Exception):await c.get(OID('1.3.6.1.2.1.1.1.0'))
        await e.execute('credential-save',{'id':cid,'networks':['127.0.0.0/8'],'community':'rotated-fixture'});await a.reconcile()
        with pytest.raises(Exception):await c.get(OID('1.3.6.1.2.1.1.1.0'))
        assert await client(port,V2C('rotated-fixture')).get(OID('1.3.6.1.2.1.1.1.0'))
        identity=a.engine_id;boots=a.boots
        await e.execute('switch-edit',{'identity':{'sys_object_id':None}});await a.reconcile()
        assert not a.listening and not a.send_transports
        await e.execute('switch-edit',{'identity':{'sys_object_id':'1.3.6.1.4.1.999.1'}});await a.reconcile()
        assert a.engine_id==identity and a.boots==boots
        assert str(await client(port,V2C('rotated-fixture')).get(OID('1.3.6.1.2.1.1.2.0')))=='1.3.6.1.4.1.999.1'
    finally:a.close()


async def test_independent_v3_discovery_noauth(engine):
    a,port=await start(engine,version='3',username='fixture-noauth',community=None)
    try:
        value=await client(port,V3('fixture-noauth')).get(OID('1.3.6.1.2.1.1.2.0'))
        assert str(value)=='1.3.999.123'
    finally:a.close()


@pytest.mark.parametrize('level',['authNoPriv','authPriv'])
async def test_sha256_aes_usm_and_reboot(engine,level):
    e=engine;a,port=await start(e,version='3',username='fixture-secure',security_level=level,
                              auth_key='fixture-auth-pass',priv_key='fixture-priv-pass',community=None)
    manager=SnmpEngine()
    try:
        user=UsmUserData('fixture-secure','fixture-auth-pass','fixture-priv-pass' if level=='authPriv' else None,
                        authProtocol=USM_AUTH_HMAC192_SHA256,privProtocol=USM_PRIV_CFB128_AES if level=='authPriv' else (1,3,6,1,6,3,10,1,2,1))
        target=await UdpTransportTarget.create(('127.0.0.1',port),timeout=0.5,retries=1)
        async def get():return await get_cmd(manager,user,target,ContextData(),ObjectType(ObjectIdentity('1.3.6.1.2.1.1.2.0')))
        error,status,index,result=await get()
        assert not error and not status,(error,status)
        assert str(result[0][1])=='1.3.999.123'
        boots=a.boots;engine_id=a.engine_id
        await e.execute('reboot');await a.reboot()
        assert a.boots==boots+1 and a.engine_id==engine_id
        error,status,index,result=await get()
        assert not error and not status,(error,status)
    finally:manager.close_dispatcher();a.close()


async def test_independent_notification_receiver_capture_order_and_gate(engine):
    e=engine
    queue=asyncio.Queue()
    class Receiver(asyncio.DatagramProtocol):
        def datagram_received(self,data,addr):queue.put_nowait(data)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(Receiver,local_addr=('127.0.0.1',0))
    port=transport.get_extra_info('sockname')[1]
    await e.execute('credential-save',{'label':'traps','purpose':'notification','community':'fixture-traps'})
    cid=next(iter(e.state.cfg.credentials))
    await e.execute('target-save',{'address':'127.0.0.1','port':port,'credential_id':cid})
    a,poll_port=await start(e)
    try:
        await a.drain_one()
        cold,_=decode(await asyncio.wait_for(queue.get(),1))
        assert isinstance(cold[2],Trap)
        assert str(cold[2].value.varbinds[1].value)=='1.3.6.1.6.3.1.1.5.1'
        host=await endpoint(e)
        await e.execute('detach',{'id':host})
        await a.drain_one();await a.drain_one()
        packets=[decode(await asyncio.wait_for(queue.get(),1))[0] for _ in range(2)]
        for n,packet in enumerate(packets):
            assert isinstance(packet[2],Trap)
            bindings=packet[2].value.varbinds
            assert str(bindings[0].oid)=='1.3.6.1.2.1.1.3.0'
            assert str(bindings[1].oid)=='1.3.6.1.6.3.1.1.4.1.0'
            assert str(bindings[1].value)==f'1.3.6.1.6.3.1.1.5.{4 if n==0 else 3}'
            assert bindings[2].value.pythonize()==101 and bindings[4].value.pythonize()==1
        await e.execute('attach',{'id':host,'port_id':next(iter(e.state.cfg.ports))})
        await e.execute('switch-edit',{'identity':{'sys_object_id':None}});await a.reconcile();await a.drain_one()
        assert queue.empty() and not e.state.outbox
    finally:a.close();transport.close()

