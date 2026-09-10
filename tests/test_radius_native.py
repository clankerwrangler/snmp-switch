import asyncio
import ipaddress
import os
import struct
import sys

import pytest

from switchlab.radius import RadiusError, native_exchange, native_observation, resolve_nas_identity
from test_radius import SECRET, PEER, request, reply
from test_radius_engine import configured


def frame(kind, payload, seq):
    return struct.pack("!4sBBHII", b"SLR1", kind, 0, 0, len(payload), seq) + payload


def packet_frame(kind, packet, req, seq, peer=PEER):
    meta = bytearray(64)
    meta[0] = 4
    meta[4:6] = struct.pack("!H",peer[1]); meta[6:8] = struct.pack("!H",30000)
    meta[8:12] = ipaddress.ip_address(peer[0]).packed
    meta[24:28] = ipaddress.ip_address("192.0.2.2").packed
    meta[40:56] = req[4:20]; meta[56:60] = struct.pack("!I",len(packet))
    return frame(kind, bytes(meta)+packet, seq)


def channel(code=2, peer_result=0, values=()):
    req=request(); response=reply(req,values,code)
    return (packet_frame(1,req,req,1) + packet_frame(2,response,req,2) +
            frame(7,struct.pack("!8I",code==2,code==3,0,0,0,0,peer_result,0),3))


@pytest.mark.parametrize("code,peer",[(2,0),(2,1),(3,2)])
def test_complete_packet_type_not_peer_or_exit_owns_decision(code,peer):
    observation=native_observation(channel(code,peer,[(25,b"private-class")]),PEER,SECRET)
    assert observation.result.code==code and observation.peer_result==peer
    assert observation.result.attributes[0]==(25,b"private-class")
    assert "private-class" not in repr(observation)


@pytest.mark.parametrize("fault",["header","partial","extra","sequence","size","unknown","wrong-peer","wrong-source","bad-secret","duplicate-rx","missing-terminal","terminal-only","terminal-disagreement"])
def test_incomplete_forged_or_uncorrelated_channel_is_not_a_result(fault):
    data=channel(); peer=PEER; secret=SECRET; source=None
    if fault=="header":data=b"FAIL"+data[4:]
    elif fault=="partial":data=data[:-1]
    elif fault=="extra":data+=b"!"
    elif fault=="sequence":data=data[:12]+struct.pack("!I",2)+data[16:]
    elif fault=="size":data=data[:8]+struct.pack("!I",8192)+data[12:]
    elif fault=="unknown":data=data[:4]+b"\xff"+data[5:]
    elif fault=="wrong-peer":peer=("192.0.2.3",PEER[1])
    elif fault=="wrong-source":source="192.0.2.9"
    elif fault=="bad-secret":secret=b"other-synthetic-secret"
    elif fault=="duplicate-rx":
        req=request(); response=reply(req)
        data=packet_frame(1,req,req,1)+packet_frame(2,response,req,2)+packet_frame(2,response,req,3)
    elif fault=="missing-terminal":data=data[:-48]
    elif fault=="terminal-only":data=frame(7,struct.pack("!8I",1,0,0,0,0,0,2,0),1)
    elif fault=="terminal-disagreement":data=data[:-32]+struct.pack("!8I",0,1,0,0,0,0,2,0)
    with pytest.raises(RadiusError):native_observation(data,peer,secret,source)


def test_synchronous_next_request_before_challenge_observation():
    first=request(); second=request()
    challenge=reply(first,[(24,b"challenge")],11)
    data=(packet_frame(1,first,first,1)+packet_frame(1,second,second,2)+
          packet_frame(2,challenge,first,3)+packet_frame(2,reply(second),second,4)+
          frame(7,struct.pack("!8I",1,0,0,0,0,0,0,0),5))
    got=native_observation(data,PEER,SECRET)
    assert got.challenges==1 and got.result.code==2


def setup_native(tmp_path,configured,body):
    from switchlab.models import RadiusServer
    cfg,pid,eid=configured
    server=RadiusServer(label="Synthetic",address=PEER[0],port=PEER[1],secret=SECRET.decode())
    profile=cfg.endpoints[eid].sources[0].supplicant
    script=tmp_path/"native-test"
    script.write_text("#!"+sys.executable+"\nimport os,sys,time,struct\nfrom pathlib import Path\n"+body)
    script.chmod(0o700)
    import hashlib,json
    script.with_name(script.name+".switchlab.json").write_text(json.dumps({"interface":"SLR1","upstream":"2.12",
        "security_fix":"aa02cfa569477f67f3915c8b9a83d1a7ca93693d",
        "managed_patch_sha256":"226721ea0081ce5b8459d1ed629ccc6a59588cfba1588a2b38d526a60faebd29",
        "binary_sha256":hashlib.sha256(script.read_bytes()).hexdigest()}))
    return cfg,server,profile,cfg.ports[pid],script


@pytest.mark.asyncio
async def test_private_files_and_diagnostic_forgery_cannot_authorize(tmp_path,configured):
    body="""
def arg(name):return sys.argv[sys.argv.index(name)+1]
for name in ('-F','-G','-c'):
 p=Path(arg(name));assert p.stat().st_mode & 0o777 == 0o600
 assert p.parent.stat().st_mode & 0o777 == 0o700
secret=Path(arg('-F')).read_bytes()
assert secret not in Path('/proc/self/cmdline').read_bytes()
assert secret not in Path('/proc/self/environ').read_bytes()
print('EAPOL_TEST_RESULT accept=1 reject=0')
os.write(int(arg('-B')),struct.pack('!4sBBHII8I',b'SLR1',7,0,0,32,1,0,0,1,0,0,0,0,0))
"""
    cfg,server,profile,port,script=setup_native(tmp_path,configured,body)
    got=await native_exchange(cfg.radius,server,profile,port,"02:00:00:00:00:11","synthetic-session",nas_identity=resolve_nas_identity(cfg),executable=str(script),temporary_parent=tmp_path)
    assert got.result is None and got.timed_out
    assert not list(tmp_path.glob("switchlab-radius-*"))


@pytest.mark.asyncio
async def test_cancel_reaps_child_and_private_files(tmp_path,configured):
    pidfile=tmp_path/"child-pid"
    body=f"Path({str(pidfile)!r}).write_text(str(os.getpid()))\ntime.sleep(120)\n"
    cfg,server,profile,port,script=setup_native(tmp_path,configured,body)
    task=asyncio.create_task(native_exchange(cfg.radius,server,profile,port,"02:00:00:00:00:11","synthetic-session",nas_identity=resolve_nas_identity(cfg),executable=str(script),temporary_parent=tmp_path))
    async with asyncio.timeout(3):
        while not pidfile.exists():await asyncio.sleep(.01)
    pid=int(pidfile.read_text());task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    assert not os.path.exists(f"/proc/{pid}")
    assert not list(tmp_path.glob("switchlab-radius-*"))


@pytest.mark.asyncio
@pytest.mark.parametrize("fault",["missing","receipt","binary","platform"])
async def test_incompatible_helper_fails_before_private_files_or_launch(tmp_path,configured,monkeypatch,fault):
    cfg,server,profile,port,script=setup_native(tmp_path,configured,"raise AssertionError('must not launch')\n")
    if fault=="missing":script.unlink()
    elif fault=="receipt":script.with_name(script.name+".switchlab.json").unlink()
    elif fault=="binary":script.write_text(script.read_text()+"# changed\n")
    else:monkeypatch.setattr(sys,"platform","win32")
    with pytest.raises(RadiusError,match="eap_"):
        await native_exchange(cfg.radius,server,profile,port,"02:00:00:00:00:11","session",nas_identity=resolve_nas_identity(cfg),executable=str(script),temporary_parent=tmp_path)
    assert not list(tmp_path.glob("switchlab-radius-*"))


def test_incremental_response_observation_cannot_authorize_without_complete_terminal():
    from switchlab.radius import _NativeDecoder
    calls=[];data=channel()
    decoder=_NativeDecoder(PEER,SECRET,on_response=lambda:calls.append('reachable'))
    for byte in data[:-48]:decoder.feed(bytes((byte,)))
    assert calls==['reachable']
    with pytest.raises(RadiusError):decoder.finish()
    bad=frame(7,struct.pack('!8I',2,0,0,0,0,0,0,0),3)
    with pytest.raises(RadiusError):decoder.feed(bad)
    with pytest.raises(RadiusError):decoder.finish()


def test_incremental_chunking_preserves_complete_result():
    from switchlab.radius import _NativeDecoder
    data=channel()
    for size in (1,7,16,511):
        decoder=_NativeDecoder(PEER,SECRET)
        for index in range(0,len(data),size):decoder.feed(data[index:index+size])
        assert decoder.finish().result.code==2


def test_incremental_eap_event_is_literal_metadata_not_a_nas_decision():
    from switchlab.radius import _NativeDecoder
    payload=bytes((1,2,0,2,7,1))+struct.pack('!H',5)+bytes.fromhex('020000000011')+bytes(2)
    decoder=_NativeDecoder(PEER,SECRET)
    encoded=frame(3,payload,1)
    for byte in encoded[:-1]:
        decoder.feed(bytes((byte,)))
        assert not decoder.eap_events
    decoder.feed(encoded[-1:])
    assert decoder.eap_events==[payload] and decoder.result is None
    decoder.feed(frame(7,struct.pack('!8I',0,0,0,0,0,0,2,0),2))
    completed=decoder.finish()
    assert completed.eap_frames==1 and completed.peer_result==2 and completed.result is None
