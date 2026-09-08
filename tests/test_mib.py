import csv
import time
from pathlib import Path
from pysnmp.proto import rfc1902, rfc1905
from switchlab.mib import CURRENT, Projection, oid
from conftest import endpoint, tick


async def test_manifest_and_nonidentical_indexes(engine):
    e=engine
    await e.execute("switch-edit",{"identity":{"sys_object_id":"2.999.4"}})
    await endpoint(e);await tick(e)
    m=Projection(e.state,["1.3.6"])
    manifest=Path(__file__).parents[1]/"specification/docs/mib-coverage.csv"
    for row in csv.DictReader(manifest.open()):
        assert (oid(row["base_oid"]) in m.bases)==(row["release_access"]=="read-only"),row["object"]
    assert isinstance(m.get("1.3.6.1.2.1.1.2.0")[1],rfc1902.ObjectIdentifier)
    assert str(m.get("1.3.6.1.2.1.1.2.0")[1])=="2.999.4"
    assert int(m.get("1.3.6.1.2.1.17.1.4.1.2.1")[1])==101
    assert m.get("1.3.6.1.2.1.17.7.1.4.3.1.2.1")[1].asOctets()==b"\xf0"
    assert int(m.get("1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.16")[1])==1
    assert m.get("1.3.6.1.2.1.17.7.1.2.2.1.1.1001.2.0.0.0.0.16")[1].tagSet==rfc1905.noSuchObject.tagSet


def test_exceptions_view_walk_and_numeric_order(engine):
    m=Projection(engine.state,["1.3.6.1.2.1.1","1.3.6.1.2.1.31"])
    assert m.get("1.3.6.1.2.1.1.1.99")[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert m.get("1.3.6.1.2.1.99.1.0")[1].tagSet==rfc1905.noSuchObject.tagSet
    assert m.next("1.3.6.1.2.1.1.7.0")[0][:7]==oid("1.3.6.1.2.1.31")
    assert m.next("2.999")[1].tagSet==rfc1905.endOfMibView.tagSet


async def test_timefilter_single_traversal_and_deletion(engine):
    e=engine
    e.state.boot_start-=2
    await e.execute("vlan-create",{"vid":10})
    m=Projection(e.state,["1.3.6"])
    assert int(m.get(CURRENT+(3,100,10))[1])==1010
    assert m.get(CURRENT+(3,100,1))[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert m.next(CURRENT+(3,100,10))[0]==CURRENT+(4,100,10)
    assert m.next(CURRENT+(7,100,10))[0]==oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1")
    assert m.next(CURRENT+(3,500,0))[0]==oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1")
    await e.execute("vlan-delete",{"vid":10})
    assert Projection(e.state,["1.3.6"]).get(CURRENT+(3,100,10))[1].tagSet==rfc1905.noSuchInstance.tagSet


async def test_management_wrap_and_counter_wrap(engine):
    e=engine;p=next(iter(e.state.cfg.ports))
    e.state.boot_start=time.monotonic()-(2**32+50)/100
    e.state.counters[p]["in_octets"]=2**32+12
    m=Projection(e.state,["1.3.6"])
    assert int(m.get("1.3.6.1.2.1.1.3.0")[1])<100
    assert m.get(CURRENT+(3,1,1))[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert int(m.get("1.3.6.1.2.1.2.2.1.10.101")[1])==12
    assert int(m.get("1.3.6.1.2.1.31.1.1.1.6.101")[1])==2**32+12
