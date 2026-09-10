import copy
import pytest
from pydantic import ValidationError
from switchlab.engine import Engine,CommandError
from switchlab.models import RadiusSettings,initial_configuration
from switchlab.radius import RadiusError,AccessResult,resolve_nas_identity,access_attributes,native_exchange
from test_radius_engine import configured,begin,PEER


@pytest.mark.parametrize("value,valid",[("",False),("a"*253,True),("a"*254,False),("界"*84,True),("界"*84+"a",True),("界"*84+"ab",False),("\ud800",False)])
def test_explicit_override_uses_utf8_octets(value,valid):
    if valid:assert RadiusSettings(nas_identifier=value).nas_identifier==value
    else:
        with pytest.raises(ValidationError):RadiusSettings(nas_identifier=value)


@pytest.mark.parametrize("name,override,valid",[("",None,False),("a"*253,None,True),("a"*254,None,False),("界"*84,None,True),("界"*84+"ab",None,False),("","explicit",True),("a"*254,"explicit",True)])
def test_default_name_is_preserved_and_effective_identity_is_checked(name,override,valid):
    cfg=initial_configuration(1);cfg.switch.name=name;cfg.radius.nas_identifier=override
    saved=cfg.model_dump();type(cfg).model_validate(saved)
    if valid:
        assert resolve_nas_identity(cfg).identifier==(override if override is not None else name).encode()
    else:
        with pytest.raises(RadiusError,match="nas_identifier_override_required"):resolve_nas_identity(cfg)
    assert cfg.model_dump()==saved


def test_eap_and_mab_share_captured_identity_and_no_source_advertising():
    cfg=initial_configuration(1);port=next(iter(cfg.ports.values()));cfg.switch.name="机架"
    capture=resolve_nas_identity(cfg)
    cfg.switch.name="Changed";cfg.radius.nas_identifier="other"
    fields=access_attributes(cfg.radius,port,"02:00:00:00:00:11","session",nas_identity=capture)
    assert [v for k,v in fields if k==32]==["机架".encode()] and not any(k==4 for k,v in fields)
    cfg.radius.nas_ip_address="192.0.2.44";capture=resolve_nas_identity(cfg)
    fields=access_attributes(cfg.radius,port,"02:00:00:00:00:11","session",nas_identity=capture)
    assert [v for k,v in fields if k==4]==[bytes((192,0,2,44))] and [v for k,v in fields if k==32]==[b"other"]
    assert dict(fields)[5]==port.bridge_port.to_bytes(4,"big")


@pytest.mark.asyncio
async def test_invalid_default_prevents_io_but_not_switch_save_or_existing_grant(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    session_id=engine.state.radius_sessions[(pid,capture["mac"])].id
    await engine.execute("switch-edit",{"name":""})
    assert engine.state.cfg.switch.name=="" and not engine.snapshot()["radius"]["nas_identity_ready"]
    assert engine.state.radius_sessions[(pid,capture["mac"])].id==session_id
    before=engine.state
    with pytest.raises(CommandError,match="explicit NAS identifier"):await begin(engine,pid,eid)
    assert engine.state is before


@pytest.mark.asyncio
async def test_rename_invalidates_default_capture_not_explicit_override(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute("switch-edit",{"name":"New NAS"})
    assert not (await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))}))["accepted"]
    cfg.radius.nas_identifier="fixed";engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute("switch-edit",{"name":"Other label"})
    assert (await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))}))["accepted"]
