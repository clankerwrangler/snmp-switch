import pytest
from cryptography.fernet import Fernet
from switchlab.engine import Engine
from switchlab.models import initial_configuration
from switchlab.storage import Store


@pytest.fixture
def store():
    s = Store(":memory:", Fernet.generate_key())
    yield s
    s.close()


@pytest.fixture
def engine(store):
    cfg = initial_configuration(4)
    cfg.paused = True
    return Engine(cfg, store)


async def endpoint(e, name="Host", mac="02:00:00:00:00:10", tag="untagged", port=0, active=True, sources=None, **kwargs):
    result = await e.execute("endpoint-create", {"name": name, "active": active,
        "sources": sources if sources is not None else [{"mac": mac, "tag":tag, **kwargs}]})
    if port is not None:
        await e.execute("attach", {"id":result["id"], "port_id":list(e.state.cfg.ports)[port]})
    return result["id"]


async def tick(e, ms=1000):
    return await e.execute("advance", {"duration_ms":ms})
