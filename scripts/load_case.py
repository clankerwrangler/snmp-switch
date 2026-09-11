"""Measure the specified 24-port / 1,000-endpoint / 4,000-source lab."""
import asyncio
import json
import platform
import resource
import statistics
import time
from switchlab.engine import Engine
from switchlab.models import initial_configuration, Endpoint, Source
from switchlab.mib import Projection


async def main():
    cfg=initial_configuration(24);cfg.paused=True
    pids=list(cfg.ports)
    for p in cfg.ports.values():p.mode='shared';p.shared_partner=True
    for i in range(1000):
        sources=[Source(mac=f'02:10:{i//256:02x}:{i%256:02x}:00:{j:02x}') for j in range(4)]
        e=Endpoint(name=f'Host {i}',sources=sources)
        cfg.endpoints[e.id]=e;cfg.attachments[e.id]=pids[i%24]
    e=Engine(cfg)
    latencies=[]
    for delta in [1000]+[30000]*10:
        start=time.perf_counter();await e.execute('advance',{'duration_ms':delta});latencies.append((time.perf_counter()-start)*1000)
    start=time.perf_counter();m=Projection(e.state,['1.3.6']);setup_ms=(time.perf_counter()-start)*1000
    start=time.perf_counter();names=tuple(m.values);enumeration_ms=(time.perf_counter()-start)*1000
    start=time.perf_counter()
    for name in names:
        assert m.get(name) is not None
    read_ms=(time.perf_counter()-start)*1000
    print(json.dumps({'platform':platform.platform(),'python':platform.python_version(),'ports':24,'endpoints':1000,'sources':4000,
        'learned_entries':len(e.state.fdb),'observations':sum(c['in_ucast'] for c in e.state.counters.values()),
        'advance_batch_ms_median':statistics.median(latencies),'advance_batch_ms_max':max(latencies),
        'projection_setup_ms':setup_ms,'ordinary_enumeration_ms':enumeration_ms,
        'ordinary_materialization_read_ms':read_ms,'ordinary_total_ms':setup_ms+enumeration_ms+read_ms,
        'ordinary_instances_read':len(names),'max_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'note':'In-memory state-engine throughput, one equal-time batch per advance. Ordinary MIB rows enumerated and read through one captured projection; Current-VLAN cutoff rows are separate. Excludes SQLite, HTTP, UI, and network latency; not a service-level claim.'},indent=2))

asyncio.run(main())
