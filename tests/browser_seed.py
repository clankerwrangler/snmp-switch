import asyncio, json, os, socket, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
class NetworkForbidden(BaseException):pass
attempts=[]
def guard(event,args):
 if event=='socket.__new__' and args[1] in (socket.AF_INET,socket.AF_INET6):attempts.append(event);raise NetworkForbidden('INET forbidden')
 if event in ('socket.getaddrinfo','socket.gethostbyname','socket.gethostbyaddr'):attempts.append(event);raise NetworkForbidden('resolution forbidden')
sys.addaudithook(guard)
from switchlab.models import initial_configuration
from switchlab.engine import Engine
from switchlab.storage import Store
from test_snmp_lifetime import ApplicationExchange, request, a, v2c
async def main():
 store=Store(os.environ['SWITCHLAB_DB'],Path(os.environ['SWITCHLAB_KEY_FILE']).read_bytes())
 cfg=initial_configuration(8);cfg.paused=False
 engine=Engine(cfg,store);pid=list(cfg.ports)[-1]
 await engine.execute('switch-edit',{'identity':{'sys_object_id':'1.3.6.1.4.1.32473.1'}})
 await engine.execute('snmp-settings',{'enabled':True})
 await engine.execute('credential-save',{'label':'Synthetic history SET','community':'synthetic-community','polling':{'enabled':True},'writing':{'enabled':True,'view_id':'all'}})
 await engine.execute('port-edit',{'id':pid,'patch':{'mode':'shared','link_notifications':False}})
 x=await ApplicationExchange(engine,store,0).start()
 try:
  await engine.execute('advance',{'duration_ms':1234,'automatic':True})
  before=engine.state.event_id
  pdu=request(35001)
  v2c.apiPDU.set_varbinds(pdu,[((1,3,6,1,2,1,2,2,1,7,cfg.ports[pid].if_index),a.Integer32(2))])
  x.send(pdu);await x.settle();assert int(v2c.apiPDU.get_error_status(x.decode()))==0
  rows=[e for e in engine.state.events if e['id']>before]
  assert [e['kind'] for e in rows].count('snmp-set')==1
  assert [e['kind'] for e in rows].count('port-edit')==1
  assert [e['kind'] for e in rows].count('linkDown')==1
  assert len({e['revision'] for e in rows})==1
  assert store.events()==engine.state.events
  receipt={'port_id':pid,'rows':rows,'real_supported_ber':True,'INET_socket_attempts':len(attempts)}
 finally:await x.close()
 # Capture a real queued/canceled destination and a renamed/deleted endpoint,
 # without a UDP transport or any saved startup identity/trust.
 first=engine.state.event_id
 credential=next(iter(engine.state.cfg.credentials))
 target=await engine.execute('target-save',{'address':'2001:db8::10','port':1162,'credential_id':credential})
 await engine.execute('test-notification',{'target_id':target['id']})
 await engine.execute('target-delete',{'id':target['id']})
 endpoint=await engine.execute('endpoint-create',{'name':'Recorded <endpoint>','sources':[]})
 await engine.execute('endpoint-edit',{'id':endpoint['id'],'patch':{'name':'Renamed endpoint'}})
 await engine.execute('endpoint-delete',{'id':endpoint['id']})
 receipt['display_rows']=[e for e in engine.state.events if e['id']>first]
 # Only synthetic lab hardware returns to its fresh direct state. Startup was
 # never overwritten by temporary SNMP identity/trust or running admin changes.
 await engine.execute('port-edit',{'id':pid,'patch':{'mode':'direct','shared_partner':False}})
 await engine.execute('snmp-settings',{'enabled':False})
 await engine.execute('switch-edit',{'identity':{'sys_object_id':None}})
 for n in range(55):await engine.execute('port-edit',{'id':pid,'patch':{'alias':'Synthetic page '+str(n)}})
 store.close()
 Path(sys.argv[1]).write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'actual_ber_set':True,'operation_effect_link':len(rows),'INET_socket_attempts':len(attempts)}))
if __name__=='__main__':asyncio.run(main())
