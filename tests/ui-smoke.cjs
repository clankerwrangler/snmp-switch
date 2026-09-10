// Run against a fresh local instance. Requires Playwright, Chromium, and a disposable
// CA/client certificate at SWITCHLAB_TEST_RADIUS_CA_FILE and matching encrypted
// key at SWITCHLAB_TEST_RADIUS_KEY_FILE (synthetic-certificate-password; configuration only).
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const browserEnv={...process.env};
  if(process.env.SWITCHLAB_BROWSER_LIBRARY_PATH)browserEnv.LD_LIBRARY_PATH=process.env.SWITCHLAB_BROWSER_LIBRARY_PATH;
  if(process.env.SWITCHLAB_BROWSER_FONTCONFIG)browserEnv.FONTCONFIG_FILE=process.env.SWITCHLAB_BROWSER_FONTCONFIG;
  const browser = await chromium.launch({headless:true,ignoreDefaultArgs:['--hide-scrollbars'],channel:process.env.SWITCHLAB_BROWSER_CHANNEL||undefined,env:browserEnv});
  try {
  const page = await browser.newPage({viewport:{width:1440,height:1100}});
  page.setDefaultTimeout(10000);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const state=()=>page.evaluate(async()=> (await fetch('/api/v1/state')).json());
  const screenshots=process.env.SWITCHLAB_TEST_SCREENSHOTS||path.join(__dirname,'../docs/screenshots');
  async function screenshot(name){if(screenshots==='0')return;fs.mkdirSync(screenshots,{recursive:true});await page.screenshot({path:path.join(screenshots,name),fullPage:true});}
  assert.ok(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE,'Supply a disposable CA certificate for the RADIUS configuration flow');
  const radiusCA=fs.readFileSync(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE,'utf8');
  assert.ok(process.env.SWITCHLAB_TEST_RADIUS_KEY_FILE,'Supply the matching disposable encrypted client key');
  const fixtureURL=process.env.SWITCHLAB_TEST_URL||'http://127.0.0.1:8765';
  const fixtureOrigin=new URL(fixtureURL).origin;
  await page.route('**/*',route=>new URL(route.request().url()).origin===fixtureOrigin?route.continue():route.abort());
  await page.goto(fixtureURL);
  assert.equal(await page.title(),'Switch Lab');
  assert.equal(await page.locator('[name=setup_token]').count(),0);
  assert.equal(await page.getByLabel('Administrator password').getAttribute('minlength'),null);
  assert.equal(await page.getByLabel('Administrator password').getAttribute('maxlength'),'1024');
  await page.getByLabel('Administrator password').fill(process.env.SWITCHLAB_TEST_PASSWORD);
  await page.getByRole('button',{name:'Create administrator'}).click();
  await page.getByRole('heading',{name:'Switch overview',exact:true}).waitFor();
  const simulation=page.locator('#simulation');
  const simulationSummary=simulation.locator('summary');
  const mutations=[];
  page.on('request',r=>{if(new URL(r.url()).pathname.startsWith('/api/v1/')&&!['GET','HEAD'].includes(r.method()))mutations.push(r);});
  const isOpen=()=>simulation.evaluate(el=>el.open);
  const openSimulation=async()=>{if(!await isOpen())await simulationSummary.click();};
  const sameSimulation=(a,b)=>{
    for(const key of ['simulation_ms','configuration_revision','paused','fdb','ports','endpoints','attachments','counters'])assert.deepEqual(a[key],b[key],key);
  };
  async function clockRefresh(){
    await simulation.evaluate(el=>el.dataset.refreshProbe='waiting');
    await page.waitForFunction(()=>!document.querySelector('#simulation').dataset.refreshProbe);
  }
  assert.equal(await isOpen(),false);
  assert.equal(await simulationSummary.textContent(),'Simulation');
  assert.equal(await page.locator('.page-heading .clock').count(),0);
  assert.equal(await page.getByRole('button',{name:'Ⅱ Pause',exact:true}).isVisible(),false);
  // Native keyboard disclosure is presentation only; background time still advances.
  const running=await state();
  await simulationSummary.focus();await page.keyboard.press('Enter');
  assert.equal(await isOpen(),true);
  await clockRefresh();
  assert.equal(await isOpen(),true);
  assert.equal(await simulationSummary.evaluate(el=>el===document.activeElement),true);
  assert.ok((await state()).simulation_ms>running.simulation_ms);
  await page.keyboard.press('Escape');
  assert.equal(await isOpen(),false);
  assert.equal(await simulationSummary.evaluate(el=>el===document.activeElement),true);
  assert.equal(mutations.length,0);
  await openSimulation();
  // Both manual controls retain the existing running-clock rejection and send nothing.
  for(const name of ['+1s','Advance…']){
    await page.getByRole('button',{name,exact:true}).click();
    await page.locator('#toast.error').filter({hasText:'Pause the clock before manual advancement.'}).waitFor();
  }
  assert.equal(mutations.length,0);assert.equal(await page.locator('dialog[open]').count(),0);
  await page.getByRole('button',{name:'Ⅱ Pause',exact:true}).click();
  await page.getByRole('button',{name:'▶ Resume',exact:true}).waitFor();
  assert.equal(await isOpen(),true);
  assert.equal(await page.locator('#simulation-toggle').evaluate(el=>el===document.activeElement),true);
  await clockRefresh();
  assert.equal(await page.locator('#simulation-toggle').evaluate(el=>el===document.activeElement),true);
  const paused=await state(),mutationCount=mutations.length;
  // Close, reopen and navigation preserve paused state and never issue a write.
  await page.getByRole('heading',{name:'Switch overview',exact:true}).click();
  assert.equal(await isOpen(),false);
  for(const nav of ['endpoints','vlans','fdb','interfaces','events','snmp','radius','settings','overview']){
    await openSimulation();await page.locator(`nav button[data-id="${nav}"]`).click();
    assert.equal(await isOpen(),false);
    assert.equal(await simulationSummary.textContent(),'Simulation');
    assert.equal(await page.locator('.page-heading .clock').count(),0);
  }
  for(const [destination,heading,present,absent] of [
    ['snmp','SNMP','SNMP service','Certificates'],['radius','RADIUS','Certificates','SNMP service'],['settings','Settings','Switch settings','SNMP service']]){
    const nav=page.locator(`nav button[data-id=${destination}]`);await nav.focus();await page.keyboard.press('Enter');
    await page.getByRole('heading',{name:heading,exact:true,level:1}).waitFor();
    assert.equal(await nav.getAttribute('aria-current'),'page');
    await page.getByRole('heading',{name:present,exact:true}).waitFor();
    assert.equal(await page.getByRole('heading',{name:absent,exact:true}).count(),0);
  }
  await page.getByRole('button',{name:'Configure SNMP →',exact:true}).click();
  assert.equal(await page.locator('nav button[data-id=snmp]').getAttribute('aria-current'),'page');
  await page.locator('nav button[data-id=overview]').click();
  await openSimulation();await clockRefresh();
  sameSimulation(await state(),paused);assert.equal(mutations.length,mutationCount);
  await simulationSummary.click();
  // Classic scrollbar allocation must not move the shared frame between routes.
  // Keep native scrollbars visible: headless Chromium otherwise masks this case.
  const frameMeasurements=[];
  for(const viewport of [{width:1440,height:1100},{width:1920,height:1080},{width:390,height:844}]){
    await page.setViewportSize(viewport);
    const frames=[];
    for(const destination of ['overview','endpoints','vlans','fdb','interfaces','events','snmp','radius','settings','overview']){
      await page.locator(`nav button[data-id="${destination}"]`).click();
      await page.evaluate(()=>window.scrollTo(0,0));
      await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
      if(destination==='radius'){
        assert.equal(await page.locator('#radius-config.settings-grid > .card').count(),5);
        const layout=await page.locator('#radius-config').evaluate(el=>{
          const box=e=>{const r=e.getBoundingClientRect();return {x:r.x,width:r.width};};
          return {container:box(el),access:box(el.querySelector('#radius-access')),templates:box(el.querySelector('#radius-templates')),certificates:box(el.querySelector('#radius-materials'))};
        });
        assert.ok(Math.abs(layout.certificates.width-layout.container.width)<1);
        if(viewport.width>680){assert.ok(layout.access.width<layout.container.width);assert.ok(layout.templates.x>layout.access.x);}
        else{assert.ok(Math.abs(layout.access.x-layout.templates.x)<1);assert.ok(Math.abs(layout.access.width-layout.container.width)<1);}
      }
      frames.push(await page.evaluate(destination=>{
        const box=selector=>{const r=document.querySelector(selector).getBoundingClientRect();return {x:r.x,width:r.width};};
        return {destination,overflow:document.documentElement.scrollHeight>innerHeight,
          horizontal:document.documentElement.scrollWidth>innerWidth,
          main:box('main'),header:box('header'),sidebar:box('.sidebar'),page:box('.page')};
      },destination));
    }
    if(viewport.width>680)assert.ok(frames.some(f=>f.overflow)&&frames.some(f=>!f.overflow),'Exercise both scrolling and short pages');
    for(const frame of frames){
      assert.equal(frame.horizontal,false,'Shared frame must not create horizontal overflow');
      for(const selector of ['main','header','sidebar','page'])for(const dimension of ['x','width'])
        assert.ok(Math.abs(frame[selector][dimension]-frames[0][selector][dimension])<0.01,
          `${viewport.width}px ${frame.destination}: ${selector}.${dimension} must remain stable`);
    }
    frameMeasurements.push({viewport,frames});
  }
  await page.setViewportSize({width:1440,height:1100});
  await page.locator('nav button[data-id="overview"]').click();
  console.log('Shared frame passed: stable x/width across long and short routes at desktop, wide, and mobile widths; native scrolling retained.');
  await screenshot('overview-empty.png');
  await page.locator('nav button[data-id=endpoints]').click();
  await page.getByRole('button',{name:'+ New endpoint',exact:true}).click();
  await page.getByLabel('Display name').fill('Lab workstation');
  await page.getByLabel('MAC address',{exact:true}).fill('02:11:22:33:44:55');
  await page.getByRole('button',{name:'Create endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await page.getByRole('button',{name:'Attach →',exact:true}).click();
  await page.getByRole('button',{name:'Connect endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await openSimulation();
  const beforeSecond=await state();
  const secondResponse=page.waitForResponse(r=>r.url().endsWith('/api/v1/clock/advance')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'+1s',exact:true}).click();
  assert.equal((await secondResponse).status(),200);
  assert.equal((await state()).simulation_ms,beforeSecond.simulation_ms+1000);
  // The same custom-duration dialog retains bounds, captured revision and error feedback.
  await page.getByRole('button',{name:'Advance…',exact:true}).click();
  assert.equal(await isOpen(),false);
  const durationInput=page.getByLabel('Duration (milliseconds)',{exact:true});
  assert.equal(await durationInput.getAttribute('min'),'1');assert.equal(await durationInput.getAttribute('max'),'86400000');
  for(const invalid of ['0','86400001']){
    await durationInput.fill(invalid);assert.equal(await durationInput.evaluate(el=>el.checkValidity()),false);
  }
  await durationInput.fill('2500');
  const customBefore=await state();
  await page.getByRole('button',{name:'Advance time',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  assert.equal((await state()).simulation_ms,customBefore.simulation_ms+2500);
  await openSimulation();await page.getByRole('button',{name:'Advance…',exact:true}).click();
  const authClock=await (await page.request.get(new URL('/api/v1/auth/status',fixtureURL).href)).json();
  const staleClock=await state();
  const bumpedClock=await page.request.post(new URL('/api/v1/clock/pause',fixtureURL).href,{headers:{'X-CSRF-Token':authClock.csrf_token},data:{expected_configuration_revision:staleClock.configuration_revision}});
  assert.equal(bumpedClock.status(),200);
  const conflictClock=page.waitForResponse(r=>r.url().endsWith('/api/v1/clock/advance')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Advance time',exact:true}).click();
  assert.equal((await conflictClock).status(),409);
  await page.locator('dialog .form-error').filter({hasText:'Configuration changed while editing; reload and retry'}).waitFor();
  assert.equal((await state()).simulation_ms,staleClock.simulation_ms);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await openSimulation();
  await page.getByRole('button',{name:'▶ Resume',exact:true}).click();
  await page.getByRole('button',{name:'Ⅱ Pause',exact:true}).waitFor();
  const resumed=await state();await clockRefresh();assert.ok((await state()).simulation_ms>resumed.simulation_ms);
  await page.getByRole('button',{name:'Ⅱ Pause',exact:true}).click();
  await page.getByRole('button',{name:'▶ Resume',exact:true}).waitFor();
  console.log('Simulation disclosure passed: native keyboard/focus/refresh, presentation-only navigation, running/manual guards, pause/resume, +1s, custom duration and real stale-revision rejection.');
  await page.locator('nav button[data-id=fdb]').click();
  await page.getByText('02:11:22:33:44:55',{exact:true}).waitFor();
  await screenshot('learned-addresses.png');
  await page.locator('nav button[data-id=overview]').click();
  await page.waitForFunction(()=>!document.querySelector('#toast').classList.contains('show'));
  await screenshot('overview.png');
  await page.getByRole('button',{name:'Configure port',exact:true}).click();
  await page.getByLabel('Alias',{exact:true}).fill('Edited through the browser');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  // Port-view detachment changes only the attachment, using the existing revision-checked DELETE.
  const attachedBefore=await state();
  const endpoint=Object.values(attachedBefore.endpoints)[0];
  const firstPort=attachedBefore.attachments[endpoint.id];
  const sharedPort=Object.keys(attachedBefore.ports).find(id=>id!==firstPort);
  const detail=page.locator('.port-detail');
  const disconnect=e=>detail.getByRole('button',{name:`Disconnect ${e.name} (${e.id})`,exact:true});
  const deleteURL=new URL(`/api/v1/endpoints/${endpoint.id}/attachment`,fixtureURL).href;
  async function attachFromPort(eid,pid){
    await page.locator(`button[data-action="select-port"][data-id="${pid}"]`).click();
    await detail.getByRole('button',{name:'+ Attach endpoint',exact:true}).click();
    await page.locator('dialog select[name=endpoint]').selectOption(eid);
    assert.equal(await page.locator('dialog select[name=port]').inputValue(),pid);
    await page.getByRole('button',{name:'Connect endpoint',exact:true}).click();
    await page.locator('dialog').waitFor({state:'hidden'});
    await disconnect((await state()).endpoints[eid]).waitFor();
  }
  let detachResponse=page.waitForResponse(r=>r.url()===deleteURL&&r.request().method()==='DELETE');
  await disconnect(endpoint).click();
  assert.equal((await detachResponse).status(),200);
  await detail.getByText('No endpoint attached.',{exact:true}).waitFor();
  let detached=await state();
  assert.deepEqual(detached.endpoints,attachedBefore.endpoints);
  assert.equal(detached.attachments[endpoint.id],undefined);
  assert.deepEqual(detached.ports[firstPort].attachments,[]);
  assert.equal(detached.ports[firstPort].operational_up,false);
  assert.equal(await page.locator('.port.selected').getAttribute('data-id'),firstPort);
  assert.equal(await page.locator('dialog[open]').count(),0);
  await attachFromPort(endpoint.id,firstPort);
  assert.equal((await state()).attachments[endpoint.id],firstPort);
  // The existing endpoint-library disconnect remains available.
  await page.locator('nav button[data-id=endpoints]').click();
  await page.locator(`button[data-action="attachment"][data-id="${endpoint.id}"]`).click();
  await page.getByRole('button',{name:'Disconnect endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  assert.equal((await state()).attachments[endpoint.id],undefined);
  await page.locator('nav button[data-id=overview]').click();
  await page.locator(`button[data-action="select-port"][data-id="${sharedPort}"]`).click();
  await detail.getByRole('button',{name:'Configure port',exact:true}).click();
  await page.locator('dialog select[name=mode]').selectOption('shared');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await attachFromPort(endpoint.id,sharedPort);
  await page.locator('nav button[data-id=endpoints]').click();
  await page.getByRole('button',{name:'+ New endpoint',exact:true}).click();
  const literalEndpoint='Lab <b> & "two"';
  await page.getByLabel('Display name').fill(literalEndpoint);
  await page.getByLabel('MAC address',{exact:true}).fill('02:11:22:33:44:66');
  await page.locator('textarea[name=metadata]').fill('{"fixture":"preserve sources"}');
  await page.getByRole('button',{name:'Create endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  const second=Object.values((await state()).endpoints).find(e=>e.name===literalEndpoint);
  await page.locator('nav button[data-id=overview]').click();
  await attachFromPort(second.id,sharedPort);
  const sharedBefore=await state();
  assert.equal(await detail.locator('.attached').count(),2);
  assert.equal(await detail.locator('.attached b').filter({hasText:literalEndpoint}).textContent(),literalEndpoint);
  assert.equal(await detail.locator('.attached b b').count(),0);
  assert.equal(await disconnect(second).textContent(),'Disconnect');
  // Keep one DELETE pending across the normal refresh timer and another render.
  let releaseDetach,markPending,deleteCount=0;
  const held=new Promise(resolve=>releaseDetach=resolve);
  const pending=new Promise(resolve=>markPending=resolve);
  const holdDelete=async route=>{
    if(route.request().method()!=='DELETE')return route.continue();
    deleteCount++;markPending();await held;await route.continue();
  };
  await page.route(deleteURL,holdDelete);
  try{
    detachResponse=page.waitForResponse(r=>r.url()===deleteURL&&r.request().method()==='DELETE');
    await disconnect(endpoint).click();await pending;
    assert.ok(await disconnect(endpoint).isDisabled());
    const periodic=page.waitForResponse(r=>r.url().endsWith('/api/v1/events?limit=2000'));
    await periodic;
    await page.locator(`button[data-action="select-port"][data-id="${sharedPort}"]`).click();
    assert.ok(await disconnect(endpoint).isDisabled());
    await disconnect(endpoint).evaluate(el=>el.click());
    assert.equal(deleteCount,1);
    assert.deepEqual((await state()).attachments,sharedBefore.attachments);
    releaseDetach();assert.equal((await detachResponse).status(),200);
  }finally{releaseDetach();await page.unroute(deleteURL,holdDelete);}
  await disconnect(endpoint).waitFor({state:'hidden'});
  detached=await state();
  assert.deepEqual(detached.endpoints,sharedBefore.endpoints);
  assert.equal(detached.attachments[endpoint.id],undefined);
  assert.equal(detached.attachments[second.id],sharedPort);
  assert.deepEqual(detached.ports[sharedPort].attachments,[second.id]);
  assert.equal(detached.ports[sharedPort].operational_up,true);
  assert.equal(await page.locator('.port.selected').getAttribute('data-id'),sharedPort);
  await disconnect(second).waitFor();
  await attachFromPort(endpoint.id,sharedPort);
  // Advance the real server revision after the UI captures it; do not mock the 409.
  let conflictSnapshot;
  const staleDelete=async route=>{
    if(route.request().method()!=='DELETE')return route.continue();
    const auth=await (await page.request.get(new URL('/api/v1/auth/status',fixtureURL).href)).json();
    const current=await state();
    const changed=await page.request.post(new URL('/api/v1/clock/pause',fixtureURL).href,{headers:{'X-CSRF-Token':auth.csrf_token},data:{expected_configuration_revision:current.configuration_revision}});
    assert.equal(changed.status(),200);
    conflictSnapshot=await state();
    await route.continue();
  };
  await page.route(deleteURL,staleDelete);
  try{
    detachResponse=page.waitForResponse(r=>r.url()===deleteURL&&r.request().method()==='DELETE');
    await disconnect(endpoint).click();assert.equal((await detachResponse).status(),409);
    await page.locator('#toast.show.error').filter({hasText:'Configuration changed while editing; reload and retry'}).waitFor();
    const rejected=await state();
    assert.deepEqual(rejected.endpoints,conflictSnapshot.endpoints);
    assert.deepEqual(rejected.attachments,conflictSnapshot.attachments);
    assert.equal(rejected.configuration_revision,conflictSnapshot.configuration_revision);
    assert.equal(await disconnect(endpoint).isEnabled(),true);
    assert.equal(await page.locator('dialog[open]').count(),0);
    assert.equal(await page.locator('.port.selected').getAttribute('data-id'),sharedPort);
  }finally{await page.unroute(deleteURL,staleDelete);}
  // A normal refresh allows retry with the new revision, without removing the other endpoint.
  await page.reload();
  await page.locator(`button[data-action="select-port"][data-id="${sharedPort}"]`).click();
  detachResponse=page.waitForResponse(r=>r.url()===deleteURL&&r.request().method()==='DELETE');
  await disconnect(endpoint).click();assert.equal((await detachResponse).status(),200);
  await disconnect(endpoint).waitFor({state:'hidden'});
  assert.equal((await state()).attachments[second.id],sharedPort);
  await attachFromPort(endpoint.id,sharedPort);
  assert.deepEqual((await state()).endpoints,sharedBefore.endpoints);
  await page.setViewportSize({width:390,height:844});
  await disconnect(endpoint).waitFor();await disconnect(second).waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  await page.setViewportSize({width:1440,height:1100});
  console.log('Port-view disconnect passed: direct empty/reconnect, endpoint-view action retained, shared isolation, literal labels, pending duplicate guard across refresh, real stale-revision rejection/retry, preserved sources/metadata and selected port, mobile layout.');
  await page.locator('nav button[data-id=snmp]').click();
  await page.locator('nav button[data-id=settings]').click();
  const beforeGeneral=await state();
  await page.getByRole('heading',{name:'Switch settings',exact:true}).waitFor();
  await page.locator('button[data-action=switch-settings]').click();
  assert.equal(await page.locator('dialog [name=oid]').count(),0);
  await page.getByLabel('Location',{exact:true}).fill('Synthetic settings location');
  const generalWrite=page.waitForRequest(r=>r.url().endsWith('/api/v1/switch')&&r.method()==='PATCH');
  await page.getByRole('button',{name:'Apply',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});
  const generalPayload=(await generalWrite).postDataJSON();
  assert.equal('identity' in generalPayload,false);assert.equal('queue_limit' in generalPayload,false);
  assert.deepEqual((await state()).switch.identity,beforeGeneral.switch.identity);
  assert.deepEqual((await state()).radius,beforeGeneral.radius);
  await page.locator('nav button[data-id=snmp]').click();await page.locator('button[data-action=identity]').click();
  assert.equal(await page.locator('dialog [name=name]').count(),0);assert.equal(await page.locator('dialog [name=aging_seconds]').count(),0);
  const snmpIdentityWrite=page.waitForRequest(r=>r.url().endsWith('/api/v1/switch')&&r.method()==='PATCH');
  await page.getByRole('button',{name:'Apply',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});
  const identityPayload=(await snmpIdentityWrite).postDataJSON();assert.equal('name' in identityPayload,false);assert.equal('aging_seconds' in identityPayload,false);
  assert.equal((await state()).switch.location,'Synthetic settings location');
  const initialHost=(await state()).snmp.host;
  await page.getByRole('button',{name:'Configure',exact:true}).click();
  assert.equal(await page.getByRole('checkbox',{name:'Enable SNMP',exact:true}).count(),1);
  assert.equal(await page.getByRole('checkbox',{name:'Enable SNMP',exact:true}).isChecked(),false);
  assert.equal(await page.getByRole('checkbox',{name:'Explicitly enable SNMP',exact:true}).count(),0);
  await page.getByLabel('Listen IP address',{exact:true}).fill('127.0.0.2');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await page.reload();
  await page.locator('nav button[data-id=snmp]').click();
  await page.getByRole('button',{name:'Configure',exact:true}).click();
  assert.equal(await page.getByLabel('Listen IP address',{exact:true}).inputValue(),'127.0.0.2');
  assert.equal(await page.getByRole('checkbox',{name:'Enable SNMP',exact:true}).isChecked(),false);
  assert.equal((await state()).switch.identity.sys_object_id,null);
  await page.getByLabel('Listen IP address',{exact:true}).fill(initialHost);
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  console.log('Listener form passed: exact Enable SNMP label, custom address roundtrip after reload, SNMP remains disabled.');
  assert.equal(await page.title(),'Switch Lab');
  const service=page.locator('section.card').filter({has:page.getByRole('heading',{name:'SNMP service',exact:true})});
  assert.equal(await service.getByText('Listener status',{exact:true}).count(),1);
  assert.equal(await service.getByText(/Polling state|SET state|Read state|Write state/).count(),0);
  assert.equal(await page.locator('button[data-action=polling],button[data-action=writing]').count(),0);
  for(const title of ['SNMPv2c communities','SNMPv3 users','SNMPv3 groups'])await page.getByRole('heading',{name:title,exact:true}).waitFor();
  const credentialRow=label=>page.locator('.setting-row').filter({has:page.locator('button[data-action=credential]')}).filter({has:page.locator('b').filter({hasText:label})});
  const editCredential=label=>credentialRow(label).getByRole('button',{name:'Edit',exact:true}).click();
  const access=()=>page.locator('dialog select[name=access_mode]');
  const readView=()=>page.locator('dialog select[name=polling_view]');
  const writeView=()=>page.locator('dialog select[name=writing_view]');
  const readNets=()=>page.getByLabel('Read source networks (optional)',{exact:true});
  const writeNets=()=>page.getByLabel('Write source networks (optional)',{exact:true});
  async function saveForm(path){
    const pending=page.waitForResponse(r=>r.url().includes('/api/v1/'+path)&&['POST','PUT'].includes(r.request().method()));
    await page.getByRole('button',{name:'Apply',exact:true}).click();
    const response=await pending;assert.equal(response.status(),200,await response.text());
    const payload=response.request().postDataJSON(),body=await response.json();
    await page.locator('dialog').waitFor({state:'hidden'});return {payload,body};
  }
  async function saveCredential(version){
    const {payload}=await saveForm('snmp/credentials');
    assert.equal(payload.version,version);
    for(const key of version==='2c'?['username','security_level','auth_key','priv_key']:['community','polling','writing'])assert.equal(key in payload,false);
    const credential=Object.values((await state()).credentials).find(c=>c.label===payload.label);
    for(const key of ['community','auth_key','priv_key'])assert.equal(key in credential,false);
    return {payload,credential};
  }
  async function failure(path,status,text){
    const pending=page.waitForResponse(r=>r.url().includes('/api/v1/'+path)&&['POST','PUT','DELETE'].includes(r.request().method()));
    await page.getByRole('button',{name:'Apply',exact:true}).click();
    assert.equal((await pending).status(),status);
    await page.locator('.form-error').filter({hasText:text}).waitFor();
  }
  await page.getByRole('button',{name:'+ Community',exact:true}).click();
  await page.getByLabel('Label',{exact:true}).fill('Browser polling');
  await page.getByLabel('Community',{exact:true}).fill('browser-community');
  assert.equal(await access().inputValue(),'none');
  assert.equal(await readView().isVisible(),false);assert.equal(await writeView().isVisible(),false);
  let result=await saveCredential('2c');
  assert.equal('polling' in result.payload,false);assert.equal('writing' in result.payload,false);
  assert.deepEqual(result.credential.polling,{enabled:false,view_id:'all',networks:[]});
  assert.deepEqual(result.credential.writing,{enabled:false,view_id:null,networks:[]});
  await editCredential('Browser polling');
  await access().selectOption('read');await readNets().fill('127.0.0.0/8, ::1/128');
  await access().selectOption('write');assert.equal(await readView().isVisible(),false);
  assert.equal(await writeView().inputValue(),'');
  await access().selectOption('read');assert.equal(await readNets().inputValue(),'127.0.0.0/8, ::1/128');
  result=await saveCredential('2c');assert.equal('community' in result.payload,false);
  assert.deepEqual(result.credential.polling.networks,['127.0.0.0/8','::1/128']);
  await editCredential('Browser polling');
  assert.equal(await page.getByLabel('Community',{exact:true}).inputValue(),'');
  await readNets().fill('192.0.2.0/24');await access().selectOption('none');
  result=await saveCredential('2c');assert.deepEqual(result.payload.polling,{enabled:false});
  assert.deepEqual(result.credential.polling.networks,['127.0.0.0/8','::1/128']);
  await editCredential('Browser polling');await access().selectOption('read-write');
  let beforeInvalid=await state();
  await failure('snmp/credentials',422,'Select an existing write view');
  assert.deepEqual((await state()).credentials,beforeInvalid.credentials);
  await writeView().selectOption('interfaces');await writeNets().fill('192.0.2.0/24');
  result=await saveCredential('2c');assert.ok(result.credential.polling.enabled&&result.credential.writing.enabled);
  await editCredential('Browser polling');await access().selectOption('write');
  result=await saveCredential('2c');assert.deepEqual(result.payload.polling,{enabled:false});assert.equal('writing' in result.payload,false);
  await editCredential('Browser polling');await access().selectOption('read');await readNets().fill('');
  result=await saveCredential('2c');assert.deepEqual(result.credential.polling.networks,[]);assert.equal(result.credential.writing.enabled,false);
  await editCredential('Browser polling');
  await page.getByLabel('Community',{exact:true}).fill('discarded-unsaved-community');
  await page.getByLabel('SNMP version').selectOption('3');
  assert.equal(await page.locator('[name=community]').count(),0);
  assert.equal(await page.getByLabel('Security level').inputValue(),'authPriv');
  assert.equal(await page.locator('dialog select[name=group_choice]').inputValue(),'');
  assert.equal(await access().count(),0);
  await page.getByLabel('Username',{exact:true}).fill('browser-v3');
  await page.getByLabel('Authentication passphrase (SHA-256)',{exact:true}).fill('browser-auth-pass');
  await page.getByLabel('Privacy passphrase (AES-128)',{exact:true}).fill('browser-priv-pass');
  await page.locator('dialog select[name=group_choice]').selectOption('keep');
  result=await saveCredential('3');assert.equal(result.payload.access_transfer,'keep');
  const transferredGroup=result.credential.group_id;
  assert.ok((await state()).groups[transferredGroup].polling.enabled);
  await editCredential('Browser polling');
  assert.equal(await page.getByLabel('Authentication passphrase (SHA-256)',{exact:true}).inputValue(),'');
  result=await saveCredential('3');assert.equal('auth_key' in result.payload,false);assert.equal('group_id' in result.payload,false);
  await editCredential('Browser polling');await page.getByLabel('Authentication passphrase (SHA-256)',{exact:true}).fill('discarded-unsaved-auth');
  await page.getByLabel('SNMP version').selectOption('2c');
  assert.equal(await page.locator('[name=username],[name=security_level],[name=auth_key],[name=priv_key]').count(),0);
  assert.equal(await page.locator('dialog select[name=access_transfer]').inputValue(),'');
  await page.getByText('Access can become usable even if the old user did not meet the group minimum',{exact:false}).waitFor();
  await page.locator('dialog select[name=access_transfer]').selectOption('keep');
  await page.getByLabel('Community',{exact:true}).fill('browser-replacement');
  result=await saveCredential('2c');assert.equal(result.payload.access_transfer,'keep');assert.ok(result.credential.polling.enabled);
  assert.ok((await state()).groups[transferredGroup]);
  // Trap forms reuse credentials or create them atomically without incoming-access fields.
  const beforeTraps=await state();
  const sharedId=Object.values(beforeTraps.credentials).find(c=>c.label==='Browser polling').id;
  const noPollingFields=async()=>assert.equal(await page.locator('dialog [name=networks],dialog [name=view_id],dialog [name=purpose],dialog [name=polling],dialog [name=writing]').count(),0);
  await page.getByRole('button',{name:'+ Destination',exact:true}).click();
  await noPollingFields();
  await page.locator('dialog select[name=credential_mode]').selectOption('new');
  await page.getByLabel('Label',{exact:true}).fill('Canceled credential');
  await page.getByLabel('Community',{exact:true}).fill('canceled-secret');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.deepEqual((await state()).credentials,beforeTraps.credentials);
  assert.deepEqual((await state()).targets,beforeTraps.targets);
  await page.getByRole('button',{name:'+ Destination',exact:true}).click();
  await page.locator('dialog select[name=version]').selectOption('3');
  assert.equal(await page.locator('dialog select[name=credential_mode]').inputValue(),'new');
  await noPollingFields();
  assert.equal(await page.locator('[name=community]').count(),0);
  await page.getByLabel('Label',{exact:true}).fill('Inline browser v3');
  await page.getByLabel('Username',{exact:true}).fill('inline-browser-v3');
  await page.locator('dialog select[name=security_level]').selectOption('authPriv');
  await page.getByLabel('Privacy passphrase (AES-128)',{exact:true}).fill('discarded-inline-privacy');
  await page.locator('dialog select[name=security_level]').selectOption('authNoPriv');
  assert.equal(await page.locator('[name=priv_key]').count(),0);
  await page.locator('dialog select[name=security_level]').selectOption('authPriv');
  assert.equal(await page.getByLabel('Privacy passphrase (AES-128)',{exact:true}).inputValue(),'');
  await page.getByLabel('Authentication passphrase (SHA-256)',{exact:true}).fill('inline-browser-auth');
  await page.getByLabel('Privacy passphrase (AES-128)',{exact:true}).fill('inline-browser-priv');
  await page.getByLabel('Destination IP address',{exact:true}).fill('invalid-address');
  let response=page.waitForResponse(r=>r.url().endsWith('/api/v1/notifications/targets')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  assert.equal((await response).status(),422);
  await page.locator('.form-error').filter({hasText:'IP'}).waitFor();
  assert.deepEqual((await state()).credentials,beforeTraps.credentials);
  assert.deepEqual((await state()).targets,beforeTraps.targets);
  await page.getByLabel('Destination IP address',{exact:true}).fill('127.0.0.1');
  response=page.waitForResponse(r=>r.url().endsWith('/api/v1/notifications/targets')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  const createdResponse=await response;assert.equal(createdResponse.status(),200);
  const created=await createdResponse.json();
  const inlinePayload=createdResponse.request().postDataJSON();
  assert.equal('credential_id' in inlinePayload,false);
  assert.deepEqual(Object.keys(inlinePayload.new_credential).sort(),['auth_key','label','priv_key','security_level','username','version']);
  await page.locator('dialog').waitFor({state:'hidden'});
  let snapshot=await state();
  assert.equal(snapshot.targets[created.id].credential_id,created.credential_id);
  assert.equal(snapshot.credentials[created.credential_id].group_id,null);
  assert.equal('polling' in snapshot.credentials[created.credential_id],false);assert.equal('writing' in snapshot.credentials[created.credential_id],false);
  for(const key of ['community','auth_key','priv_key'])assert.equal(key in snapshot.credentials[created.credential_id],false);
  const targetRow=()=>page.locator('.setting-row').filter({has:page.locator('b',{hasText:'127.0.0.1:162'})});
  await targetRow().getByRole('button',{name:'Edit',exact:true}).click();
  await noPollingFields();
  assert.deepEqual(await page.locator('dialog select[name=credential_id]').locator('option').evaluateAll(o=>o.map(x=>x.value)),[created.credential_id]);
  assert.equal(await page.locator('[name=auth_key],[name=priv_key],[name=community]').count(),0);
  await page.locator('dialog select[name=version]').selectOption('2c');
  assert.deepEqual(await page.locator('dialog select[name=credential_id]').locator('option').evaluateAll(o=>o.map(x=>x.value)),[sharedId]);
  response=page.waitForResponse(r=>r.url().endsWith('/api/v1/notifications/targets/'+created.id)&&r.request().method()==='PUT');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  const selected=await response;assert.equal(selected.status(),200);
  assert.equal('new_credential' in selected.request().postDataJSON(),false);
  assert.equal(selected.request().postDataJSON().credential_id,sharedId);
  await page.locator('dialog').waitFor({state:'hidden'});
  snapshot=await state();assert.deepEqual(snapshot.credentials[sharedId].polling,beforeTraps.credentials[sharedId].polling);
  assert.ok(snapshot.credentials[created.credential_id]);
  await credentialRow('Browser polling').getByRole('button',{name:'Edit',exact:true}).click();
  await page.getByText('Trap destinations: 127.0.0.1:162.',{exact:false}).waitFor();
  assert.equal(await page.getByLabel('Community',{exact:true}).inputValue(),'');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await targetRow().getByRole('button',{name:'×',exact:true}).click();
  await page.getByRole('button',{name:'Delete record',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  snapshot=await state();assert.equal(Object.keys(snapshot.targets).length,0);assert.equal(Object.keys(snapshot.credentials).length,2);
  console.log('Shared trap browser checks passed: inline create/cancel/failure atomicity, version filtering, secret-free selection, polling separation and retained credentials.');
  const initialViews=(await state()).views;
  assert.deepEqual(initialViews.all,{id:'all',name:'iso',includes:['1']});
  assert.deepEqual(initialViews.internet,{id:'internet',name:'internet',includes:['1.3.6.1']});
  assert.deepEqual(initialViews.interfaces.includes,['1.3.6.1.2.1.1','1.3.6.1.2.1.2','1.3.6.1.2.1.31']);
  assert.equal(await page.locator('button[data-action=view][data-id=all]').locator('..').locator('..').locator('b').textContent(),'iso');
  // Inactive restrictions survive missing views, with literal labels and no injected markup.
  await editCredential('Browser polling');await access().selectOption('none');await saveCredential('2c');
  await page.locator(`button[data-action=group][data-id="${transferredGroup}"]`).click();
  await access().selectOption('none');await saveForm('snmp/groups');
  for(const view of Object.values((await state()).views)){
    await page.locator(`button[data-action=delete-view][data-id="${view.id}"]`).click();
    await page.getByRole('button',{name:'Delete record',exact:true}).click();await page.locator('dialog').waitFor({state:'hidden'});
  }
  assert.deepEqual((await state()).views,{});
  const literalLabel='Browser <span data-fixture="access-label">literal</span> & view';
  await page.getByRole('button',{name:'+ Destination',exact:true}).click();
  await page.locator('dialog select[name=credential_mode]').selectOption('new');
  await page.getByLabel('Label',{exact:true}).fill(literalLabel);await page.getByLabel('Community',{exact:true}).fill('browser-no-view');
  const noView=(await saveForm('notifications/targets')).body;
  const retainedTarget=(await state()).targets[noView.id];
  const openLiteral=async()=>{
    await editCredential(literalLabel);
    assert.equal(await page.locator('dialog h2').textContent(),'Edit credential');
    assert.equal(await page.getByLabel('Label',{exact:true}).inputValue(),literalLabel);
    assert.equal(await page.locator('[data-fixture="access-label"]').count(),0);
  };
  await openLiteral();await access().selectOption('read');
  assert.equal(await readView().inputValue(),'all');
  assert.equal(await readView().locator('option:checked').textContent(),'Missing view · all');
  beforeInvalid=await state();await failure('snmp/credentials',422,'Unknown read view');
  assert.deepEqual((await state()).credentials,beforeInvalid.credentials);assert.deepEqual((await state()).targets,beforeInvalid.targets);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await page.getByRole('button',{name:'+ View',exact:true}).click();
  await page.getByLabel('Name',{exact:true}).fill('Invalid prefix');
  for(const prefix of ['3','1.40','1..3']){
    beforeInvalid=await state();
    await page.locator('dialog input[name=includes]').fill(prefix);
    await failure('snmp/views',422,'OID');
    snapshot=await state();assert.deepEqual(snapshot.views,beforeInvalid.views);assert.equal(snapshot.configuration_revision,beforeInvalid.configuration_revision);
  }
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  async function addView(name){
    await page.getByRole('button',{name:'+ View',exact:true}).click();
    assert.equal(await page.locator('dialog input[name=includes]').inputValue(),'1');
    await page.getByLabel('Name',{exact:true}).fill(name);
    const id=(await saveForm('snmp/views')).body.id;
    assert.deepEqual((await state()).views[id].includes,['1']);
    return id;
  }
  const readViewId=await addView('Browser read'),writeViewId=await addView('Browser write');
  for(const prefix of ['1.3.6.1','1']){
    await page.locator(`button[data-action=view][data-id="${readViewId}"]`).click();
    await page.locator('dialog input[name=includes]').fill(prefix);
    await saveForm('snmp/views');assert.deepEqual((await state()).views[readViewId].includes,[prefix]);
  }
  console.log('Root-prefix view checks passed: iso/internet defaults, root create/edit, invalid atomic rejection and stable internal references.');
  await openLiteral();await access().selectOption('read-write');
  assert.equal(await readView().inputValue(),'all');assert.equal(await writeView().inputValue(),'');
  await readView().selectOption(readViewId);await writeView().selectOption(writeViewId);
  await readNets().fill('127.0.0.0/8');await writeNets().fill('192.0.2.0/24, 2001:db8::/32');
  result=await saveCredential('2c');
  assert.deepEqual(result.credential.polling,{enabled:true,view_id:readViewId,networks:['127.0.0.0/8']});
  assert.deepEqual(result.credential.writing,{enabled:true,view_id:writeViewId,networks:['192.0.2.0/24','2001:db8::/32']});
  await page.locator(`button[data-action=delete-view][data-id="${writeViewId}"]`).click();
  response=page.waitForResponse(r=>r.url().endsWith('/snmp/views/'+writeViewId)&&r.request().method()==='DELETE');
  await page.getByRole('button',{name:'Delete record',exact:true}).click();assert.equal((await response).status(),422);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await openLiteral();await writeNets().fill('');await saveCredential('2c');
  await openLiteral();await access().selectOption('none');await saveCredential('2c');
  await page.locator(`button[data-action=delete-view][data-id="${readViewId}"]`).click();
  await page.getByRole('button',{name:'Delete record',exact:true}).click();await page.locator('dialog').waitFor({state:'hidden'});
  await openLiteral();await access().selectOption('read');
  assert.equal(await readView().inputValue(),readViewId);
  assert.equal(await readView().locator('option:checked').textContent(),'Missing view · '+readViewId);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.deepEqual((await state()).targets[noView.id],retainedTarget);
  // Shared groups own policy; users have one membership selector and no overrides.
  await page.getByRole('button',{name:'+ Group',exact:true}).click();
  await page.getByLabel('Label',{exact:true}).fill('Browser group');
  assert.equal(await page.getByLabel('Minimum security level').inputValue(),'authPriv');assert.equal(await access().inputValue(),'none');
  const groupId=(await saveForm('snmp/groups')).body.id;
  await page.getByRole('button',{name:'+ User',exact:true}).click();
  assert.equal(await page.getByLabel('Security level').inputValue(),'authPriv');
  assert.equal(await page.locator('dialog select[name=group_choice]').inputValue(),'none');assert.equal(await access().count(),0);
  await page.getByLabel('Label',{exact:true}).fill('Grouped browser user');await page.getByLabel('Username',{exact:true}).fill('grouped-browser');
  await page.getByLabel('Security level').selectOption('noAuthNoPriv');
  await page.locator('dialog select[name=group_choice]').selectOption('group:'+groupId);
  await page.getByText("This user's security level does not meet the group's minimum",{exact:false}).waitFor();
  const grouped=(await saveCredential('3')).credential;
  await editCredential('Inline browser v3');await page.locator('dialog select[name=group_choice]').selectOption('group:'+groupId);await saveCredential('3');
  await page.locator(`button[data-action=group][data-id="${groupId}"]`).click();
  await page.getByText('Grouped browser user (noAuthNoPriv)',{exact:false}).waitFor();
  await page.getByText('Below selected minimum: Grouped browser user.',{exact:false}).waitFor();
  await page.getByLabel('Minimum security level').selectOption('noAuthNoPriv');
  assert.equal(await page.locator('#group-members-hint').textContent(),'');await access().selectOption('write');
  await writeView().selectOption(writeViewId);await writeNets().fill('192.0.2.0/24');
  const groupSave=await saveForm('snmp/groups');assert.equal('polling' in groupSave.payload,false);
  snapshot=await state();assert.equal(snapshot.credentials[grouped.id].group_id,groupId);
  assert.equal(snapshot.credentials[created.credential_id].group_id,groupId);
  assert.equal('writing' in snapshot.credentials[grouped.id],false);
  await page.locator(`button[data-action=group][data-id="${groupId}"]`).click();
  await writeNets().fill('203.0.113.0/24');await access().selectOption('none');
  const hiddenSave=await saveForm('snmp/groups');assert.deepEqual(hiddenSave.payload.writing,{enabled:false});
  assert.deepEqual((await state()).groups[groupId].writing.networks,['192.0.2.0/24']);
  // A real competing revision rejects the entire combined group form.
  await page.locator(`button[data-action=group][data-id="${groupId}"]`).click();
  await access().selectOption('read-write');await readView().selectOption(writeViewId);await writeView().selectOption(writeViewId);
  await page.getByLabel('Label',{exact:true}).fill('Rejected group rename');
  const auth=await (await page.request.get(new URL('/api/v1/auth/status',fixtureURL).href)).json();
  snapshot=await state();
  assert.equal((await page.request.post(new URL('/api/v1/clock/pause',fixtureURL).href,{headers:{'X-CSRF-Token':auth.csrf_token},data:{expected_configuration_revision:snapshot.configuration_revision}})).status(),200);
  const beforeStale=await state();await failure('snmp/groups',409,'Configuration changed while editing');
  assert.deepEqual((await state()).groups,beforeStale.groups);assert.deepEqual((await state()).credentials,beforeStale.credentials);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  // Only presentation is synthetic here: the actual application remains disabled/unset.
  const statusURL=new URL('/api/v1/state',fixtureURL).href;
  const displayWriter=async route=>{
    const actual=await route.fetch(),body=await actual.json();
    body.snmp_status={...body.snmp_status,ready:false,reason:'credentials_required',listener_ready:true,writing_ready:true,writing_reason:'ready'};
    await route.fulfill({response:actual,json:body});
  };
  await page.route(statusURL,displayWriter);
  await page.reload();await page.locator('nav button[data-id=snmp]').click();
  await service.getByText('Listening',{exact:true}).waitFor();
  assert.equal(await service.getByText(/Polling state|SET state|Read state|Write state/).count(),0);
  await page.unroute(statusURL,displayWriter);await page.reload();await page.locator('nav button[data-id=snmp]').click();
  assert.equal((await state()).snmp.enabled,false);assert.equal((await state()).switch.identity.sys_object_id,null);
  console.log('Unified access browser passed: four modes, sparse/hidden drafts, explicit conversions, shared users/groups, mismatch/defaults, missing views, literal labels, real atomic errors, one listener status and exact title.');

  await page.locator('nav button[data-id=radius]').click();
  for(const [section,action] of [['radius-templates','radius-template'],['radius-accounting','accounting-settings'],['radius-dynamic','dynamic-settings']]){
    const disclosure=page.locator('#'+section),summary=disclosure.locator(':scope > summary');
    for(const opened of [false,true]){
      if(await disclosure.evaluate(el=>el.open)!==opened)await summary.click({position:{x:8,y:8}});
      const control=summary.locator(`button[data-action=${action}]`);
      await control.focus();await page.keyboard.press('Enter');await page.locator('dialog[open]').waitFor();
      assert.equal(await disclosure.evaluate(el=>el.open),opened);
      await page.getByRole('button',{name:'Cancel',exact:true}).click();
      assert.equal(await disclosure.evaluate(el=>el.open),opened);
    }
    await summary.focus();await page.keyboard.press('Space');
    assert.equal(await disclosure.evaluate(el=>el.open),false);
  }
  await page.locator('nav button[data-id=snmp]').click();


  // The port form preserves independent egress sets and previews native API convenience.
  await page.locator('nav button[data-id=vlans]').click();
  for(const vid of [10,20,30]){
    await page.getByRole('button',{name:'+ Add VLAN',exact:true}).click();
    await page.getByLabel('VLAN ID',{exact:true}).fill(String(vid));
    await page.getByLabel('Name',{exact:true}).fill('Browser VLAN '+vid);
    await page.getByRole('button',{name:'Apply',exact:true}).click();
    await page.locator('dialog').waitFor({state:'hidden'});
  }
  await page.locator('nav button[data-id=overview]').click();
  await page.locator(`button[data-action="select-port"][data-id="${sharedPort}"]`).click();
  const openPort=()=>detail.getByRole('button',{name:'Configure port',exact:true}).click();
  const savePort=async()=>{
    const request=page.waitForRequest(r=>r.url().endsWith('/api/v1/ports/'+sharedPort)&&r.method()==='PATCH');
    await page.getByRole('button',{name:'Apply',exact:true}).click();
    const payload=(await request).postDataJSON();
    await page.locator('dialog').waitFor({state:'hidden'});
    return payload;
  };
  const ulabel='Untagged VLANs (comma-separated, optional)',flabel='Forbidden VLANs (comma-separated, optional)';
  const endpointData=(await state()).endpoints;
  await openPort();
  // Familiar labels must still submit the original attachment/authentication enums.
  for(const [name,expected] of [
    ['mode',[['direct','Direct · one endpoint'],['shared','Shared · explicit partner']]],
    ['auth_control',[['force-authorized','Force authorized'],['auto','Auto (authentication required)'],['force-unauthorized','Force unauthorized']]],
    ['auth_method',[['dot1x','802.1X only'],['mab','MAB only'],['dot1x-mab','802.1X with MAB fallback']]],
    ['auth_host_mode',[['single-host','Single-host'],['multi-auth','Multi-auth (per-MAC authentication)'],['multi-host','Multi-host (one authenticated owner)']]]]){
    assert.deepEqual(await page.locator(`dialog [name=${name}] option`).evaluateAll(options=>options.map(o=>[o.value,o.textContent])),expected);
  }
  assert.equal(await page.getByLabel('MAB fallback after RADIUS Access-Reject',{exact:true}).getAttribute('name'),'auth_reject');
  assert.equal(await page.getByLabel('Enable port',{exact:true}).getAttribute('name'),'admin_up');
  await page.getByLabel('Allowed VLANs (configured, comma-separated)').fill('1, 10, 20');
  await page.getByLabel(ulabel).fill('1, 20');
  await page.getByLabel(flabel).fill('30');
  assert.deepEqual((await savePort()).untagged,[1,20]);
  await openPort();
  assert.equal(await page.getByLabel(ulabel).inputValue(),'1, 20');
  await page.getByLabel('Alias',{exact:true}).fill('Independent egress preserved');
  assert.equal('untagged' in await savePort(),false);
  assert.deepEqual((await state()).ports[sharedPort].untagged,[1,20]);
  await openPort();
  await page.getByLabel('Port VLAN ID (PVID)').selectOption('10');
  assert.equal(await page.getByLabel(ulabel).inputValue(),'10, 20');
  assert.equal('untagged' in await savePort(),false);
  assert.deepEqual((await state()).ports[sharedPort].untagged,[10,20]);
  await openPort();
  await page.getByLabel(ulabel).fill('');
  await page.getByLabel('Port VLAN ID (PVID)').selectOption('20');
  assert.equal(await page.getByLabel(ulabel).inputValue(),'');
  await page.getByLabel('Port VLAN ID (PVID)').selectOption('10');
  assert.deepEqual((await savePort()).untagged,[]);
  await openPort();
  await page.getByLabel('Port VLAN ID (PVID)').selectOption('20');
  assert.equal(await page.getByLabel(ulabel).inputValue(),'20');
  assert.equal('untagged' in await savePort(),false);
  snapshot=await state();
  assert.equal(snapshot.ports[sharedPort].pvid,20);assert.deepEqual(snapshot.ports[sharedPort].untagged,[20]);
  assert.deepEqual(snapshot.ports[sharedPort].forbidden,[30]);assert.deepEqual(snapshot.endpoints,endpointData);
  await openPort();
  await page.getByLabel(flabel).fill('1');
  response=page.waitForResponse(r=>r.url().endsWith('/api/v1/ports/'+sharedPort)&&r.request().method()==='PATCH');
  await page.getByRole('button',{name:'Apply',exact:true}).click();
  assert.equal((await response).status(),422);
  await page.locator('.form-error').filter({hasText:'forbidden VLANs cannot be admitted'}).waitFor();
  assert.deepEqual((await state()).ports[sharedPort],snapshot.ports[sharedPort]);
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await detail.getByText('Untagged VLANs',{exact:true}).waitFor();
  await detail.getByText('Forbidden VLANs',{exact:true}).waitFor();
  await page.locator('nav button[data-id=vlans]').click();
  await page.getByRole('columnheader',{name:'Forbidden ports',exact:true}).waitFor();
  const vlan20=page.locator('tbody tr').filter({has:page.locator('td:first-child .pill',{hasText:/^20$/})});
  assert.ok((await vlan20.locator('td').nth(4).textContent()).split(', ').includes(String(snapshot.ports[sharedPort].bridge_port)));
  await page.locator('nav button[data-id=snmp]').click();
  console.log('Independent VLAN browser passed: actual admitted/untagged/forbidden sets, explicit empty egress, untouched native preview/formula, unrelated edit preservation, rejected overlap and unchanged endpoint/source data.');
  await page.locator('nav button[data-id=radius]').click();
  // RADIUS uses the existing source/selected-port owners. No server or
  // listener is enabled here; protocol interoperability is tested separately.
  const radiusCard=page.locator('#radius-config');
  const saveRadius=async()=>{await page.locator('dialog button[type=submit]').click();await page.locator('dialog[open]').waitFor({state:'hidden'});};
  await radiusCard.locator('#radius-servers > summary').click();
  await radiusCard.locator('#radius-servers > summary').focus();
  await radiusCard.evaluate(el=>el.dataset.refreshProbe='waiting');
  await page.waitForFunction(()=>!document.getElementById('radius-config').dataset.refreshProbe);
  assert.equal(await radiusCard.locator('#radius-servers').evaluate(el=>el.open),true);
  assert.equal(await radiusCard.locator('#radius-servers > summary').evaluate(el=>el===document.activeElement),true);
  await radiusCard.locator('#radius-servers button[data-action=radius-server]').click();
  await page.getByText(/In Docker bridge mode, the local source IP must exist inside the container/).waitFor();
  await page.getByLabel('Label',{exact:true}).fill('Browser RADIUS');await page.getByLabel('Server IP address',{exact:true}).fill('192.0.2.10');
  await page.getByLabel('Shared secret',{exact:true}).fill('synthetic-browser-radius-secret');await page.getByLabel('Enabled',{exact:true}).uncheck();await saveRadius();
  let radiusState=await state();const radiusServer=radiusState.radius.servers[0];assert.ok(radiusServer.has_secret);assert.equal(radiusServer.enabled,false);
  await radiusCard.locator('.setting-row').filter({hasText:'Browser RADIUS'}).getByRole('button',{name:'Edit',exact:true}).click();
  assert.equal(await page.getByLabel('Shared secret (blank = unchanged)',{exact:true}).inputValue(),'');await page.getByLabel('Label',{exact:true}).fill('Browser RADIUS renamed');await saveRadius();
  await radiusCard.getByRole('button',{name:'+ Add certificate',exact:true}).click();
  assert.equal(await page.locator('dialog [name=kind]').inputValue(),'ca');
  await page.getByLabel('Label',{exact:true}).fill('Browser trust');
  const beforeFile=await state(),beforeFileWrites=mutations.length;
  await page.locator('dialog [name=certificate_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE);
  assert.equal(mutations.length,beforeFileWrites);assert.deepEqual((await state()).radius,beforeFile.radius);
  assert.equal(await page.locator('dialog textarea[name=certificate]').inputValue(),'');
  await saveRadius();
  radiusState=await state();const trust=Object.values(radiusState.radius.materials).find(m=>m.label==='Browser trust');
  const certRow=label=>radiusCard.locator('#radius-materials .setting-row').filter({has:page.locator('b').filter({hasText:label})});
  await certRow('Browser trust').getByRole('button',{name:'Edit',exact:true}).click();
  assert.equal(await page.locator('dialog textarea[name=certificate]').inputValue(),'');
  assert.equal(await page.locator('dialog [name=certificate_file]').inputValue(),'');
  await page.getByLabel('Label',{exact:true}).fill('Browser trust renamed');await saveRadius();
  assert.equal(await page.locator('dialog').textContent(),'');
  assert.ok((await state()).radius.materials[trust.id].has_certificate);
  // Client certificate/key files stay draft-only; saved bytes are never redisplayed.
  await radiusCard.getByRole('button',{name:'+ Add certificate',exact:true}).click();
  await page.locator('dialog [name=kind]').selectOption('client');
  await page.getByLabel('Label',{exact:true}).fill('Browser client');
  await page.locator('dialog [name=certificate_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE);
  await page.locator('dialog [name=private_key_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_KEY_FILE);
  await page.getByLabel('Key password (optional)',{exact:true}).fill('synthetic-certificate-password');await saveRadius();
  const clientCertificate=Object.values((await state()).radius.materials).find(m=>m.label==='Browser client');
  assert.ok(clientCertificate.has_private_key&&clientCertificate.has_key_password);
  await certRow('Browser client').getByRole('button',{name:'Edit',exact:true}).click();
  assert.equal(await page.locator('dialog textarea[name=private_key]').inputValue(),'');
  assert.equal(await page.getByLabel('Key password (blank = unchanged)',{exact:true}).inputValue(),'');
  await page.getByLabel('Label',{exact:true}).fill('Browser client renamed');
  const sparse=page.waitForRequest(r=>r.url().endsWith('/radius/materials')&&r.method()==='POST');await saveRadius();
  const sparsePayload=(await sparse).postDataJSON();for(const key of ['certificate','private_key','key_password'])assert.equal(key in sparsePayload,false);
  assert.ok((await state()).radius.materials[clientCertificate.id].has_key_password);
  // Save snapshots both PEM drafts before any file read: later choices belong
  // to the next edit, never to the request already in flight.
  const pemSnapshotCases=[];
  for(const change of ['replace key file','change key mode and paste']){
    await certRow('Browser client renamed').getByRole('button',{name:'Edit',exact:true}).click();
    await page.locator('dialog [name=certificate_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE);
    await page.locator('dialog [name=private_key_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_KEY_FILE);
    await page.getByLabel('Key password (blank = unchanged)',{exact:true}).fill('synthetic-certificate-password');
    const clickedRevision=(await state()).configuration_revision;
    await page.evaluate(()=>{
      const certificate=document.querySelector('dialog [name=certificate_file]').files[0];
      const read=File.prototype.arrayBuffer;
      window.restoreSnapshotRead=()=>{File.prototype.arrayBuffer=read;delete window.releaseSnapshotRead;delete window.restoreSnapshotRead;};
      File.prototype.arrayBuffer=function(){return this===certificate?new Promise(resolve=>{window.releaseSnapshotRead=()=>read.call(this).then(resolve);}):read.call(this);};
    });
    const saved=page.waitForResponse(r=>r.url().endsWith('/radius/materials')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Save changes',exact:true}).click();
    await page.waitForFunction(()=>!!window.releaseSnapshotRead);
    if(change==='replace key file'){
      await page.locator('dialog [name=private_key_file]').setInputFiles({name:'later-key.pem',mimeType:'text/plain',buffer:Buffer.from('later unsaved key file')});
    }else{
      await page.locator('dialog [name=private_key_input]').selectOption('paste');
      await page.locator('dialog textarea[name=private_key]').fill('later unsaved pasted key');
    }
    await page.getByLabel('Label',{exact:true}).fill('Later unsaved label');
    await page.getByLabel('Key password (blank = unchanged)',{exact:true}).fill('later-unsaved-password');
    await page.evaluate(async()=>{await window.releaseSnapshotRead();window.restoreSnapshotRead();});
    const response=await saved,payload=response.request().postDataJSON();
    // Compare privately; assertion output must never print PEM/key/password values.
    const expected={id:clientCertificate.id,kind:'client',label:'Browser client renamed',certificate:radiusCA,private_key:fs.readFileSync(process.env.SWITCHLAB_TEST_RADIUS_KEY_FILE,'utf8'),key_password:'synthetic-certificate-password',expected_configuration_revision:clickedRevision};
    const exact=Object.keys(payload).sort().join()===Object.keys(expected).sort().join()&&Object.keys(expected).every(key=>payload[key]===expected[key]);
    if(response.ok())await page.locator('dialog[open]').waitFor({state:'hidden'});
    else {await page.locator('dialog .form-error').filter({hasText:/./}).waitFor();await page.getByRole('button',{name:'Cancel',exact:true}).click();}
    const retained=(await state()).radius.materials[clientCertificate.id];
    const passed=exact&&response.status()===200&&retained.label==='Browser client renamed'&&retained.has_private_key&&retained.has_key_password;
    pemSnapshotCases.push(passed);console.log(`PEM Save snapshot (${change}): ${passed?'pass':'FAIL'}`);
  }
  assert.deepEqual(pemSnapshotCases,[true,true],'Save must use the exact click-time certificate/key/scalar/revision snapshot');
  // File read/size failures keep the other draft; no failed read silently saves blank.
  await certRow('Browser trust renamed').getByRole('button',{name:'Edit',exact:true}).click();
  await page.locator('dialog [name=certificate_input]').selectOption('paste');await page.locator('dialog textarea[name=certificate]').fill(radiusCA);
  await page.locator('dialog [name=certificate_input]').selectOption('file');
  await page.locator('dialog [name=certificate_file]').setInputFiles({name:'oversize.pem',mimeType:'text/plain',buffer:Buffer.alloc(262145)});
  await page.evaluate(()=>{window.originalFileRead=File.prototype.arrayBuffer;window.fileReads=0;File.prototype.arrayBuffer=function(){window.fileReads++;return window.originalFileRead.call(this);};});
  const beforeBadRead=mutations.length;await page.getByRole('button',{name:'Save changes',exact:true}).click();
  await page.locator('dialog .form-error').filter({hasText:'size limit'}).waitFor();
  assert.equal(await page.evaluate(()=>window.fileReads),0);assert.equal(mutations.length,beforeBadRead);
  await page.locator('dialog [name=certificate_file]').setInputFiles({name:'invalid-utf8.pem',mimeType:'text/plain',buffer:Buffer.from([255])});
  await page.getByRole('button',{name:'Save changes',exact:true}).click();await page.locator('dialog .form-error').filter({hasText:'UTF-8'}).waitFor();
  assert.equal(mutations.length,beforeBadRead);assert.ok((await page.locator('dialog textarea[name=certificate]').inputValue())===radiusCA,'Alternate PEM draft is preserved');
  await page.evaluate(()=>{File.prototype.arrayBuffer=window.originalFileRead;delete window.originalFileRead;});
  await page.locator('dialog [name=certificate_input]').selectOption('paste');await saveRadius();
  // Invalid parsed material is rejected atomically, including a useful entered label.
  await certRow('Browser trust renamed').getByRole('button',{name:'Edit',exact:true}).click();
  await page.getByLabel('Label',{exact:true}).fill('Must not commit');
  await page.locator('dialog [name=certificate_input]').selectOption('paste');await page.locator('dialog textarea[name=certificate]').fill('not a certificate');
  const beforeInvalidMaterial=(await state()).radius.materials;
  await page.getByRole('button',{name:'Save changes',exact:true}).click();await page.locator('dialog .form-error').filter({hasText:'Invalid certificate'}).waitFor();
  assert.deepEqual((await state()).radius.materials,beforeInvalidMaterial);
  assert.equal(await page.locator('dialog textarea[name=certificate]').inputValue(),'not a certificate');await page.getByRole('button',{name:'Cancel',exact:true}).click();
  // A canceled asynchronous file read cannot submit or close the next dialog.
  await radiusCard.getByRole('button',{name:'+ Add certificate',exact:true}).click();await page.getByLabel('Label',{exact:true}).fill('Canceled read');
  await page.locator('dialog [name=certificate_file]').setInputFiles(process.env.SWITCHLAB_TEST_RADIUS_CA_FILE);
  await page.evaluate(()=>{window.originalFileRead=File.prototype.arrayBuffer;File.prototype.arrayBuffer=function(){return new Promise(resolve=>{window.releaseFileRead=()=>window.originalFileRead.call(this).then(resolve);});};});
  const beforeCanceledRead=mutations.length;await page.getByRole('button',{name:'Save changes',exact:true}).click();
  await page.waitForFunction(()=>!!window.releaseFileRead);await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await radiusCard.getByRole('button',{name:'+ Add certificate',exact:true}).click();await page.getByLabel('Label',{exact:true}).fill('Next dialog');
  await page.evaluate(async()=>{await window.releaseFileRead();File.prototype.arrayBuffer=window.originalFileRead;delete window.originalFileRead;delete window.releaseFileRead;});
  await page.waitForTimeout(80);assert.equal(mutations.length,beforeCanceledRead);assert.equal(await page.getByLabel('Label',{exact:true}).inputValue(),'Next dialog');
  await page.getByRole('button',{name:'Cancel',exact:true}).click();assert.equal(await page.locator('dialog').textContent(),'');
  await certRow('Browser trust renamed').getByRole('button',{name:'Edit',exact:true}).click();
  await page.getByLabel('Label',{exact:true}).fill('Stale certificate edit');
  const staleMaterialBefore=await state();
  assert.equal((await page.request.post(new URL('/api/v1/clock/pause',fixtureURL).href,{headers:{'X-CSRF-Token':auth.csrf_token},data:{expected_configuration_revision:staleMaterialBefore.configuration_revision}})).status(),200);
  await page.getByRole('button',{name:'Save changes',exact:true}).click();await page.locator('dialog .form-error').filter({hasText:'Configuration changed while editing'}).waitFor();
  assert.deepEqual((await state()).radius.materials,staleMaterialBefore.radius.materials);await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await radiusCard.locator('#radius-templates > summary').click();await radiusCard.getByRole('button',{name:'+ Template',exact:true}).click();
  assert.equal(await page.locator('dialog [name=client_identity_id]').inputValue(),'');assert.ok((await page.locator('dialog [name=client_identity_id]').textContent()).includes('Browser client renamed'));assert.equal(await page.getByLabel('Expected server DNS name',{exact:true}).getAttribute('required'),'');
  await page.getByLabel('Template label',{exact:true}).fill('Browser supplicant');await page.locator('dialog [name=method]').selectOption('peap');
  await page.getByLabel('Outer identity',{exact:true}).fill('outer-browser');await page.locator('dialog [name=trust_id]').selectOption(trust.id);
  await page.getByLabel('Expected server DNS name',{exact:true}).fill('radius-fixture.invalid');await page.getByLabel('Inner username',{exact:true}).fill('inner-'+ 'x'.repeat(64));
  await page.getByLabel('Password',{exact:true}).fill('synthetic-browser-peap-password');await saveRadius();
  radiusState=await state();const template=Object.values(radiusState.radius.templates).find(t=>t.label==='Browser supplicant');
  await page.locator('nav button[data-id=endpoints]').click();
  for(const sourceEndpoint of [endpoint,second]){
    await page.locator(`button[data-action=supplicants][data-id="${sourceEndpoint.id}"]`).click();
    await page.locator('dialog [name=template_id]').selectOption(template.id);assert.equal(await page.locator('dialog [name=method]').inputValue(),'peap');
    if(sourceEndpoint.id===endpoint.id)await page.getByLabel('Inner username',{exact:true}).fill('custom-browser-inner');
    await saveRadius();
  }
  radiusState=await state();assert.equal(radiusState.endpoints[endpoint.id].sources[0].supplicant.username,'custom-browser-inner');
  assert.equal(radiusState.endpoints[second.id].sources[0].supplicant.username,'inner-'+ 'x'.repeat(64));
  assert.ok(radiusState.endpoints[endpoint.id].sources[0].supplicant.has_password);
  await page.locator('nav button[data-id=radius]').click();
  await certRow('Browser trust renamed').getByText('1 template · 2 copied source profiles',{exact:true}).waitFor();
  await certRow('Browser trust renamed').getByRole('button',{name:'Delete',exact:true}).click();
  const beforeReferencedDelete=(await state()).radius.materials;
  await page.locator('dialog').getByRole('button',{name:'Delete',exact:true}).click();
  await page.waitForFunction(()=>!!document.querySelector('dialog .form-error')?.textContent);
  assert.deepEqual((await state()).radius.materials,beforeReferencedDelete);await page.getByRole('button',{name:'Cancel',exact:true}).click();
  if(!await radiusCard.locator('#radius-templates').evaluate(el=>el.open))await radiusCard.locator('#radius-templates > summary').click();
  await radiusCard.locator('.setting-row').filter({hasText:'Browser supplicant'}).getByRole('button',{name:'Edit',exact:true}).click();
  await page.getByLabel('Inner username',{exact:true}).fill('changed-template-only');await saveRadius();
  radiusState=await state();assert.equal(radiusState.endpoints[endpoint.id].sources[0].supplicant.username,'custom-browser-inner');assert.equal(radiusState.endpoints[second.id].sources[0].supplicant.username,'inner-'+ 'x'.repeat(64));
  await radiusCard.locator('#radius-accounting > summary').click();await radiusCard.locator('#radius-accounting > summary button[data-action=accounting-target]').click();
  assert.equal(await page.getByLabel('UDP port',{exact:true}).inputValue(),'1813');await page.getByLabel('Label',{exact:true}).fill('Browser collector');
  await page.getByLabel('Server IP address',{exact:true}).fill('192.0.2.11');await page.getByLabel('Shared secret',{exact:true}).fill('synthetic-browser-accounting-secret');await saveRadius();
  await radiusCard.locator('.setting-row').filter({hasText:'Browser collector'}).getByRole('button',{name:'Edit',exact:true}).click();assert.equal(await page.getByLabel('Shared secret (blank = unchanged)',{exact:true}).inputValue(),'');await saveRadius();
  for(const [mode,interval] of [['local',120],['off',0],['server',null]]){
    await radiusCard.locator('#radius-accounting > summary button[data-action=accounting-settings]').click();await page.locator('dialog [name=interim_mode]').selectOption(mode);
    await page.getByLabel('Local interim interval (simulation seconds)',{exact:true}).fill('120');
    await page.getByLabel('RADIUS response timeout (real seconds)',{exact:true}).fill('4');await page.getByLabel('Attempts per server',{exact:true}).fill('2');await page.getByLabel('Retry backoff base (real seconds)',{exact:true}).fill('0');await saveRadius();
    radiusState=await state();assert.equal(radiusState.radius.accounting.interim_seconds,interval);assert.equal(radiusState.radius.accounting.response_timeout_seconds,4);assert.equal(radiusState.radius.accounting.attempts,2);assert.equal(radiusState.radius.accounting.retry_backoff_seconds,0);
    assert.equal(radiusState.radius.accounting.enabled,false);assert.equal(radiusState.radius.response_timeout_seconds,3);assert.equal(radiusState.radius.attempts,3);
  }
  await radiusCard.locator('#radius-dynamic > summary').click();await radiusCard.locator('#radius-dynamic > summary button[data-action=dynamic-sender]').click();
  await page.getByLabel('Label',{exact:true}).fill('Browser sender');await page.getByLabel('Client IP address',{exact:true}).fill('192.0.2.12');await page.getByLabel('Shared secret',{exact:true}).fill('synthetic-browser-das-secret');await saveRadius();
  await radiusCard.locator('.setting-row').filter({hasText:'Browser sender'}).getByRole('button',{name:'Edit',exact:true}).click();assert.equal(await page.getByLabel('Shared secret (blank = unchanged)',{exact:true}).inputValue(),'');await saveRadius();
  await radiusCard.locator('#radius-dynamic > summary button[data-action=dynamic-settings]').click();await page.getByLabel('Bind IP address',{exact:true}).fill('127.0.0.1');await page.getByLabel('UDP port',{exact:true}).fill('3799');await saveRadius();
  radiusState=await state();assert.equal(radiusState.radius.dynamic_authorization.enabled,false);assert.equal(radiusState.radius.dynamic_status.ready,false);assert.ok(radiusState.radius.dynamic_authorization.senders[0].has_secret);
  for(const label of ['Browser collector','Browser sender']){await radiusCard.locator('.setting-row').filter({hasText:label}).getByRole('button',{name:'Delete',exact:true}).click();await page.locator('dialog').getByRole('button',{name:'Delete',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});}
  await page.locator('nav button[data-id=overview]').click();await page.locator(`button[data-action=select-port][data-id="${sharedPort}"]`).click();
  const overviewClasses=await page.locator(`button[data-action=select-port][data-id="${sharedPort}"]`).getAttribute('class');
  const carrier=(await state()).ports[sharedPort].operational_up;
  await openPort();await page.locator('dialog [name=auth_control]').selectOption('auto');await page.locator('dialog [name=auth_method]').selectOption('dot1x');await page.locator('dialog [name=auth_host_mode]').selectOption('multi-auth');await savePort();
  assert.equal((await state()).ports[sharedPort].operational_up,carrier);
  assert.equal(await page.locator(`button[data-action=select-port][data-id="${sharedPort}"]`).getAttribute('class'),overviewClasses);
  // Presentation-only responses exercise simultaneous successful, pending, failed
  // clients and safe on-demand attributes. They never install a backend grant.
  const macA=endpoint.sources[0].mac,macB=second.sources[0].mac,macC='02:11:22:33:44:77';
  const safeResponse={nas_code:2,attributes:[{name:'Service-Type',status:'present',value:2},{name:'Tunnel-Private-Group-ID',status:'present',value:30},{name:'Session-Timeout',status:'absent'}],omitted:[{name:'Class',count:2},{name:'State',count:1}]};
  const badResponse={nas_code:2,attributes:[{name:'Service-Type',status:'present',value:8},{name:'Idle-Timeout',status:'invalid'}],omitted:[{name:'Attribute 11',count:1}]};
  const displayRadius=async route=>{const actual=await route.fetch(),body=await actual.json();body.authentication_sessions=[{id:'browser-display-session',port_id:sharedPort,mac:macA,method:'peap',vid:20,source:'radius',started_ms:0,in_octets:128,in_packets:2,lease_deadline_ms:60000,idle_deadline_ms:30000,reauthentication_deadline_ms:60000}];body.authentication_clients=[{port_id:sharedPort,mac:macA,status:'authorized',method:'peap',response:safeResponse},{port_id:sharedPort,mac:macB,status:'pending',method:'peap'},{port_id:sharedPort,mac:macC,status:'failed',reason:'local-policy <b>not applied</b>',response:badResponse}];await route.fulfill({response:actual,json:body});};
  const displayHistory=async route=>{const actual=await route.fetch(),body=await actual.json();body.events.push(...[900000,900001].map(id=>({id,kind:'authentication-failed',port_id:sharedPort,mac:macC,simulation_ms:1000,reason:'local-policy <b>not applied</b>',response:badResponse})));await route.fulfill({response:actual,json:body});};
  const eventsURL=new URL('/api/v1/events?limit=2000',fixtureURL).href;
  await page.route(statusURL,displayRadius);await page.route(eventsURL,displayHistory);
  try{
    await page.reload();await page.locator(`button[data-action=select-port][data-id="${sharedPort}"]`).click();
    assert.equal(await page.locator('.port-detail').count(),1);
    for(const heading of ['Link','Configured VLANs','Attached endpoints','Port access'])await detail.getByRole('heading',{name:new RegExp('^'+heading)}).waitFor();
    for(const label of ['Admin / carrier','Mode','Shared link partner','Forced link fault','Port VLAN ID (PVID)','Allowed VLANs (configured)','Untagged VLANs','Forbidden VLANs'])await detail.getByText(label,{exact:true}).waitFor();
    await detail.getByRole('button',{name:'Configure port',exact:true}).waitFor();await detail.getByRole('button',{name:'+ Attach endpoint',exact:true}).waitFor();
    await detail.getByRole('button',{name:'Reauthenticate',exact:true}).waitFor();await detail.getByRole('button',{name:'Restart authentication',exact:true}).waitFor();
    assert.ok((await detail.locator('.port-meta').textContent()).includes('ifIndex '+(await state()).ports[sharedPort].if_index));

    const clientRows=detail.locator('.authentication-clients tbody tr');
    await clientRows.filter({hasText:macA}).getByText('Authorized',{exact:true}).waitFor();await clientRows.filter({hasText:macB}).getByText('pending',{exact:true}).waitFor();await clientRows.filter({hasText:macC}).getByText('failed',{exact:true}).waitFor();
    assert.equal(await clientRows.locator('td b').filter({hasText:'not applied'}).count(),0);
    const currentDetails=page.locator(`[id="current-response-${sharedPort}-${macA}"]`);await currentDetails.locator(':scope > summary').click();
    await currentDetails.getByText('Present × 2; value omitted',{exact:true}).waitFor();await currentDetails.getByText('absent',{exact:true}).waitFor();
    await currentDetails.locator('summary').getByText('Returned RADIUS attributes',{exact:true}).waitFor();
    await currentDetails.getByText('RADIUS response: Access-Accept',{exact:true}).waitFor();
    assert.equal(await currentDetails.locator('.facts > div').filter({has:page.getByText('Tunnel-Private-Group-ID',{exact:true})}).locator('dd').textContent(),'30');
    const authorizedRow=clientRows.filter({hasText:macA});
    assert.equal(await authorizedRow.locator('[data-label="Effective VLAN"]').textContent(),'20RADIUS-assigned');
    await authorizedRow.getByText('Session timeout at 00:01:00 (simulation time) · Idle timeout at 00:00:30 (simulation time)',{exact:true}).waitFor();
    await detail.locator('.access-policy').getByText('Multi-auth',{exact:true}).waitFor();
    await detail.locator('.access-policy').getByText('Auto (authentication required)',{exact:true}).waitFor();
    const history=page.locator(`[id="auth-history-${sharedPort}-${macC}"]`);await history.locator(':scope > summary').click();await history.getByText('authentication-failed × 2',{exact:true}).waitFor();
    const historical=history.locator('details');await historical.locator('summary').click();await historical.getByText('invalid',{exact:true}).waitFor();
    await historical.locator('summary').focus();const scroll=await page.evaluate(()=>scrollY);
    await history.evaluate(el=>el.dataset.refreshProbe='waiting');
    await page.waitForFunction(id=>!document.getElementById(id).dataset.refreshProbe,`auth-history-${sharedPort}-${macC}`);
    assert.equal(await history.evaluate(el=>el.open),true);assert.equal(await historical.evaluate(el=>el.open),true);
    assert.equal(await historical.locator('summary').evaluate(el=>el===document.activeElement),true);
    assert.equal(await page.locator('.port.selected').getAttribute('data-id'),sharedPort);assert.equal(await page.evaluate(()=>scrollY),scroll);
    await screenshot('port-detail-desktop.png');
    await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    for(const node of await detail.locator('button,summary').all()){if(await node.isVisible()){const box=await node.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=390);}}
    await screenshot('port-detail-mobile.png');await page.setViewportSize({width:1440,height:1100});
  }finally{await page.unroute(statusURL,displayRadius);await page.unroute(eventsURL,displayHistory);}
  await page.reload();await page.locator(`button[data-action=select-port][data-id="${sharedPort}"]`).click();
  await openPort();await page.locator('dialog [name=auth_control]').selectOption('force-authorized');await savePort();
  radiusState=await state();assert.equal(radiusState.authentication_sessions.length,0);assert.equal(radiusState.ports[sharedPort].operational_up,carrier);
  assert.equal(radiusState.radius.accounting.targets.length,0);assert.equal(radiusState.radius.dynamic_authorization.senders.length,0);
  assert.equal(radiusState.radius.servers.length,1);assert.equal(radiusState.radius.servers[0].enabled,false);
  const radiusText=JSON.stringify(radiusState);for(const privateValue of ['synthetic-browser-radius-secret','synthetic-browser-peap-password','synthetic-browser-accounting-secret','synthetic-browser-das-secret','BEGIN CERTIFICATE'])assert.equal(radiusText.includes(privateValue),false);
  await page.locator('nav button[data-id=radius]').click();
  console.log('RADIUS browser passed: independent disabled destinations, captured retry policy, sparse secrets, copied profiles/templates, unchanged carrier/colors, selected-port successful/pending/failed presentation, grouped escaped history, safe on-demand attributes, focus/disclosure/scroll refresh and mobile. Presentation samples do not authorize backend sessions.');
  // Explicit startup save is global; lab saves never save dirty switch policy.
  assert.equal(await page.getByRole('button',{name:'Save configuration',exact:true}).count(),1);
  const saveConfiguration=async()=>{
    const response=page.waitForResponse(r=>r.url().endsWith('/api/v1/switch/save')&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Save configuration',exact:true}).click();
    assert.equal((await response).status(),200);
    await page.locator('#configuration-status').getByText('Saved',{exact:true}).waitFor();
    assert.equal((await state()).configuration_status.unsaved,false);
  };
  const deniedSaveState=await state();
  assert.equal((await page.request.post(new URL('/api/v1/switch/save',fixtureURL).href,{data:{expected_configuration_revision:deniedSaveState.configuration_revision}})).status(),403);
  assert.deepEqual((await state()).configuration_status,deniedSaveState.configuration_status);
  await saveConfiguration();
  await page.locator('nav button[data-id=vlans]').click();
  await page.getByRole('button',{name:'+ Add VLAN',exact:true}).click();
  await page.getByLabel('VLAN ID',{exact:true}).fill('3099');await page.getByLabel('Name',{exact:true}).fill('Saved browser VLAN');
  await page.getByRole('button',{name:'Apply',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});
  await page.locator('#configuration-status').getByText('Unsaved changes',{exact:true}).waitFor();
  const beforeSave=await state(),saveURL=new URL('/api/v1/switch/save',fixtureURL).href;
  await page.route(saveURL,async route=>{
    const body=route.request().postDataJSON();body.expected_configuration_revision=beforeSave.configuration_revision-1;
    await route.continue({postData:JSON.stringify(body)});
  });
  try{
    const denied=page.waitForResponse(r=>r.url()===saveURL&&r.request().method()==='POST');
    await page.getByRole('button',{name:'Save configuration',exact:true}).click();assert.equal((await denied).status(),409);
    await page.locator('#toast').getByText('Configuration changed while editing; reload and retry',{exact:true}).waitFor();
    assert.deepEqual((await state()).configuration_status,beforeSave.configuration_status);
  }finally{await page.unroute(saveURL);}
  await page.getByRole('button',{name:'Save configuration',exact:true}).focus();
  await page.locator('#save-configuration').evaluate(el=>el.dataset.refreshProbe='waiting');
  await page.waitForFunction(()=>!document.getElementById('save-configuration').dataset.refreshProbe);
  assert.equal(await page.locator('#save-configuration').evaluate(el=>el===document.activeElement),true);
  await saveConfiguration();
  const savedStartup=await state();
  await page.locator('button[data-action=edit-vlan][data-id="3099"]').click();
  await page.getByLabel('Name',{exact:true}).fill('Unsaved browser VLAN');await page.getByRole('button',{name:'Apply',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});
  await page.locator('nav button[data-id=endpoints]').click();
  await page.locator(`button[data-action=edit-endpoint][data-id="${endpoint.id}"]`).click();
  await page.getByLabel('Display name',{exact:true}).fill('Durable browser endpoint');
  await page.getByRole('button',{name:'Save endpoint',exact:true}).click();await page.locator('dialog[open]').waitFor({state:'hidden'});
  const dirtyLab=await state();assert.equal(dirtyLab.configuration_status.unsaved,true);
  assert.equal(dirtyLab.configuration_status.startup_revision,savedStartup.configuration_status.startup_revision);
  await page.locator('nav button[data-id=settings]').click();await page.locator('button[data-action=reboot]').click();
  await page.locator('dialog').getByText(/Discard unsaved switch settings/).waitFor();
  const bootResponse=page.waitForResponse(r=>r.url().endsWith('/api/v1/switch/reboot')&&r.request().method()==='POST');
  await page.locator('dialog').getByRole('button',{name:'Reboot switch',exact:true}).click();assert.equal((await bootResponse).status(),200);await page.locator('dialog[open]').waitFor({state:'hidden'});
  const booted=await state();assert.equal(booted.vlans['3099'].name,'Saved browser VLAN');
  assert.equal(booted.endpoints[endpoint.id].name,'Durable browser endpoint');assert.deepEqual(booted.attachments,dirtyLab.attachments);
  assert.equal(booted.simulation_ms,0);assert.equal(booted.configuration_status.unsaved,false);
  assert.ok(booted.configuration_revision>dirtyLab.configuration_revision);assert.ok(booted.revision>dirtyLab.revision);
  assert.equal((await (await page.request.get(new URL('/api/v1/auth/status',fixtureURL).href)).json()).authenticated,true);
  await page.locator('nav button[data-id=radius]').click();
  console.log('Running/startup browser passed: one global revision-checked Save, Apply versus durable lab Save, dirty/focus refresh, real stale rejection, saved restore with physical edits retained and manager login preserved.');
  const final=await state();assert.equal(final.snmp.enabled,false);assert.equal(final.switch.identity.sys_object_id,null);
  await screenshot('settings.png');
  await page.setViewportSize({width:390,height:844});
  for(const destination of ['snmp','radius','settings']){await page.locator(`nav button[data-id=${destination}]`).click();assert.equal(await page.locator(`nav button[data-id=${destination}]`).getAttribute('aria-current'),'page');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);}
  await page.locator('nav button[data-id=overview]').click();
  assert.equal(await isOpen(),false);
  await simulationSummary.focus();await page.keyboard.press('Space');
  assert.equal(await isOpen(),true);
  const panel=await page.locator('.simulation-panel').boundingBox();
  assert.ok(panel&&panel.x>=0&&panel.x+panel.width<=390&&panel.y>=0&&panel.y+panel.height<=844);
  await page.getByRole('button',{name:'+1s',exact:true}).waitFor();
  await page.getByRole('button',{name:'Advance…',exact:true}).waitFor();
  const mobileBefore=await state();
  await page.getByRole('button',{name:'+1s',exact:true}).click();
  await page.waitForFunction(async before=>(await (await fetch('/api/v1/state')).json()).simulation_ms===before+1000,mobileBefore.simulation_ms);
  await page.keyboard.press('Escape');assert.equal(await isOpen(),false);
  await screenshot('mobile.png');
  if(errors.length)throw new Error(errors.join('\n'));
  if(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth))throw new Error('Mobile page overflows viewport');
  console.log('Browser smoke passed: setup, pause, endpoint creation, attachment, learning, port edit, settings, mobile layout; no page errors.');
  await page.setViewportSize({width:1440,height:1100});
  await page.getByRole('button',{name:'Sign out',exact:true}).click();
  await page.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
  assert.equal(await page.locator('[name=setup_token]').count(),0);
  assert.equal((await page.request.post(new URL('/api/v1/auth/setup',page.url()).href,{data:{password:'not-a-reset'}})).status(),409);
  await page.getByLabel('Administrator password').fill(process.env.SWITCHLAB_TEST_PASSWORD);
  await page.getByRole('button',{name:'Sign in'}).click();
  await page.getByRole('heading',{name:'Switch overview',exact:true}).waitFor();
  console.log('Credential browser checks passed: optional filters, version-only fields and payloads, blank-secret edits, protocol changes, short-password login and setup closure.');
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exit(1);});

