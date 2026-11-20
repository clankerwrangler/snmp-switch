const assert = require('node:assert/strict');

module.exports = async ({page}) => {
  const url = path => new URL('/api/v1'+path, page.url()).href;
  const state = async () => (await page.request.get(url('/state'))).json();
  // Earlier smoke cases may remove the default read view. Restore the fresh-setup fixture.
  if(!(await state()).views.all){
    const origin = new URL(page.url()).origin;
    const auth = await (await page.request.get(url('/auth/status'))).json();
    const revision = (await state()).configuration_revision;
    const restored = await page.request.post(url('/snmp/views'),{
      headers:{Origin:origin,'X-CSRF-Token':auth.csrf_token},
      data:{id:'all',name:'iso',includes:['1'],expected_configuration_revision:revision}});
    assert.equal(restored.status(),200);
    await page.reload();
    await page.locator('#nav-snmp').waitFor();
  }
  const initial = await state();
  let listenerReady = false, saves = 0;
  // The browser fixture forbids UDP. Only stand in for listener reconciliation/status;
  // the identity, credential, and startup writes go through the actual API.
  const settings = async route => {
    if(route.request().method()!=='PATCH') return route.continue();
    const current = await state();
    return route.fulfill({json:{configuration_revision:current.configuration_revision}});
  };
  const listener = route => route.fulfill({json:{ready:listenerReady, listener_ready:listenerReady,
    reason:listenerReady?'ready':'listener_bind_failed'}});
  const save = route => {saves++;return route.continue();};
  await page.route(url('/snmp/settings'),settings);
  await page.route(url('/snmp/status'),listener);
  await page.route(url('/switch/save'),save);
  try {
    await page.locator('nav button[data-id=snmp]').click();
    const open = () => page.locator('#snmp-quick-setup').getByRole('button',{name:'Set up SNMP',exact:true}).click();
    const dialog = page.getByRole('dialog');
    const submit = () => dialog.getByRole('button',{name:'Set up SNMP',exact:true}).click();
    await open();
    await dialog.getByLabel('System object ID (sysObjectID)').fill('2.999.123');
    await dialog.getByLabel('Read-only community').fill('synthetic-quick-setup');
    await submit();
    await dialog.getByRole('alert').filter({hasText:'Could not bind the SNMP listener'}).waitFor();
    assert.equal(saves,0,'a failed listener must not be saved to startup');
    const failed = await state();
    assert.equal(failed.configuration_status.startup_revision,initial.configuration_status.startup_revision);
    const [id,...extra] = Object.keys(failed.credentials).filter(id=>!(id in initial.credentials));
    assert.ok(id);assert.deepEqual(extra,[]);
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
    listenerReady=true;
    await open();
    await dialog.getByLabel('Read-only community').fill('synthetic-corrected-quick-setup');
    await submit();
    await dialog.waitFor({state:'hidden'});
    await page.locator('#toast').filter({hasText:'SNMP is set up and saved'}).waitFor();
    const saved = await state();
    assert.equal(saves,1);
    assert.equal(saved.configuration_status.unsaved,false);
    assert.ok(saved.configuration_status.startup_revision>initial.configuration_status.startup_revision);
    assert.deepEqual(Object.keys(saved.credentials).filter(id=>!(id in initial.credentials)),[id]);
    assert.equal(saved.credentials[id].polling.enabled,true);
    assert.equal(saved.credentials[id].writing.enabled,false);
    console.log('Quick SNMP setup passed: bind failure avoids Save, correction reuses the community, and ready setup saves.');
  } finally {
    await page.unroute(url('/snmp/settings'),settings);
    await page.unroute(url('/snmp/status'),listener);
    await page.unroute(url('/switch/save'),save);
  }
};
