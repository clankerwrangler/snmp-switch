// Runs inside the maintained synthetic loopback browser launcher, after its admin flow.
const assert = require('node:assert/strict');

module.exports = async function managementChecks({page,browser,fixtureURL,password}) {
  const origin=new URL(fixtureURL).origin;
  assert.equal(new URL(origin).hostname,'127.0.0.1','Only the owned synthetic fixture is permitted');
  const context=await browser.newContext({viewport:{width:1440,height:1100}});
  const viewer=await context.newPage(),errors=[];
  viewer.setDefaultTimeout(10000);
  viewer.on('pageerror',error=>errors.push(error.message));
  await viewer.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
  const status=async target=>await (await target.request.get(origin+'/api/v1/auth/status')).json();
  const settings=async()=>await (await page.request.get(origin+'/api/v1/management/viewer')).json();
  const state=async()=>await (await page.request.get(origin+'/api/v1/state')).json();
  const openSettings=async()=>{
    await page.locator('nav [data-id=settings]').click();
    await page.getByRole('button',{name:'Manage viewer access',exact:true}).click();
    await page.locator('dialog').getByRole('heading',{name:'Local viewer access',exact:true,level:2}).waitFor();
  };
  const save=async()=>{
    await page.getByRole('button',{name:'Save viewer access',exact:true}).click();
    await page.locator('dialog[open]').waitFor({state:'hidden'});
  };
  const login=async secret=>{
    await viewer.getByRole('combobox',{name:'Account',exact:true}).selectOption('local-viewer');
    await viewer.getByLabel('Viewer password',{exact:true}).fill(secret);
    await viewer.getByLabel('Viewer password',{exact:true}).press('Enter');
    await viewer.locator('.session-role').filter({hasText:'Local viewer · Read only'}).waitFor();
  };
  const firstPassword='synthetic-viewer-first',secondPassword='synthetic-viewer-rotated';
  const uiWrites=[];
  const collect=request=>{if(new URL(request.url()).pathname.startsWith('/api/v1/')&&!['GET','HEAD'].includes(request.method()))uiWrites.push(request);};
  viewer.on('request',collect);
  try {
    assert.equal((await status(page)).role,'admin');
    const initial=await settings();
    assert.deepEqual(Object.keys(initial).sort(),['enabled','generation','password_configured']);
    assert.equal(initial.enabled,false);assert.equal(initial.password_configured,false);
    await viewer.goto(fixtureURL);
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await viewer.getByRole('combobox',{name:'Account',exact:true}).waitFor({state:'visible'});
    assert.deepEqual(await viewer.getByRole('combobox',{name:'Account',exact:true}).locator('option').allTextContents(),['Local administrator']);
    assert.equal(await viewer.getByLabel('Administrator password').inputValue(),'');

    // Optional access is disabled initially; abandoned secrets never survive reopening.
    await openSettings();
    assert.equal(await page.getByLabel('Enable viewer sign-in').isChecked(),false);
    await page.getByLabel('Enable viewer sign-in').check();
    assert.equal(await page.getByLabel('Viewer password',{exact:true}).evaluate(el=>el.checkValidity()),false);
    await page.getByLabel('Viewer password',{exact:true}).fill('synthetic-abandoned');
    await page.getByRole('button',{name:'Cancel',exact:true}).click();
    assert.deepEqual(await settings(),initial);
    await openSettings();
    assert.equal(await page.getByLabel('Viewer password',{exact:true}).inputValue(),'');
    await page.getByLabel('Enable viewer sign-in').check();
    await page.getByLabel('Viewer password',{exact:true}).fill(firstPassword);
    const configurationBefore=(await state()).configuration_revision;
    await save();
    assert.equal((await settings()).enabled,true);
    assert.equal((await settings()).password_configured,true);
    assert.equal((await state()).configuration_revision,configurationBefore,'Management generation is independent of simulation edits');

    await viewer.reload();
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await viewer.getByRole('combobox',{name:'Account',exact:true}).waitFor({state:'visible'});
    assert.deepEqual(await viewer.getByRole('combobox',{name:'Account',exact:true}).locator('option').allTextContents(),['Local administrator','Local viewer']);
    await viewer.getByLabel('Administrator password').fill('synthetic-discard-on-account-change');
    await viewer.getByRole('combobox',{name:'Account',exact:true}).selectOption('local-viewer');
    assert.equal(await viewer.getByLabel('Viewer password',{exact:true}).inputValue(),'');
    await viewer.getByLabel('Viewer password',{exact:true}).fill('synthetic-wrong-password');
    await viewer.getByLabel('Viewer password',{exact:true}).press('Enter');
    await viewer.locator('.form-error').filter({hasText:'Invalid credentials'}).waitFor();
    assert.equal(await viewer.getByLabel('Viewer password',{exact:true}).inputValue(),'');
    await login(firstPassword);
    const viewerAuth=await status(viewer);
    assert.equal(viewerAuth.provider,'local-viewer');
    assert.deepEqual([...viewerAuth.permissions].sort(),['scenario:export','state:read']);
    const readOnlyActions=new Set(['nav','select-port','event-port','event-client','event-endpoint','event-latest','event-next','event-previous','export','logout']);
    const beforeBrowsing=uiWrites.length;
    for(const destination of ['overview','endpoints','vlans','fdb','interfaces','events','snmp','radius','settings']) {
      const nav=viewer.locator(`nav [data-id=${destination}]`);
      await nav.focus();await viewer.keyboard.press('Enter');
      assert.equal(await nav.getAttribute('aria-current'),'page');
      for(const action of await viewer.locator('[data-action]').evaluateAll(elements=>elements.map(el=>el.dataset.action)))assert.ok(readOnlyActions.has(action),'Viewer mutation affordance: '+action);
      assert.equal(await viewer.locator('dialog[open],#viewer-access').count(),0);
    }
    // Interface names and attachment links remain usable read-only port navigation.
    await viewer.locator('nav [data-id=interfaces]').click();
    const portLink=viewer.locator('table button[data-action=event-port]').first();
    if(await portLink.count()){await portLink.click();assert.equal(await viewer.locator('nav [data-id=overview]').getAttribute('aria-current'),'page');}
    await viewer.locator('#simulation-summary').focus();await viewer.keyboard.press('Enter');
    assert.equal(await viewer.locator('.simulation-time').isVisible(),true);
    assert.equal(await viewer.locator('#simulation [data-action]').count(),0);
    await viewer.keyboard.press('Escape');
    await viewer.locator('nav [data-id=events]').click();
    await viewer.getByRole('combobox',{name:'Category',exact:true}).selectOption('System');
    await viewer.getByLabel('Search',{exact:true}).fill('port');
    await viewer.getByLabel('Search',{exact:true}).fill('');
    await viewer.getByRole('combobox',{name:'Category',exact:true}).selectOption('');
    const event=viewer.locator('#event-history .event-disclosure > summary').first();
    if(await event.count()){await event.focus();await viewer.keyboard.press('Enter');assert.equal(await event.evaluate(el=>el.parentElement.open),true);}
    assert.equal(uiWrites.length,beforeBrowsing,'Viewer navigation and details send no writes');

    // Recreated/keyboard-triggered mutation controls cannot bypass the action owner.
    await viewer.evaluate(()=>{
      for(const action of ['new-port','new-endpoint','pause','resume','advance','advance1','cancel-advance','save-configuration','import','viewer-access','switch-settings','reboot','credential','radius-settings','clear']){
        const el=document.createElement('button');el.dataset.action=action;document.querySelector('#app').append(el);el.click();el.remove();
      }
      const el=document.createElement('button');el.id='denied-keyboard';el.dataset.action='new-port';el.textContent='Injected stale action';document.querySelector('#app').append(el);
    });
    await viewer.locator('#denied-keyboard').focus();await viewer.keyboard.press('Enter');
    await viewer.locator('#denied-keyboard').evaluate(el=>el.remove());
    assert.equal(await viewer.locator('dialog[open]').count(),0);
    assert.equal(uiWrites.length,beforeBrowsing,'Direct DOM action paths send no writes');

    // The server remains authoritative, including when bypassing the UI entirely.
    const denied=await viewer.request.post(origin+'/api/v1/clock/pause',{headers:{Origin:origin,'X-CSRF-Token':viewerAuth.csrf_token},data:{expected_configuration_revision:configurationBefore}});
    assert.equal(denied.status(),403);
    assert.equal((await viewer.request.get(origin+'/api/v1/management/viewer')).status(),403);
    assert.equal((await viewer.request.put(origin+'/api/v1/management/viewer',{headers:{Origin:origin,'X-CSRF-Token':viewerAuth.csrf_token},data:{expected_generation:(await settings()).generation,enabled:false}})).status(),403);
    assert.equal((await state()).configuration_revision,configurationBefore);

    // Read-only scenario export and essential session actions remain usable on mobile.
    await viewer.setViewportSize({width:390,height:844});
    for(const destination of ['overview','events','snmp','radius','settings']){
      await viewer.locator(`nav [data-id=${destination}]`).click();
      assert.equal(await viewer.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    }
    assert.equal(await viewer.locator('.session-role').isVisible(),true);
    assert.equal(await viewer.getByRole('button',{name:'Sign out',exact:true}).isVisible(),true);
    const downloadPromise=viewer.waitForEvent('download');
    await viewer.getByRole('button',{name:'↗ Export scenario',exact:true}).click();
    const download=await downloadPromise,stream=await download.createReadStream(),chunks=[];
    for await (const chunk of stream)chunks.push(chunk);
    const exported=Buffer.concat(chunks).toString('utf8');
    assert.ok(JSON.parse(exported));assert.equal(exported.includes(firstPassword),false);assert.equal(exported.includes('password_hash'),false);
    assert.equal(uiWrites.length,beforeBrowsing);

    // Revoke between initial status and state reads: the failed loading promise must
    // settle before recovery opens a fresh sign-in flow, rather than a blank shell.
    let revokeOnLoad=true;
    const revokeDuringLoad=async route=>{
      if(revokeOnLoad){
        revokeOnLoad=false;
        const admin=await status(page),current=await settings();
        const response=await page.request.put(origin+'/api/v1/management/viewer',{headers:{Origin:origin,'X-CSRF-Token':admin.csrf_token},data:{expected_generation:current.generation,enabled:true}});
        assert.equal(response.status(),200);
      }
      await route.continue();
    };
    await viewer.route('**/api/v1/state',revokeDuringLoad);
    try {
      await viewer.reload();
      await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
      assert.equal(revokeOnLoad,false,'Exercise the initial state-read revocation');
    } finally {await viewer.unroute('**/api/v1/state',revokeDuringLoad);}
    await login(firstPassword);

    // Concurrent generation conflict stays visible and does not silently replay a secret.
    await openSettings();
    assert.equal(await page.getByLabel('New viewer password (blank = unchanged)',{exact:true}).inputValue(),'');
    const admin=await status(page),current=await settings();
    const concurrent=await page.request.put(origin+'/api/v1/management/viewer',{headers:{Origin:origin,'X-CSRF-Token':admin.csrf_token},data:{expected_generation:current.generation,enabled:true}});
    assert.equal(concurrent.status(),200);
    await page.getByLabel('New viewer password (blank = unchanged)',{exact:true}).fill('synthetic-stale-not-applied');
    await page.getByRole('button',{name:'Save viewer access',exact:true}).click();
    await page.locator('dialog .form-error').filter({hasText:'Close and reopen'}).waitFor();
    assert.equal(await page.getByLabel('New viewer password (blank = unchanged)',{exact:true}).inputValue(),'');
    await page.getByRole('button',{name:'Cancel',exact:true}).click();
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await login(firstPassword);

    // Password rotation revokes live viewers even while a search input has focus.
    await viewer.locator('nav [data-id=endpoints]').click();await viewer.getByLabel('Search endpoints').fill('synthetic');
    await openSettings();
    await page.getByLabel('New viewer password (blank = unchanged)',{exact:true}).fill(secondPassword);
    await save();
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    await login(secondPassword);
    await viewer.getByRole('button',{name:'Sign out',exact:true}).click();
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.equal((await status(viewer)).authenticated,false);
    await login(secondPassword);

    // Disabling removes the provider and current session without affecting admin recovery.
    await openSettings();await page.getByLabel('Enable viewer sign-in').uncheck();await save();
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.deepEqual(await viewer.getByRole('combobox',{name:'Account',exact:true}).locator('option').allTextContents(),['Local administrator']);
    assert.equal((await settings()).enabled,false);assert.equal((await settings()).password_configured,true);
    assert.equal((await status(page)).role,'admin');
    await page.setViewportSize({width:1280,height:600});
    await page.getByRole('button',{name:'Sign out',exact:true}).scrollIntoViewIfNeeded();
    const logoutBounds=await page.getByRole('button',{name:'Sign out',exact:true}).boundingBox();
    assert.ok(logoutBounds.y>=0&&logoutBounds.y+logoutBounds.height<=600,'Session actions remain reachable in short desktop windows');
    await page.setViewportSize({width:1440,height:1100});
    // The legacy password-only API still identifies the administrator, never the viewer.
    const legacy=await viewer.request.post(origin+'/api/v1/auth/login',{data:{password}});
    assert.equal(legacy.status(),200);assert.equal((await legacy.json()).role,'admin');
    await viewer.reload();await viewer.locator('.session-role').filter({hasText:'Local administrator'}).waitFor();
    assert.equal(await viewer.getByRole('button',{name:'+ Add port',exact:true}).isVisible(),true);
    assert.equal((await state()).configuration_revision,configurationBefore);
    // Session observation continues while a secret editor is open and owns focus.
    await viewer.locator('nav [data-id=settings]').click();
    await viewer.getByRole('button',{name:'Manage viewer access',exact:true}).click();
    await viewer.getByLabel('New viewer password (blank = unchanged)',{exact:true}).fill('synthetic-expired-draft');
    const editorAuth=await status(viewer);
    assert.equal((await viewer.request.post(origin+'/api/v1/auth/logout',{headers:{Origin:origin,'X-CSRF-Token':editorAuth.csrf_token},data:{}})).status(),200);
    await viewer.getByRole('heading',{name:'Sign in',exact:true}).waitFor();
    assert.equal(await viewer.locator('dialog[open],dialog input').count(),0);
    assert.equal(await viewer.getByLabel('Administrator password').inputValue(),'');
    assert.deepEqual(errors,[]);
    console.log('Management browser passed: disabled-by-default local viewer, explicit account/role, keyboard/read-only navigation/details/events/export, mobile session actions, denied UI/direct writes, independent generation conflict, secret disposal, rotation/revocation and administrator recovery.');
  } finally {
    viewer.off('request',collect);
    await context.close();
  }
};
