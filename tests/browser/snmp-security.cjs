// Runs in the maintained synthetic loopback fixture with existing users and groups.
const assert = require('node:assert/strict');

module.exports = async function snmpSecurityChecks({page,state,saveForm,editCredential,grouped,groupId,screenshot}) {
  const level=()=>page.getByLabel('Security level',{exact:true});
  const auth=()=>page.getByLabel('Authentication algorithm',{exact:true});
  const priv=()=>page.getByLabel('Encryption algorithm',{exact:true});
  const warning=()=>page.locator('dialog .security-warning');
  const cancel=async()=>{await page.getByRole('button',{name:'Cancel',exact:true}).click();await page.locator('dialog').waitFor({state:'hidden'});};
  const fits=async()=>{
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Page fits viewport');
    assert.ok(await page.locator('dialog .dialog-body').evaluate(el=>el.scrollWidth<=el.clientWidth),'Dialog controls fit');
  };
  const original=(await state()).groups[groupId];
  await editCredential(grouped.label);
  assert.equal(await level().inputValue(),'noAuthNoPriv');
  for(const control of [auth(),priv()]){assert.equal(await control.isVisible(),false);assert.equal(await control.isDisabled(),true);}
  assert.match(await warning().textContent(),/No authentication or encryption/);
  assert.equal(await page.locator('[name=auth_key],[name=priv_key]').count(),0);
  await level().selectOption('authNoPriv');
  assert.equal(await auth().inputValue(),'sha256');assert.equal(await priv().isVisible(),false);
  assert.deepEqual(await auth().locator('option').evaluateAll(els=>els.map(el=>el.value)),['md5','sha1','sha224','sha256','sha384','sha512']);
  assert.deepEqual(await priv().locator('option').evaluateAll(els=>els.map(el=>el.value)),['des','aes128','aes192','aes256']);
  await auth().selectOption('sha512');await page.getByLabel('Authentication passphrase',{exact:true}).fill('synthetic-auth-pass');
  assert.match(await warning().textContent(),/No encryption.*plaintext/);
  let saved=await saveForm('snmp/credentials');
  assert.equal(saved.payload.auth_protocol,'sha512');assert.equal('priv_protocol' in saved.payload,false);assert.equal('priv_key' in saved.payload,false);
  assert.equal((await state()).credentials[grouped.id].priv_protocol,'aes128');
  await editCredential(grouped.label);
  assert.equal(await auth().inputValue(),'sha512');assert.equal(await page.getByLabel('Authentication passphrase',{exact:true}).inputValue(),'');
  await level().selectOption('authPriv');
  for(const value of ['md5','sha1','sha224','sha256','sha384','sha512']){
    await auth().selectOption(value);
    assert.equal(await warning().isVisible(),['md5','sha1'].includes(value));
  }
  await priv().selectOption('des');assert.match(await warning().textContent(),/DES is legacy/);
  await auth().selectOption('md5');assert.match(await warning().textContent(),/MD5 and DES are legacy/);
  await auth().selectOption('sha384');await priv().selectOption('aes256');
  assert.equal(await warning().isVisible(),false);
  for(const value of ['aes192','aes256'])assert.match(await priv().locator(`option[value=${value}]`).textContent(),/extension/);
  await page.getByLabel('Authentication passphrase',{exact:true}).fill('discarded-auth-draft');
  await page.getByLabel('Privacy passphrase',{exact:true}).fill('discarded-priv-draft');
  await level().selectOption('noAuthNoPriv');
  assert.equal(await auth().isDisabled(),true);assert.equal(await priv().isDisabled(),true);
  await level().selectOption('authPriv');
  assert.equal(await auth().inputValue(),'sha384');assert.equal(await priv().inputValue(),'aes256');
  for(const name of ['Authentication passphrase','Privacy passphrase'])assert.equal(await page.getByLabel(name,{exact:true}).inputValue(),'');
  // Blank authentication keeps the saved secret; this user has no saved privacy secret yet.
  await page.getByLabel('Privacy passphrase',{exact:true}).fill('synthetic-priv-pass');
  saved=await saveForm('snmp/credentials');
  assert.equal(saved.payload.auth_protocol,'sha384');assert.equal(saved.payload.priv_protocol,'aes256');assert.equal('auth_key' in saved.payload,false);
  let current=(await state()).credentials[grouped.id];
  assert.equal(current.auth_protocol,'sha384');assert.equal(current.priv_protocol,'aes256');
  assert.deepEqual((await state()).groups[groupId],original);
  const row=()=>page.locator('.setting-row').filter({has:page.locator(`button[data-action=credential][data-id="${grouped.id}"]`)});
  assert.match(await row().textContent(),/SHA-384.*AES-256 \(extension\)/);
  for(const [name,viewport] of [['desktop',{width:1440,height:1100}],['mobile',{width:390,height:844}]]){
    await page.setViewportSize(viewport);await page.evaluate(()=>scrollTo(0,0));
    await screenshot(`snmp-security-${name}.png`);
    await editCredential(grouped.label);await fits();
    assert.equal(await auth().inputValue(),'sha384');assert.equal(await priv().inputValue(),'aes256');
    await screenshot(`snmp-security-user-${name}.png`,false);
    if(name==='mobile'){
      await level().selectOption('authNoPriv');await auth().selectOption('sha1');await fits();
      await screenshot('snmp-security-plaintext-mobile.png',false);
    }
    await cancel();
    await page.locator(`button[data-action=group][data-id="${groupId}"]`).click();await fits();
    assert.equal(await page.getByLabel('Minimum security level',{exact:true}).inputValue(),original.minimum_security_level);
    await screenshot(`snmp-security-group-${name}.png`,false);await cancel();
  }
  // Applying a disabled level omits its algorithms and preserves saved selections.
  await editCredential(grouped.label);await level().selectOption('noAuthNoPriv');
  saved=await saveForm('snmp/credentials');
  for(const key of ['auth_protocol','priv_protocol','auth_key','priv_key'])assert.equal(key in saved.payload,false);
  current=(await state()).credentials[grouped.id];
  assert.equal(current.auth_protocol,'sha384');assert.equal(current.priv_protocol,'aes256');
  assert.match(await row().textContent(),/No auth or encryption/);assert.doesNotMatch(await row().textContent(),/SHA-384|AES-256/);
  await page.setViewportSize({width:1440,height:1100});
  console.log('SNMP security browser checks passed: active algorithms, legacy/plaintext warnings, sparse roundtrips, draft clearing, unchanged group policy, desktop/mobile fit.');
};
