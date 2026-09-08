// Run against a fresh local instance. Requires Playwright and Chromium.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({headless:true,channel:process.env.SWITCHLAB_BROWSER_CHANNEL||undefined});
  const page = await browser.newPage({viewport:{width:1440,height:1100}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  const screenshots=path.join(__dirname,'../docs/screenshots');fs.mkdirSync(screenshots,{recursive:true});
  await page.goto(process.env.SWITCHLAB_TEST_URL||'http://127.0.0.1:8765');
  await page.getByLabel('Setup token').fill(process.env.SWITCHLAB_TEST_TOKEN);
  await page.getByLabel('Administrator password').fill(process.env.SWITCHLAB_TEST_PASSWORD);
  await page.getByRole('button',{name:'Create administrator'}).click();
  await page.getByRole('heading',{name:'Switch overview',exact:true}).waitFor();
  await page.getByRole('button',{name:'Ⅱ Pause',exact:true}).click();
  await page.getByRole('button',{name:'▶ Resume',exact:true}).waitFor();
  await page.screenshot({path:path.join(screenshots,'overview-empty.png'),fullPage:true});
  await page.locator('nav button[data-id=endpoints]').click();
  await page.getByRole('button',{name:'+ New endpoint',exact:true}).click();
  await page.getByLabel('Display name').fill('Lab workstation');
  await page.getByLabel('MAC address',{exact:true}).fill('02:11:22:33:44:55');
  await page.getByRole('button',{name:'Create endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await page.getByRole('button',{name:'Attach →',exact:true}).click();
  await page.getByRole('button',{name:'Connect endpoint',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await page.getByRole('button',{name:'+1s',exact:true}).click();
  await page.locator('nav button[data-id=fdb]').click();
  await page.getByText('02:11:22:33:44:55',{exact:true}).waitFor();
  await page.screenshot({path:path.join(screenshots,'learned-addresses.png'),fullPage:true});
  await page.locator('nav button[data-id=overview]').click();
  await page.screenshot({path:path.join(screenshots,'overview.png'),fullPage:true});
  await page.getByRole('button',{name:'Configure port',exact:true}).click();
  await page.getByLabel('Alias',{exact:true}).fill('Edited through the browser');
  await page.getByRole('button',{name:'Save changes',exact:true}).click();
  await page.locator('dialog').waitFor({state:'hidden'});
  await page.locator('nav button[data-id=settings]').click();
  await page.screenshot({path:path.join(screenshots,'settings.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.locator('nav button[data-id=overview]').click();
  await page.screenshot({path:path.join(screenshots,'mobile.png'),fullPage:true});
  if(errors.length)throw new Error(errors.join('\n'));
  if(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth))throw new Error('Mobile page overflows viewport');
  console.log('Browser smoke passed: setup, pause, endpoint creation, attachment, learning, port edit, settings, mobile layout; no page errors.');
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1);});

