// A periodic state read that started before a change and finishes after it must
// not replace what the change showed, and the next action must still succeed.
const assert = require('node:assert/strict');

module.exports = async ({page}) => {
  const state = () => page.evaluate(async () => (await fetch('/api/v1/state')).json());
  const pause = page.getByRole('button', {name: 'Ⅱ Pause', exact: true});
  const resume = page.getByRole('button', {name: '▶ Resume', exact: true});
  const simulation = page.locator('#simulation');
  if (!await simulation.evaluate(el => el.open)) await simulation.locator('summary').click();
  if ((await state()).paused) { await resume.click(); await pause.waitFor(); }
  const stateURL = new URL('/api/v1/state', page.url()).href;
  let armed = true, captured, release;
  const held = new Promise(resolve => captured = resolve), gate = new Promise(resolve => release = resolve);
  // Answer the next periodic read with the running clock as it is now, but only after the change.
  const holdOldRead = async route => {
    if (!armed || route.request().method() !== 'GET') return route.continue();
    armed = false;
    const old = await route.fetch();
    captured();
    await gate;
    await route.fulfill({response: old});
  };
  await page.route(stateURL, holdOldRead);
  try {
    await held;
    await pause.click();
    await resume.waitFor();
    const oldHistory = page.waitForResponse(r => r.url().endsWith('/api/v1/events?limit=2000'));
    release();
    await oldHistory;
    await page.waitForTimeout(200);
  } finally {
    release();
    await page.unroute(stateURL, holdOldRead);
  }
  assert.equal(await resume.isVisible(), true, 'an older state read replaced the paused clock');
  assert.equal((await state()).paused, true);
  await resume.click();
  await pause.waitFor();
  assert.equal((await state()).paused, false);
  console.log('Refresh order passed: an older periodic read cannot replace a newer change, and the next action succeeds.');
};
