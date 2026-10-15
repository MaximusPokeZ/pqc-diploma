// Render each .fig element of figures.html to figures/figN.png at 3x scale: node render_figures.js
const { chromium } = require('playwright');
const path = require('path');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ deviceScaleFactor: 3, viewport: { width: 700, height: 600 } });
  await p.goto('file://' + path.join(__dirname, 'figures.html'));
  await p.evaluate(() => document.fonts.ready);
  for (const el of await p.$$('.fig')) {
    const id = await el.getAttribute('id');
    await el.screenshot({ path: path.join(__dirname, 'figures', id + '.png') });
  }
  await b.close();
})();
