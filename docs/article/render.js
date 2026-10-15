// Render article.print.html to A4 PDF + PNG preview: node render.js <dir>
const { chromium } = require('playwright');
(async () => {
  const dir = process.argv[2];
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 794, height: 1123 }, deviceScaleFactor: 2 });
  await p.goto('file://' + dir + '/article.print.html');
  await p.evaluate(() => document.fonts.ready);
  console.log(JSON.stringify(await p.evaluate(() => {
    const c = document.querySelector('.cols'), f = document.querySelector('.foot');
    return { colsTop: c.getBoundingClientRect().top, colsBottom: c.getBoundingClientRect().bottom,
             footTop: f.getBoundingClientRect().top, overflowX: c.scrollWidth - c.clientWidth };
  })));
  await p.screenshot({ path: dir + '/article-preview.png' });
  await p.pdf({ path: dir + '/article.pdf', format: 'A4', printBackground: true, preferCSSPageSize: true });
  await b.close();
})();
