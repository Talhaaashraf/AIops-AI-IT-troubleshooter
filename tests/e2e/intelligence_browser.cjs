/* Isolated browser contract checks. No server, endpoint, credentials or provider calls.
 * Run with Playwright installed: node tests/e2e/intelligence_browser.cjs
 */
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

async function run(browser, root) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [], calls = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const config = (provider) => ({provider, configured:true, enabled:true, storage:'encrypted-memory',
    policy:{enabled:true,business_authorized:true,upload_authorized:true,use_basis:'Mock permission only',per_minute:4,per_day:500,retry_at:0},
    keys:[{slot:1,primary:true,wait_seconds:0,usage:{minute:0,day:0}}],max_keys:5,
    usage:{minute:0,day:0},connection:{state:'connected',last_success:1},capabilities:{verified:true,environments:[120]}});
  const script = await fs.readFile(path.join(root,'frontend/threat_intelligence.js'),'utf8');
  await page.route('**/*', async (route) => {
    const req=route.request(), url=new URL(req.url()); calls.push({path:url.pathname,method:req.method(),body:req.postData()});
    if (url.pathname === '/') return route.fulfill({contentType:'text/html',body:`<!doctype html><html><head><meta charset="utf-8"></head><body>
      <section id="security"></section><section id="threats"><select id="threat-device"><option value="first">First</option><option value="second">Second</option></select><div id="threat-findings"></div></section>
      <script>const $=(id)=>document.getElementById(id);let threatDeviceId='first';let threatData={scan:{scan_id:'123456abcdef'}};function switchTab(){};function friendlyError(e){return e.message};async function readJson(r){const d=await r.json();if(!r.ok)throw Error(d.detail);return d}</script>
      <script src="/test.js"></script></body></html>`});
    if(url.pathname === '/test.js') return route.fulfill({contentType:'text/javascript',body:script});
    const respond=(data,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(data)});
    if(url.pathname.endsWith('/settings')) return respond(config(url.pathname.split('/')[3]));
    if(url.pathname.includes('/files/')) {
      await new Promise(r=>setTimeout(r,250));
      return respond({job_id:'job',state:'completed',result:{sha256:'a'.repeat(64),classification:'malicious',note:'EXTERNAL-MOCK-REPORT',fetched_at:1,stats:{malicious:3},detections:[{engine:'Test',category:'malicious',result:'<img src=x onerror=alert(1)>'}]}});
    }
    if(url.pathname.includes('/history/')) return respond({files:[],investigations:[]});
    if(url.pathname.includes('/investigations')) return respond({id:'investigation',device:'second',state:'completed',summary:'Evidence collected',evidence:[{tool:'security_hashes',summary:'One hash'}],unfinished:[]});
    if(url.pathname.endsWith('/check-file')) return respond({upload_token:'approval',sha256:'a'.repeat(64),size:3,status:'unknown',note:'Separate approval required'});
    if(url.pathname.includes('/uploads/')) return respond({analysis_token:'approval',sha256:'a'.repeat(64),status:'queued'});
    if(url.pathname.includes('/analyses/')) return respond({analysis_token:'approval',sha256:'a'.repeat(64),status:'completed'});
    return respond({detail:'Mock endpoint not implemented'},404);
  });
  try {
    await page.goto('https://sentinel.test/');
    await page.locator('#threat-intelligence details').first().evaluate(el=>el.open=true);
    await page.getByText('key(s) configured', {exact:false}).first().waitFor();
    await page.locator('#ti-key-virustotal').fill('test-key-not-real');
    await page.locator('[data-show="virustotal"]').click();
    assert.equal(await page.locator('#ti-key-virustotal').getAttribute('type'),'text');
    await page.locator('#ti-config-virustotal button').filter({hasText:'Save / update'}).click();
    await page.waitForFunction(()=>document.getElementById('ti-key-virustotal').value==='');
    const saved=JSON.parse(calls.find(row=>row.path.endsWith('/virustotal/settings')&&row.method==='POST').body);
    assert.equal(saved.business_authorized,true); assert.equal(saved.enabled,true);
    assert.equal(await page.evaluate(()=>JSON.stringify(localStorage)),'{}');
    await page.locator('#ti-hash').fill('a'.repeat(64));
    await page.locator('#ti-search button').click();
    await page.locator('#threat-device').selectOption('second');
    await page.waitForTimeout(400);
    assert.equal(await page.locator('#ti-results').textContent(),'');
    await page.locator('#ti-search button').click();
    await page.getByText('EXTERNAL-MOCK-REPORT',{exact:true}).first().waitFor();
    assert.equal(await page.locator('#ti-results img').count(),0);
    await page.locator('#ti-investigate').click();
    await page.getByText('completed: Evidence collected',{exact:false}).waitFor();
    await page.locator('#threat-intelligence details').nth(1).evaluate(el=>el.open=true);
    await page.locator('#ti-file').setInputFiles({name:'inert.txt',mimeType:'text/plain',buffer:Buffer.from('abc')});
    await page.locator('#ti-file-form button').click();
    await page.locator('#ti-upload').waitFor({state:'visible'});
    assert.equal(calls.filter(row=>row.path.includes('/uploads/')&&row.method==='POST').length,0);
    page.once('dialog',dialog=>dialog.accept());
    await page.locator('#ti-upload').click();
    await page.locator('#ti-analysis').waitFor({state:'visible'});
    assert.equal(calls.filter(row=>row.path.includes('/uploads/')&&row.method==='POST').length,1);
    await page.setViewportSize({width:390,height:844});
    const style=await fs.readFile(path.join(root,'frontend/style.css'),'utf8');
    await page.addStyleTag({content:style});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    assert.deepEqual(errors,[]);
    return {checks:10,passed:10,errors};
  } finally { await context.close(); }
}
module.exports={run};
if(require.main===module) {
  (async()=>{const browser=await require('playwright').chromium.launch({headless:true});try{console.log(await run(browser,path.resolve(__dirname,'../..')));}finally{await browser.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
}
