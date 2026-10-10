"""Records REAL browser interactions with TrustBoundary via its FastAPI TestClient.
Navigation to localhost is blocked in the execution environment; in-process
bridging is used exclusively for the recording (not for the runnable app).
"""
from pathlib import Path
from playwright.sync_api import sync_playwright
from fastapi.testclient import TestClient
from trustboundary.api import app
import json,re,time
root=Path(__file__).resolve().parent.parent
out=root/'submission';out.mkdir(exist_ok=True)
h=(root/'web'/'index.html').read_text(); h=re.sub(r'<link[^>]+stylesheet[^>]+>','',h);h=h.replace('<script src="/assets/app.js"></script>','')
css=(root/'web'/'style.css').read_text().split('\n',1)[1];js=(root/'web'/'app.js').read_text()
client=TestClient(app)
def dispatch(path,method,body):
    try:
        response=client.request(method,path,json=json.loads(body) if body else None)
        return {'ok':response.is_success,'status':response.status_code,'data':response.json()}
    except Exception as e:return {'ok':False,'status':500,'data':{'detail':str(e)}}
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
    context=browser.new_context(viewport={'width':1440,'height':810},record_video_dir=str(out),record_video_size={'width':1440,'height':810})
    page=context.new_page();page.expose_function('backend',dispatch)
    page.set_content(h.replace('</head>','<style>'+css+'</style></head>'),wait_until='domcontentloaded')
    page.evaluate('''window.fetch = async (url,options={}) => {
      const r=await window.backend(String(url),options.method||'GET',options.body||null);
      return {ok:r.ok,status:r.status,json:async()=>r.data};
    };''')
    page.add_script_tag(content=js)
    page.wait_for_function("document.querySelector('#scenario').options.length > 0",timeout=10000)
    page.evaluate("""() => {const b=document.createElement('div');b.id='tb-captions';b.style.cssText='position:fixed;left:268px;bottom:16px;right:35px;min-height:60px;padding:13px 22px;z-index:99999;border-radius:12px;background:rgba(3,13,27,.94);border:1px solid #39d9b0;color:white;font:600 17px Arial;box-shadow:0 10px 35px #000a;pointer-events:none';document.body.appendChild(b)}""")
    def caption(s):page.evaluate('(v) => document.querySelector("#tb-captions").innerText=v',s)
    def wait(s):page.wait_for_timeout(int(s*500))
    def goto(name):page.locator(f'[data-page="{name}"]').click();wait(.6)
    caption('TRUSTBOUNDARY AI v1.4  |  F3-D1  |  Working synthetic prototype')
    wait(9)
    caption('01  Inspect malicious merchant content from a low-trust email')
    page.select_option('#scenario','role');page.click('#scanBtn');wait(12)
    caption('02  Execute the same case against a deliberately insecure scripted control and protected workflow')
    page.click('#compareBtn');page.locator('#comparison:not(.hide)').wait_for(timeout=10000);wait(9)
    page.locator('#comparison').scroll_into_view_if_needed()
    caption('03  Vulnerable scripted control simulates refund; protected agent denies it and completes the ticket')
    wait(14)
    page.evaluate('window.scrollTo(0,0)');page.select_option('#scenario','normal');page.click('#compareBtn');wait(2)
    caption('04  Benign content remains useful. Legitimate support workflow completes without a security incident')
    wait(11)
    page.select_option('#scenario','encoded');page.click('#scanBtn');wait(1)
    caption('05  Encoded instructions are inspected with provenance and redacted evidence spans')
    wait(12)
    goto('evaluation');caption('06  EGO: templated benchmark detects 45/45 attacks; a newly authored 40-case challenge detects only 7/20 attacks')
    wait(15)
    page.evaluate('window.scrollBy(0,490)');caption('07  External-style authored test recall: 35.0 percent; 13 misses and 1 benign false positive — published separately')
    wait(12)
    goto('audit');caption('08  Full audit timeline: classification, policy decision, tool gate and completed execution')
    wait(11)
    goto('evidence');caption('09  F3-D1 evidence map: nine synthetic categories, without a D2 reliability claim')
    wait(10)
    goto('architecture');caption('10  Deterministic authorization is independent of the LLM classifier and cannot be overridden by documents')
    wait(10)
    goto('impact');page.click('#impactBtn');caption('11  Business impact uses an editable hypothetical financial model — no real customer results')
    wait(11)
    goto('lab');caption('TRUSTBOUNDARY AI v1.4  |  Provenance before permission  |  Prototype only')
    wait(7)
    video=page.video
    context.close();browser.close()
    source=Path(video.path())
    dest=out/'TrustBoundary_Demo_Walkthrough.webm'
    source.rename(dest)
print('recorded',dest,'bytes',dest.stat().st_size)
