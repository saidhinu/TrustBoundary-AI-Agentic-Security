"""Browser snapshots of actual app frontend + in-process FastAPI backend.
Chromium navigation is restricted in this environment, so set_content + exposed
TestClient handles API calls; all data come from real application code.
"""
from playwright.sync_api import sync_playwright
from fastapi.testclient import TestClient
from trustboundary.api import app
from pathlib import Path
import re,json
root=Path(__file__).resolve().parent.parent
out=root/'submission'/'screenshots';out.mkdir(parents=True,exist_ok=True)
html=(root/'web'/'index.html').read_text()
html=re.sub(r'<link[^>]+stylesheet[^>]+>', '',html)
html=re.sub(r'<script src="/assets/app.js"></script>', '',html)
css=(root/'web'/'style.css').read_text()
js=(root/'web'/'app.js').read_text()
client=TestClient(app)
def dispatch(path,method,body):
    try:
        resp=client.request(method,path,json=json.loads(body) if body else None)
        return {'ok':resp.is_success,'status':resp.status_code,'data':resp.json()}
    except Exception as ex:
        return {'ok':False,'status':500,'data':{'detail':str(ex)}}
with sync_playwright() as p:
 browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
 page=browser.new_page(viewport={'width':1600,'height':1000},device_scale_factor=1)
 page.expose_function('backend',dispatch)
 page.set_content(html.replace('</head>', '<style>'+css.split('\n',1)[1]+'</style></head>'),wait_until='domcontentloaded')
 page.evaluate('''window.fetch = async (url,options={}) => {
  const r=await window.backend(String(url),options.method||'GET',options.body||null);
  return {ok:r.ok,status:r.status,json:async()=>r.data};
 };''')
 page.add_script_tag(content=js)
 page.wait_for_function("document.querySelector('#scenario').options.length > 0",timeout=10000)
 page.screenshot(path=str(out/'01_attack_lab.png'),full_page=True)
 page.select_option('#scenario','role');page.click('#compareBtn');page.locator('#comparison:not(.hide)').wait_for(timeout=15000)
 page.screenshot(path=str(out/'02_before_after.png'),full_page=True)
 page.locator('[data-page="evaluation"]').click();page.wait_for_timeout(500)
 page.screenshot(path=str(out/'03_evaluation.png'),full_page=True)
 page.locator('[data-page="audit"]').click();page.wait_for_timeout(800)
 page.screenshot(path=str(out/'04_audit.png'),full_page=True)
 page.locator('[data-page="impact"]').click();page.click('#impactBtn');page.wait_for_timeout(500)
 page.screenshot(path=str(out/'05_impact.png'),full_page=True)
 page.locator('[data-page="architecture"]').click();page.wait_for_timeout(200)
 page.screenshot(path=str(out/'06_architecture.png'),full_page=True)
 page.locator('[data-page="settings"]').click();page.wait_for_timeout(300)
 page.screenshot(path=str(out/'07_settings.png'),full_page=True)
 browser.close()
print('Captured',len(list(out.glob('0*.png'))),'screenshots of actual app/frontend and TestClient data')
