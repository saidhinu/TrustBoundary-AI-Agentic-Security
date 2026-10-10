"""FastAPI for TrustBoundary demonstrator. Not internet-exposed production service."""
import io,json,os,re,zipfile
import xml.etree.ElementTree as ET
import httpx
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .detection import Detector
from .agent import run,compare,inspect_incident
from .evaluation import evaluate,REPORTS
from .fixtures import SCENARIOS,CATEGORIES,evaluation_dataset
from . import traces
from . import __version__
from .conversation import observe
from .model_agent import compare_model_tool_calls
from collections import defaultdict, deque
from threading import Lock
import time

BASE=Path(__file__).resolve().parent.parent
app=FastAPI(title='TrustBoundary AI',version=__version__,description='Provenance-aware agentic injection firewall; SYNTHETIC sandbox only')
app.mount('/assets',StaticFiles(directory=str(BASE/'web')),name='assets')

class ConnectionTestIn(BaseModel):
 model: str = Field(default='gpt-4o-mini',pattern=r'^[A-Za-z0-9_.-]{1,80}$')

# No key in request bodies, URLs, logs, traces, frontend storage or API responses.
# Header is used only for user-triggered scans. Unauthenticated internet deployment
# still requires HTTPS, authentication, rate limits and standard web protections.
def personal_llm(request:Request):
 key=request.headers.get('x-openai-api-key','')
 model=request.headers.get('x-openai-model','gpt-4o-mini')
 if key and os.getenv('TB_ALLOW_BYOK','1')=='0':
  raise HTTPException(403,'BYOK disabled for this deployment')
 if key and (len(key)>512 or len(key)<16 or not key.startswith('sk-')):
  raise HTTPException(400,'Invalid personal API key format')
 if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',model):
  raise HTTPException(400,'Invalid model name')
 return key,model

_rate_lock=Lock()
_rate_history=defaultdict(deque)

@app.middleware('http')
async def secure_api_headers(request:Request,call_next):
 if os.getenv('TB_PUBLIC_RATE_LIMIT','0')=='1' and request.method=='POST' and request.url.path.startswith(('/scan','/agent','/ingest')):
  address=request.client.host if request.client else 'unknown'
  now=time.monotonic()
  with _rate_lock:
   q=_rate_history[address]
   while q and now-q[0]>60:q.popleft()
   if len(q)>=30: return JSONResponse({'detail':'Demo rate limit exceeded; try again in one minute'},status_code=429)
   q.append(now)
 response=await call_next(request)
 if request.url.path.startswith(('/scan','/agent','/settings')):
  response.headers['Cache-Control']='no-store'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
 return response

class ScanIn(BaseModel):
 content: str = Field(min_length=1,max_length=100000)
 source_type: str = Field(default='email',pattern='^(email|api|html|web|markdown|pdf|text|docx|code|ocr)$')
 force_fallback: bool = False
 conversation_id: str | None = Field(default=None,max_length=64,pattern=r'^[A-Za-z0-9_-]{5,64}$')
class SequenceIn(BaseModel):
 messages: list[str] = Field(min_length=1,max_length=20)

class RunIn(ScanIn):
 role: str = Field(default='merchant_support',pattern='^(merchant_support|compliance_analyst|finance_admin)$')
 task: str = Field(default='Summarize settlement ST-2048 and create a draft support ticket; do not initiate a refund.',max_length=1000)
class ROIIn(BaseModel):
 monthly_requests:int=Field(default=100000,ge=0,le=100000000)
 risk_incident_rate:float=Field(default=.0001,ge=0,le=1)
 average_incident_cost:float=Field(default=250000,ge=0)
 assumed_risk_reduction:float=Field(default=.5,ge=0,le=1)
 manual_review_rate:float=Field(default=.02,ge=0,le=1)
 analyst_minutes:float=Field(default=4,ge=0)
 analyst_hourly_cost:float=Field(default=800,ge=0)
 false_positive_review_rate:float=Field(default=.01,ge=0,le=1)
 estimated_monthly_platform_cost:float=Field(default=20000,ge=0)

@app.get('/')
def index(): return FileResponse(BASE/'web'/'index.html')
@app.get('/health')
def health(): return {'status':'ok','mode':'synthetic_sandbox','llm_configured':False,'personal_key_supported':True,'local_ml_enabled':os.getenv('TB_ENABLE_LOCAL_ML','1')!='0','hosted_validation':'not_run_by_health_check','version':__version__}
@app.get('/scenarios')
def scenarios(): return {'scenarios':SCENARIOS,'categories':CATEGORIES}
@app.post('/settings/test')
def test_personal_key(v:ConnectionTestIn,request:Request):
 key,_=personal_llm(request)
 if not key:raise HTTPException(400,'Enter an OpenAI API key in Settings')
 try:
  categories=Detector(enable_llm=True,api_key=key,model=v.model)._llm_classify('Synthetic merchant settlement ST-2048 is pending. Classify this benign status note.')
  return {'connected':True,'model':v.model,'provider':'openai','categories':categories,'key_stored':False}
 except httpx.TimeoutException:
  raise HTTPException(504,'OpenAI connection timed out; key was not saved') from None
 except httpx.HTTPStatusError as e:
  code=e.response.status_code
  if code==401: detail='OpenAI authentication failed; check or rotate your key'
  elif code==403: detail='OpenAI denied model or project access'
  elif code==429: detail='OpenAI rate limit or quota exceeded'
  else: detail='OpenAI could not complete connection test'
  raise HTTPException(502,detail) from None
 except (httpx.HTTPError,KeyError,ValueError,TypeError,IndexError):
  raise HTTPException(502,'OpenAI connection or response validation failed; offline mode remains available') from None

@app.post('/scan')
def scan(v:ScanIn,request:Request):
 key,model=personal_llm(request)
 return observe(v.conversation_id,v.content,Detector(enable_llm=bool(key),api_key=key,model=model).scan(v.content,v.source_type,v.force_fallback).to_dict())
@app.post('/scan/sequence')
def sequence(v:SequenceIn): return Detector(enable_llm=False).scan_sequence(v.messages)

@app.post('/agent/run')
def agent_run(v:RunIn,request:Request):
 key,model=personal_llm(request)
 return run(v.content,v.source_type,v.role,task=v.task,force_fallback=v.force_fallback,llm_api_key=key,llm_model=model)
@app.post('/agent/compare')
def agent_compare(v:RunIn,request:Request):
 key,model=personal_llm(request)
 return compare(v.content,v.source_type,v.role,v.force_fallback,task=v.task,llm_api_key=key,llm_model=model)
@app.post('/agent/model-compare')
def model_agent_compare(v:RunIn,request:Request):
 key,model=personal_llm(request)
 if not key:raise HTTPException(400,'A personal OpenAI key is required for actual model tool calls; offline comparison remains available')
 try:
  return compare_model_tool_calls(key,model,v.task,v.content,v.source_type,v.role)
 except httpx.TimeoutException: raise HTTPException(504,'Model tool proposal timed out; no action executed') from None
 except httpx.HTTPError: raise HTTPException(502,'Hosted model tool comparison unavailable; no action executed') from None

@app.post('/evaluate')
def eval_endpoint(split:str='heldout'):
 if split not in ('heldout','development','all'): raise HTTPException(400,'Invalid split')
 return evaluate(split=split)
@app.get('/metrics')
def metrics():
 f=REPORTS/'metrics.json'
 return json.loads(f.read_text()) if f.exists() else {'message':'No evaluation run recorded yet. Click Run evaluation.'}
@app.get('/audit/recent')
def audits(): return {'runs':traces.recent()}
@app.get('/traces/{run_id}')
def trace(run_id:str):
 if len(run_id)>100:raise HTTPException(400,'Invalid run ID')
 events=traces.read(run_id)
 if not events: raise HTTPException(404,'Trace not found')
 return {'run_id':run_id,'events':events}
@app.get('/evidence')
def evidence():
 records=[x for x in evaluation_dataset() if x['split']=='heldout' and x['category']]
 return {'source':'synthetic held-out benchmark','minimum_F3_categories':7,'D2_claim_caveat':'High reliability on templated synthetic text is not sufficient to establish generalization or true production D2.',
 'rows':[{'category':cat,'sample_ids':[x['id'] for x in records if x['category']==cat][:5]} for cat in CATEGORIES]}
@app.post('/impact')
def impact(v:ROIIn):
 baseline_cost=v.monthly_requests*v.risk_incident_rate*v.average_incident_cost
 avoided=baseline_cost*v.assumed_risk_reduction
 review_cost=v.monthly_requests*v.manual_review_rate*(v.analyst_minutes/60)*v.analyst_hourly_cost
 fp_cost=v.monthly_requests*v.false_positive_review_rate*(v.analyst_minutes/60)*v.analyst_hourly_cost
 return {'baseline_monthly_expected_loss_inr':round(baseline_cost), 'assumed_monthly_loss_avoided_inr':round(avoided),
 'monthly_review_cost_inr':round(review_cost),'monthly_false_positive_review_cost_inr':round(fp_cost),
 'monthly_platform_cost_inr':round(v.estimated_monthly_platform_cost),
 'modeled_monthly_net_benefit_inr':round(avoided-review_cost-fp_cost-v.estimated_monthly_platform_cost),
 'disclaimer':'HYPOTHETICAL BUSINESS SCENARIO. Not actual customer outcomes; assumptions are editable and do not derive from the synthetic benchmark.'}
def extract_docx_text(data: bytes) -> str:
    """Extract document, header, footer and comment text, including hidden w:vanish runs.

    OOXML text-run extraction deliberately includes hidden text rather than
    relying on what Word renders. This does not execute macros or field code.
    """
    from docx import Document
    Document(io.BytesIO(data))  # validate package structure using python-docx
    namespace='{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
    extracted=[]
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names=[n for n in archive.namelist() if n=='word/document.xml' or
              re.fullmatch(r'word/(?:header\d+|footer\d+|comments)\.xml',n)]
        for name in names:
            xml=ET.fromstring(archive.read(name))
            # Every w:t is read, even when parent w:rPr contains w:vanish.
            parts=[node.text or '' for node in xml.iter() if node.tag in (namespace+'t',namespace+'instrText')]
            if parts:extracted.append(' '.join(parts))
    return '\n'.join(extracted)

def extract_image_text(data:bytes)->str:
    """OCR image text; never run embedded code, scripts, or shell commands."""
    from PIL import Image,ImageOps,ImageEnhance
    import pytesseract
    with Image.open(io.BytesIO(data)) as img:
        if img.width*img.height>18_000_000: raise HTTPException(413,'Image pixel limit exceeded')
        gray=ImageOps.autocontrast(ImageOps.grayscale(img))
        gray=ImageEnhance.Contrast(gray).enhance(2.2)
        gray=gray.resize((min(gray.width*2,5000),min(gray.height*2,5000)))
        return pytesseract.image_to_string(gray,config='--psm 6')[:100000]

def extract_scanned_pdf(data:bytes)->str:
    try:
        import fitz
        doc=fitz.open(stream=data,filetype='pdf')
        result=[]
        for page in list(doc)[:8]:
            pix=page.get_pixmap(matrix=fitz.Matrix(2,2),alpha=False)
            from PIL import Image
            img=Image.frombytes('RGB',[pix.width,pix.height],pix.samples)
            out=io.BytesIO();img.save(out,format='PNG')
            result.append(extract_image_text(out.getvalue()))
        return '\n'.join(result)
    except ImportError:
        return ''

@app.post('/ingest/file')
async def ingest_file(file:UploadFile=File(...)):
 raw=await file.read(5_000_001)
 if len(raw)>5_000_000:raise HTTPException(413,'File exceeds 5 MB sandbox limit')
 filename=Path(file.filename or 'unknown').name.lower()
 if filename.endswith(('.png','.jpg','.jpeg')):
  try:
   text=extract_image_text(raw);source='ocr'
   if not text.strip(): raise HTTPException(422,'OCR found no readable text')
  except HTTPException: raise
  except Exception as exc: raise HTTPException(422,'Could not OCR image') from exc
 elif filename.endswith('.pdf'):
  try:
   from pypdf import PdfReader
   r=PdfReader(io.BytesIO(raw));text='\n'.join((p.extract_text() or '') for p in r.pages[:25]); source='pdf'
   if not text.strip():
    text=extract_scanned_pdf(raw);source='ocr'
   if not text.strip():return JSONResponse({'error':'Image-only PDF produced no readable OCR text'},status_code=422)
  except Exception as exc:raise HTTPException(422,'Could not parse the supplied PDF') from exc
 elif filename.endswith('.docx'):
  try:
   text=extract_docx_text(raw);source='docx'
   if not text.strip():raise ValueError('Empty DOCX')
  except (ValueError,ET.ParseError,zipfile.BadZipFile,KeyError) as exc:
   raise HTTPException(422,'Could not extract DOCX text') from exc
 elif filename.endswith(('.py','.js')):
  # Ingest the whole source, including Python docstrings, JS/Python comments
  # and string literals; no code is imported or executed.
  text=raw.decode('utf-8',errors='replace');source='code'
 elif filename.endswith(('.txt','.md','.html','.htm','.eml','.json')):
  text=raw.decode('utf-8',errors='replace');source=('html' if filename.endswith(('.html','.htm')) else 'api' if filename.endswith('.json') else 'email' if filename.endswith('.eml') else 'markdown' if filename.endswith('.md') else 'text')
 else:raise HTTPException(415,'Supported: PDF, DOCX, PNG, JPG, PY, JS, TXT, MD, HTML, EML, JSON')
 return {'filename':filename,'source_type':source,'content':text[:100000],'characters':len(text),'truncated':len(text)>100000}
