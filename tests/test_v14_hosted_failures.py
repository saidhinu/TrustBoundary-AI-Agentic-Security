"""Mocked API protocol tests, not claims about OpenAI network connectivity."""
import json,pytest,httpx
from trustboundary.detection import Detector

@pytest.mark.parametrize('status',[401,429,503])
def test_hosted_api_http_errors_fall_back(monkeypatch,status):
 monkeypatch.setenv('OPENAI_API_KEY','synthetic-test-only')
 monkeypatch.setenv('TB_ENABLE_LOCAL_ML','0')
 class F:
  def __init__(self,*a,**kw):pass
  def __enter__(self):return self
  def __exit__(self,*a):return False
  def post(self,url,**kw):return httpx.Response(status,request=httpx.Request('POST',url),text='test')
 monkeypatch.setattr(httpx,'Client',F)
 result=Detector().scan('Merchant ST-3091 status settled.')
 assert result.model=='heuristic_fallback_llm_unavailable'
 assert not result.malicious

@pytest.mark.parametrize('payload',[{'not_categories':[]},{'categories':'Invalid'},{'categories':[123]}])
def test_hosted_invalid_response_fallback(monkeypatch,payload):
 monkeypatch.setenv('OPENAI_API_KEY','synthetic-test-only')
 monkeypatch.setenv('TB_ENABLE_LOCAL_ML','0')
 class F:
  def __init__(self,*a,**kw):pass
  def __enter__(self):return self
  def __exit__(self,*a):return False
  def post(self,url,**kw):
   return httpx.Response(200,request=httpx.Request('POST',url),json={'choices':[{'message':{'content':json.dumps(payload)}}]})
 monkeypatch.setattr(httpx,'Client',F)
 result=Detector().scan('Merchant ST-3091 status settled.')
 assert result.model=='heuristic_fallback_llm_unavailable'
 assert not result.malicious

def test_hosted_false_positive_is_measurable(monkeypatch):
 monkeypatch.setenv('TB_ENABLE_LOCAL_ML','0')
 d=Detector(enable_llm=True)
 monkeypatch.setattr(d,'_llm_classify',lambda _:['Tool Abuse'])
 out=d.scan('Merchant ST-3091 is settled.')
 assert out.malicious and out.disposition=='QUARANTINE'
 assert out.model=='heuristic_local_ml_plus_llm'

def test_hosted_no_key_is_offline(monkeypatch):
 monkeypatch.delenv('OPENAI_API_KEY',raising=False)
 assert not Detector().enable_llm
