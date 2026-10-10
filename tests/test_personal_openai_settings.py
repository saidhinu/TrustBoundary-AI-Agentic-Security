"""BYOK tests use synthetic mock keys. They NEVER access a real OpenAI account."""
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from trustboundary.api import app
from trustboundary.detection import Detector

FAKE_KEY='sk-'+'synthetic' * 5
client=TestClient(app)


def test_default_is_offline_even_with_server_key(monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','sk-server-secret-should-not-be-used')
    monkeypatch.setattr(Detector,'_llm_classify',lambda self,text: (_ for _ in ()).throw(AssertionError('Unexpected LLM call')))
    r=client.post('/scan',json={'content':'Merchant settlement ST-2048 pending.'})
    assert r.status_code==200
    assert r.json()['model'] in ('heuristic_plus_local_ml','heuristic_fallback')
    assert client.get('/health').json()['personal_key_supported'] is True
    assert client.get('/health').json()['llm_configured'] is False


def test_user_key_used_per_request_and_not_returned(monkeypatch):
    seen=[]
    def fake(self,text):
        seen.append((self.api_key,self.model_name))
        return ['Tool Abuse']
    monkeypatch.setattr(Detector,'_llm_classify',fake)
    r=client.post('/scan',json={'content':'Merchant settlement ST-2048 pending.'},headers={'x-openai-api-key':FAKE_KEY,'x-openai-model':'gpt-4o-mini'})
    assert r.status_code==200
    assert seen==[(FAKE_KEY,'gpt-4o-mini')]
    assert r.json()['model']=='heuristic_local_ml_plus_llm'
    assert r.json()['disposition']=='QUARANTINE'
    assert FAKE_KEY not in r.text
    assert r.headers['Cache-Control']=='no-store'
    seen.clear()
    other=client.post('/scan',json={'content':'Merchant ST-3091 is settled.'})
    assert other.status_code==200 and not seen
    assert FAKE_KEY not in other.text


def test_test_connection_only_uses_own_key(monkeypatch):
    calls=[]
    def fake(self,text):
        calls.append((self.api_key,self.model_name,text))
        return []
    monkeypatch.setattr(Detector,'_llm_classify',fake)
    r=client.post('/settings/test',json={'model':'gpt-4o-mini'},headers={'x-openai-api-key':FAKE_KEY})
    assert r.status_code==200 and r.json()['connected'] is True
    assert r.json()['key_stored'] is False
    assert calls[0][0]==FAKE_KEY
    assert 'Synthetic merchant' in calls[0][2]
    assert FAKE_KEY not in r.text


@pytest.mark.parametrize('code,expect',[(401,'authentication'),(403,'access'),(429,'quota'),(500,'could not')])
def test_connection_errors_are_safe(monkeypatch,code,expect):
    def fake(self,text):
        raise httpx.HTTPStatusError('secret '+FAKE_KEY,request=httpx.Request('POST','https://api.openai.com/v1/chat/completions'),response=httpx.Response(code,request=httpx.Request('POST','https://api.openai.com/v1/chat/completions')))
    monkeypatch.setattr(Detector,'_llm_classify',fake)
    r=client.post('/settings/test',json={'model':'gpt-4o-mini'},headers={'x-openai-api-key':FAKE_KEY})
    assert r.status_code==502
    assert expect in r.json()['detail'].lower()
    assert FAKE_KEY not in r.text


def test_timeout_and_offline_fallback(monkeypatch):
    def fail(self,text): raise httpx.ReadTimeout('fake timeout')
    monkeypatch.setattr(Detector,'_llm_classify',fail)
    r=client.post('/settings/test',json={'model':'gpt-4o-mini'},headers={'x-openai-api-key':FAKE_KEY})
    assert r.status_code==504
    out=client.post('/scan',json={'content':'Merchant ST-3091 is settled.'},headers={'x-openai-api-key':FAKE_KEY})
    assert out.status_code==200 and out.json()['model']=='heuristic_fallback_llm_unavailable'


def test_force_fallback_must_never_call_hosted(monkeypatch):
    monkeypatch.setattr(Detector,'_llm_classify',lambda self,text: (_ for _ in ()).throw(AssertionError('Unexpected hosted call')))
    r=client.post('/scan',json={'content':'Merchant ST-3091 is settled.','force_fallback':True},headers={'x-openai-api-key':FAKE_KEY})
    assert r.status_code==200 and 'llm' not in r.json()['model']


def test_protected_compare_passes_key_to_protected_run_only(monkeypatch):
    calls=[]
    def fake(self,text):
        calls.append(self.api_key)
        return []
    monkeypatch.setattr(Detector,'_llm_classify',fake)
    task='Summarize settlement ST-3091 only. Do not create a ticket.'
    r=client.post('/agent/compare',json={'content':'Merchant ST-3091 is settled.','task':task},headers={'x-openai-api-key':FAKE_KEY})
    assert r.status_code==200
    assert calls==[FAKE_KEY] and r.json()['protected']['task_completed']
    assert FAKE_KEY not in r.text
    assert not r.json()['protected']['attack_success']


def test_missing_and_invalid_keys():
    missing=client.post('/settings/test',json={'model':'gpt-4o-mini'})
    invalid=client.post('/settings/test',json={'model':'gpt-4o-mini'},headers={'x-openai-api-key':'anything'})
    assert missing.status_code==400 and invalid.status_code==400
    assert client.post('/scan',json={'content':'A status report'},headers={'x-openai-model':'invalid model!'}).status_code==400


def test_frontend_settings_and_no_persistent_browser_storage():
    html=client.get('/').text
    js=client.get('/assets/app.js').text
    assert 'data-page="settings"' in html and 'type="password"' in html
    assert 'Test connection' in html and 'Use key in this tab' in html
    assert 'localStorage' not in js.replace('Never localStorage/sessionStorage/cookies or URL.', '')
    assert 'sessionStorage' not in js.replace('Never localStorage/sessionStorage/cookies or URL.', '')
    assert "personalApiKey=''" in js
