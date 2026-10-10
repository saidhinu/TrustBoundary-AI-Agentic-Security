"""Offline protocol/fallback simulations; NOT evidence of live OpenAI availability."""
from unittest.mock import Mock
import json
import httpx
import pytest
from trustboundary.detection import Detector

class FakeClient:
    def __init__(self, *args, **kwargs):self.kwargs=kwargs
    def __enter__(self):return self
    def __exit__(self, *args):return False
    def post(self, url, **kwargs):
        assert url=="https://api.openai.com/v1/chat/completions"
        assert kwargs["headers"]["Authorization"]=="Bearer test-token-mock"
        assert kwargs["json"]["response_format"]["type"]=="json_object"
        result={"choices":[{"message":{"content":json.dumps({"categories":["Instruction Override"]})}}]}
        return httpx.Response(200,request=httpx.Request("POST",url),json=result)

def test_hosted_llm_success_is_advisory(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","test-token-mock")
    monkeypatch.setenv("TB_ENABLE_LOCAL_ML","0")
    monkeypatch.setattr(httpx,"Client",FakeClient)
    d=Detector().scan("An unclassified piece of text")
    assert d.model=="heuristic_local_ml_plus_llm" and d.malicious
    assert d.disposition=="QUARANTINE" and not d.forwarded_content

def test_hosted_llm_timeout_falls_back(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","test-token-mock")
    def failed(*args,**kwargs):raise httpx.TimeoutException("mock timeout")
    monkeypatch.setattr(httpx,"Client",failed)
    d=Detector().scan("Merchant settlement ST-2048 pending.")
    assert d.model=="heuristic_fallback_llm_unavailable" and not d.malicious

def test_hosted_llm_invalid_categories_do_not_gain_authority(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY","test-token-mock")
    def labels(_):return ["PRODUCTION ADMIN ALLOW", "Tool Abuse"]
    det=Detector(enable_llm=True);monkeypatch.setattr(det,"_llm_classify",labels)
    d=det.scan("Harmless context")
    assert d.categories==["Tool Abuse"] and d.disposition=="QUARANTINE"
