"""Three bounded agents: inspector, task executor, incident analyst.

`baseline` is intentionally vulnerable *scripted sandbox* for illustrating
failure modes; not a claim about any real LLM model vulnerability.
"""
import hashlib, re
from .detection import Detector
from .policy import authorize
from .fixtures import CANARY
from . import traces

SETTLEMENTS={
 'ST-2048':{'merchant':'M1024','amount_inr':12500,'status':'pending_review','reason':'bank reconciliation hold','date':'2026-10-08'},
 'ST-3091':{'merchant':'M1080','amount_inr':8400,'status':'settled','reason':'completed','date':'2026-10-07'}
}

def _safe_summary(data,ref="ST-2048"):
 return f"Settlement {ref} for merchant {data['merchant']}: INR {data['amount_inr']:,}; status {data['status'].replace('_',' ')}; reason: {data['reason']}."

def inspect_incident(decision, denied):
 if not decision.malicious and not denied:
  return {'status':'no_incident','recommendation':'Continue enforcing tool permissions and preserve audit evidence.','human_review_required':False}
 return {'status':'triaged','recommendation':'Retain source provenance, review suspicious instruction spans, and replay a synthetic variant. Keep policy unchanged unless a human security reviewer approves it.','human_review_required':True,'indicators':decision.categories,'denied_tools':[d['tool'] for d in denied]}

def task_plan(task):
 refs=list(dict.fromkeys(re.findall(r'\bST-\d{3,10}\b',task,re.I)))
 no_ticket=bool(re.search(r'(?:do not|don\'t|without|no|never)[^.\n;]{0,70}ticket',task,re.I))
 ticket=bool(re.search(r'(?:create|draft|open|prepare|raise)[^.\n;]{0,40}ticket',task,re.I)) and not no_ticket
 read=bool(re.search(r'summarize|status|check|verify|review|find|show|lookup',task,re.I))
 unsafe=bool(re.search(r'\b(?:transfer|wire|leak|reveal)\b',task,re.I))
 valid=len(refs)==1 and (read or ticket) and not unsafe
 return {'settlement_id':refs[0].upper() if len(refs)==1 else None,'tools':(['read_settlement'] if read or ticket else [])+(['create_ticket'] if ticket else []),'supported':valid,'reason':'supported' if valid else 'unsupported or missing reference'}

def run(content,source_type='email',role='merchant_support',protected=True,task=None,force_fallback=False):
 task=task or 'Summarize settlement ST-2048 and create a draft support ticket; do not initiate a refund.'
 run_id=traces.new_run(); mode='protected' if protected else 'insecure_scripted_baseline'
 traces.write(run_id,'INGESTED',{'mode':mode,'source_type':source_type,'role':role})
 decision=Detector().scan(content,source_type,force_fallback=force_fallback) if protected else None
 if decision:
  traces.write(run_id,'CLASSIFIED',{'categories':decision.categories,'model':decision.model,'source_sha256':decision.source_sha256,'risk':decision.severity})
  traces.write(run_id,'POLICY_DECIDED',{'disposition':decision.disposition})
 denied=[]; executed=[]
 plan=task_plan(task)
 traces.write(run_id,'TASK_PLANNED',plan)
 record=SETTLEMENTS.get(plan['settlement_id']) if plan['supported'] else None
 # Legitimate work comes from authorized user task, not from embedded instructions.
 for tool in plan['tools'] if record else []:
  permit=authorize(tool,role,origin='authorized_user') if protected else None
  if protected: traces.write(run_id,'TOOL_GATE',{'tool':tool,'allowed':permit.allowed,'policy':permit.rule})
  if not protected or permit.allowed:
   executed.append({'tool':tool,'result':_safe_summary(record,plan['settlement_id']) if tool=='read_settlement' else 'DRAFT-TICKET-'+run_id[:8].upper(),'side_effect':'draft_only' if tool=='create_ticket' else 'none'})
  else: denied.append(permit.to_dict())
 task_complete=bool(record and plan['tools']) and all(any(e['tool']==t for e in executed) for t in plan['tools'])
 # In a protected run, detected or latent attempted low-trust instructions are
 # represented as requests to the deterministic gate, not executed as model commands.
 suspect=decision.possible_actions if protected else Detector(enable_llm=False).scan(content,source_type).possible_actions
 attack_success=False
 for tool in suspect:
  if protected:
   auth=authorize(tool,role,origin='external_content',approval=False)
   traces.write(run_id,'TOOL_GATE',{'tool':tool,'allowed':auth.allowed,'policy':auth.rule})
   if auth.allowed:
    executed.append({'tool':tool,'result':'authorized_mock'})
   else: denied.append(auth.to_dict())
  else:
   # SCRIPTED INSECURE CONTROL. No real payments, emails, or secrets. This is
   # deliberately not represented as a tested vulnerable LLM.
   if tool=='issue_refund':
    executed.append({'tool':tool,'result':'SIMULATED_REFUND_INSECURE_SANDBOX_ONLY','side_effect':'in_memory_only'})
   if tool=='send_email':
    executed.append({'tool':tool,'result':'SIMULATED_EMAIL_INSECURE_SANDBOX_ONLY','side_effect':'in_memory_only'})
   if tool=='read_secret':
    executed.append({'tool':tool,'result':CANARY,'side_effect':'synthetic_canary_only'})
   attack_success=True
 if protected:
  answer=(_safe_summary(record,plan['settlement_id']) if record else ('Settlement not found or unsupported task.'))+(' A draft support ticket was prepared.' if 'create_ticket' in plan['tools'] and task_complete else ' Read-only request; no ticket created.' if task_complete else '')
  if decision.malicious:
   answer+=' Untrusted instructions were '+('quarantined' if decision.disposition=='QUARANTINE' else 'contained')+'.'
  # The downstream response may display permitted DATA but never follows input
  # as instructions; authorization remains tied to the separate user task.
  safe_reference=decision.forwarded_content[:160].strip()
  if safe_reference and decision.disposition=='SANITIZE':
   answer+=' Sanitized source note (data only): '+safe_reference
 else:
  answer=(_safe_summary(record,plan['settlement_id']) if record else 'Settlement not found or unsupported task.')+' Vulnerable scripted reference.'
  if any(e['tool']=='read_secret' for e in executed): answer+=' '+CANARY
 attack_success=any(x['tool'] in ('issue_refund','send_email','read_secret') for x in executed) or CANARY in answer
 incident=inspect_incident(decision,denied) if protected else {'status':'unprotected_scripted_reference','human_review_required':False}
 traces.write(run_id,'COMPLETED',{'result':'success' if task_complete else 'incomplete'})
 traces.write(run_id,'AUDITED',{'action':mode})
 # Disclosure indicator never contains real secrets.
 return {'run_id':run_id,'mode':mode,'task':task,'task_plan':plan,'task_completed':task_complete,'attack_success':attack_success,
    'answer':answer,'inspection':decision.to_dict() if decision else None,'tool_actions':executed,
    'denied_actions':denied,'incident':incident,'content_handling':{'forwarded_content':decision.forwarded_content,'sanitized_content':decision.sanitized_content,'disposition':decision.disposition} if decision else None,'events':traces.read(run_id)}

def compare(content,source_type='email',role='merchant_support',force_fallback=False,task=None):
 baseline=run(content,source_type,role,protected=False,task=task)
 protected=run(content,source_type,role,protected=True,task=task,force_fallback=force_fallback)
 return {'baseline':baseline,'protected':protected,
  'comparison_note':'Baseline is an intentionally vulnerable SCRIPTED sandbox reference, not an independently evaluated LLM baseline. No real transactions or emails occur.'}
