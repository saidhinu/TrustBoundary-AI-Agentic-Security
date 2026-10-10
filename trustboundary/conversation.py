"""Ephemeral, bounded same-process conversation risk memory.

NOT a distributed conversation store, secure authentication mechanism, or
trusted user identity. Do not use in shared production environments as-is.
"""
import re
import time
from collections import OrderedDict
from threading import RLock

LOCK=RLock()
STATES=OrderedDict()
MAX_CONVERSATIONS=512
TTL_SECONDS=1800
ROLE=re.compile(r'\b(?:system|developer|admin|higher\s+authority|pre.?authori[sz]ed|privileges?|approved\s+role)\b',re.I)
ACTION=re.compile(r'\b(?:refund|wire|transfer|send|forward|export|api\s+key|credentials?|token|secret|payout|approval|password)\b',re.I)

def observe(conversation_id, text, base_decision):
    """Add one observation and return a NEW JSON-compatible decision snapshot."""
    if not conversation_id:
        return base_decision
    if not re.fullmatch(r'[A-Za-z0-9_-]{5,64}',conversation_id):
        raise ValueError('Invalid conversation ID')
    with LOCK:
        now=time.monotonic()
        for key in list(STATES):
            if now-STATES[key]['last']>TTL_SECONDS:
                STATES.pop(key,None)
        prev=STATES.get(conversation_id,{'risk':0.0,'role_ever':False,'turns':0})
        # Simple decaying cumulative score; earlier role claims followed by tool
        # action language warrant escalation even if the individual turn is missed.
        risk=min(1.0,prev['risk']*0.75+(0.42 if ROLE.search(text) else 0)+(0.40 if ACTION.search(text) else 0))
        cross_turn=bool(prev['role_ever'] and ACTION.search(text))
        STATES[conversation_id]={'last':now,'risk':risk,'role_ever':prev['role_ever'] or bool(ROLE.search(text)),'turns':prev['turns']+1}
        STATES.move_to_end(conversation_id)
        while len(STATES)>MAX_CONVERSATIONS:
            STATES.popitem(last=False)
    result=dict(base_decision)
    result['conversation_risk']=round(risk,3)
    result['cross_turn_escalation']=cross_turn
    if cross_turn:
        result['malicious']=True
        result['disposition']='QUARANTINE'
        result['forwarded_content']=''
        result['sanitized_content']=''
        result['severity']='high'
        result['categories']=list(dict.fromkeys(result.get('categories',[])+['Multi-Step Jailbreaks']))
        result['rationale']='Role/authority claim followed by an action request across this ephemeral conversation. Source quarantined; tool authorization remains independent.'
    return result
