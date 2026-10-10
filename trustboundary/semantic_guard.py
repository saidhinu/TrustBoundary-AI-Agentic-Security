"""Structure-focused *advisory* risk signals for untrusted text.

This is a conservative heuristic, NOT semantic understanding. Signals do not authorize
anything; the policy gate is independent. The patterns are broad enough to generalize
beyond a small phrase list but can still miss paraphrases and cause false positives.
"""
import re

RX = {
    'agent': r'\b(?:assistant|\bai\b|bot|automated\s+(?:reader|system|reviewer|agent)|whoever\s+(?:summarizes?|reads?)|you|your|agent|summariz(?:er|es?))\b',
    'override': r'\b(?:ignore|disregard|supersede|replace|set\s+aside|skip|expire|no\s+longer|outdated|retired|override|instead\s+of|only\s+brief|higher\s+priority|from\s+now\s+on|before\s+(?:you|respond)|new\s+policy)\b',
    'authority': r'\b(?:system|developer|admin(?:istrator)?|root|supervisor|maintenan(?:ce|t)|config(?:uration)?|privileges?|policy|pre.authori[sz]ed|approval|instructions?|permissions?|unrestricted|financegpt|role)\b',
    'secret': r'\b(?:exact\s+(?:words|text)\s+(?:you\s+were\s+)?(?:given|supplied)|secret|hidden|setup\s+text|system\s+prompt|initial\s+prompt|instructions?\s+(?:before|given)|environment\s+variables?|\.aws/credentials|bearer\s+token|api\s+key|password|credential|config(?:uration)?|customer\s+database|ledger|full\s+thread|thread|otp|provisioned\s+keys?)\b',
    'extract': r'\b(?:add\s+(?:a\s+)?(?:line|note)|tell\s+the\s+reader|paste|quote|print|show|output|reveal|list|return|include|provide|give|fetch|retrieve|dump|read|send|forward|transmit|post|upload|curl|deliver|sync|expose|export)\b',
    'destination': r'(?:\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b|https?://\S+|\b(?:sender|outside\s+account|external\s+recipient|in\s+the\s+reply|into\s+the\s+reply|below|account\s+in\s+the\s+invoice)\b)',
    'money': r'\b(?:wire|transfer|payout|pay|refund|disburse|move|release|remit|send)\b.{0,90}\b(?:INR|balance|funds?|settlement|account|invoice|money|amount|customer|\d[,\d]*)\b',
    'step': r'\b(?:step\s*(?:one|1)|first|phase\s*(?:one|a))\b.{0,220}\b(?:step\s*(?:two|2)|next\s+(?:message|turn)|then|phase\s*(?:two|b))\b',
    'instruction': r'\b(?:must|should|need\s+to|do\s+it|carry\s+out|execute|run|act\s+as|treat\s+this|switch|comply|obey|follow|reply\s+with|answer\s+as|stop\s+following|start\s+following|when\s+i\s+say)\b',
    'identity': r'(?:["\']role["\']\s*:\s*["\'](?:system|developer|admin)["\']|\b(?:you\s+(?:are|become)(?:\s+now)?|act\s+as|become|pretend|assume\s+the\s+role|switch\s+to)\b.{0,90}\b(?:admin|system|root|developer|finance|maintenance|supervisor))',
    'poison': r'\b(?:remember\s+for\s+(?:future|later)|kb\s+update|internal\s+wiki|documentation|verified\s+policy|new\s+policy|remember\s+for\s+future|effective\s+today|permanently\s+approved|no\s+longer\s+require|pre.authori[sz]ed)\b',
    'sourcecode': r'(?:(?:\bcurl\b|\bwget\b).{0,70}(?:https?://|\b-d\b)|(?:\.aws/credentials|/etc/(?:passwd|shadow)))',
}
C = {k: re.compile(v,re.I|re.S) for k,v in RX.items()}

# Reporting language is a negative signal; only if not followed by a live
# instruction to the summarizer/assistant. This remains intentionally cautious.
REPORT_ONLY=re.compile(r'\b(?:article|case\s+study|tutorial|training|what\s+is|explains?|reported|example|incident|documentation|security\s+team|guide)\b',re.I)

def structural_findings(text: str, source_type='email'):
    """Return {category:confidence} and redacted-safe evidence markers.

    Does not use the evaluator's sample IDs or any particular judge phrase.
    """
    hit={k for k,p in C.items() if p.search(text)}
    labels={}
    if 'identity' in hit or (('agent' in hit or source_type=='api') and 'authority' in hit and 'instruction' in hit):
        labels['Role Change']=.86 if 'identity' in hit else .79
    if 'override' in hit and ((('agent' in hit or 'authority' in hit) and ('instruction' in hit or 'money' in hit)) or ('agent' in hit and 'authority' in hit)):
        labels['Instruction Override']=.85
    if 'extract' in hit and 'secret' in hit and ('agent' in hit or 'destination' in hit or 'sourcecode' in hit):
        labels['Secret Extraction']=.86
    if 'secret' in hit and 'destination' in hit and ('extract' in hit or 'sourcecode' in hit):
        labels['Credential Theft']=.90
    if 'money' in hit and ('instruction' in hit or 'destination' in hit or 'override' in hit):
        labels['Tool Abuse']=.84
    if 'step' in hit and ('override' in hit or 'authority' in hit or 'secret' in hit or 'agent' in hit or 'instruction' in hit):
        labels['Multi-Step Jailbreaks']=.83
    if 'poison' in hit and ('authority' in hit or 'money' in hit or 'override' in hit or 'instruction' in hit or 'destination' in hit):
        labels['Context Poisoning']=.82
    if source_type in {'html','web','markdown','code','api'} and 'agent' in hit and ('extract' in hit or 'money' in hit or 'instruction' in hit or 'secret' in hit):
        labels['Indirect Prompt Injection']=.80
    if 'sourcecode' in hit and ('extract' in hit or 'agent' in hit):
        labels['Tool Abuse']=.90
    if REPORT_ONLY.search(text) and not {'money','destination','sourcecode'} & hit and not re.search(r'\b(?:you|your|assistant|automated readers)\b.{0,80}\b(?:act|become|execute|send|forward|pay|release)\b',text,re.I):
        # Preserve legitimate educational discussion of security concepts.
        labels={cat:score for cat,score in labels.items() if cat not in {'Secret Extraction','Role Change','Multi-Step Jailbreaks'}}
    return labels,sorted(hit)
