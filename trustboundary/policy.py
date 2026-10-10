"""Deterministic, non-LLM authorization. LLM content can never override tool ACL."""
from dataclasses import dataclass, asdict
ALLOWED={'merchant_support':{'read_settlement','create_ticket'},'compliance_analyst':{'read_settlement','create_ticket','read_audit'},'finance_admin':{'read_settlement','create_ticket','read_audit','issue_refund','send_email'}}
PRIVILEGED={'issue_refund','send_email'}
NEVER_ALLOWED={'read_secret'}
@dataclass
class Authorization:
    tool: str
    allowed: bool
    reason: str
    rule: str
    def to_dict(self): return asdict(self)

def authorize(tool,role='merchant_support',approval=False,origin='authorized_user',context=''):
    if tool in NEVER_ALLOWED:
        return Authorization(tool,False,'Secrets cannot be disclosed by business tools','SEC-000')
    if origin!='authorized_user':
        return Authorization(tool,False,'Low-trust content cannot grant tool access','TRUST-001')
    if tool not in ALLOWED.get(role,set()):
        return Authorization(tool,False,'The assigned role does not permit this tool','RBAC-002')
    if tool in PRIVILEGED and not approval:
        return Authorization(tool,False,'Privileged operation requires separate verified human approval','HITL-003')
    return Authorization(tool,True,'Authorized by role and operation policy','ALLOW-100')
