"""Fail CI on high-confidence API-key patterns in committed history.

Runs git log -p with fetch-depth: 0. Prints path-independent safe counts only;
never prints candidate credentials. This does not substitute for gitleaks.
"""
import subprocess
import re
import sys

COMMAND=['git','log','--all','-p','--no-ext-diff','--no-color']
try:
    log=subprocess.run(COMMAND,check=True,capture_output=True,text=True,errors='replace',timeout=60).stdout
except Exception as exc:
    print('History scan unavailable:',type(exc).__name__)
    sys.exit(2)
# Only newly added patch lines, not removed context. Scan full history for live
# credential-like strings; avoid treating documentation placeholders as keys.
added='\n'.join(line[1:] for line in log.splitlines() if line.startswith('+') and not line.startswith('+++'))
patterns=[
    re.compile(r'\bsk-proj-[A-Za-z0-9_-]{40,}'),
    re.compile(r'\bsk-[A-Za-z0-9_-]{45,}'),
    re.compile(r'\bghp_[A-Za-z0-9]{36,}'),
]
count=sum(len(p.findall(added)) for p in patterns)
print('High-confidence credentials found in added historical diffs:', count)
if count:print('Revoke the affected credentials, rotate usage, and remove exposure from relevant repo history.')
sys.exit(1 if count else 0)
