"""Measured, transparent synthetic held-out classification and sandbox outcome evaluation."""
import csv, json, statistics, time
from collections import Counter,defaultdict
from pathlib import Path
from .fixtures import evaluation_dataset,CATEGORIES
from .detection import Detector
from .agent import run
REPORTS=Path(__file__).resolve().parent.parent/'reports'

def _ratio(a,b): return round(a/b,4) if b else None

def evaluate(split='heldout',write_files=True):
 items=[x for x in evaluation_dataset() if x['split']==split] if split!='all' else evaluation_dataset()
 detector=Detector(enable_llm=False)
 rows=[]; latencies=[]; bycat=defaultdict(lambda:{'tp':0,'fn':0})
 tp=fp=tn=fn=0; protected_success=baseline_success=0; benign_task=0; malicious_task=0; denied_attempts=0; unauthorized_executed=0
 for sample in items:
  out=detector.scan(sample['text'],sample['source_type']); latencies.append(out.latency_ms)
  predicted=out.malicious
  if sample['malicious'] and predicted: tp+=1
  elif sample['malicious'] and not predicted: fn+=1
  elif not sample['malicious'] and predicted: fp+=1
  else: tn+=1
  if sample['category']:
   bycat[sample['category']]['tp' if sample['category'] in out.categories else 'fn']+=1
  # Real mock tool effects via the orchestrator; scripted baseline disclosed separately.
  protected=run(sample['text'],sample['source_type'],protected=True,force_fallback=True)
  baseline=run(sample['text'],sample['source_type'],protected=False)
  if sample['malicious']:
   protected_success+=int(protected['attack_success'])
   baseline_success+=int(baseline['attack_success'])
   malicious_task+=int(protected['task_completed'])
  else: benign_task+=int(protected['task_completed'])
  denied_attempts+=len(protected['denied_actions'])
  unauthorized_executed+=sum(1 for a in protected['tool_actions'] if a['tool'] in ('issue_refund','send_email','read_secret'))
  rows.append({'id':sample['id'],'kind':sample['kind'],'split':sample['split'],'source':sample['source_type'],'true_category':sample['category'] or '',
   'malicious_expected':sample['malicious'],'malicious_predicted':predicted,'categories_predicted':'; '.join(out.categories),
   'correct':sample['category'] in out.categories if sample['malicious'] else not predicted,'scan_latency_ms':out.latency_ms,
   'protected_attack_success':protected['attack_success'],'scripted_baseline_attack_success':baseline['attack_success'],
   'protected_task_completed':protected['task_completed'],'denied_attempts':len(protected['denied_actions'])})
 nbad=tp+fn; nbenign=tn+fp
 precision=_ratio(tp,tp+fp); recall=_ratio(tp,nbad)
 def r4(x):return round(x,4)
 metrics={'benchmark_type':'synthetic template-family heldout; local heuristic+ML with deterministic mock tools',
   'model':'local heuristics plus dev-split-trained TF-IDF/logistic regression; optional hosted LLM was not used',
   'baseline_type':'intentionally vulnerable scripted sandbox (NOT an LLM baseline)',
   'date_generated_utc':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
   'split':split,'total_cases':len(items),'attack_cases':nbad,'benign_and_ambiguous_cases':nbenign,
   'tp':tp,'fp':fp,'tn':tn,'fn':fn,'precision':precision,'recall':recall,
   'f1':r4(2*precision*recall/(precision+recall)) if precision is not None and recall is not None and precision+recall else None,
   'false_positive_rate':_ratio(fp,nbenign),
   'protected_attack_success_rate':_ratio(protected_success,nbad),
   'scripted_baseline_attack_success_rate':_ratio(baseline_success,nbad),
   'protected_benign_task_completion_rate':_ratio(benign_task,nbenign),
   'protected_task_completion_under_attack_rate':_ratio(malicious_task,nbad),
   'unauthorized_protected_tool_executions':unauthorized_executed,'denied_tool_attempts':denied_attempts,
   'median_scan_ms':round(statistics.median(latencies),3) if latencies else None,
   'p95_scan_ms':round(sorted(latencies)[min(len(latencies)-1,int(len(latencies)*.95))],3) if latencies else None,
   'per_category':{cat:{'cases':v['tp']+v['fn'],'detected':v['tp'],'recall':_ratio(v['tp'],v['tp']+v['fn'])} for cat,v in bycat.items()},
   'disclaimer':'Synthetic, heavily templated evaluation. High scores do not establish generalization or production security. No genuine LLM attacks evaluated offline.'}
 if write_files:
  REPORTS.mkdir(parents=True,exist_ok=True)
  (REPORTS/'metrics.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')
  with (REPORTS/'evaluation.csv').open('w',newline='',encoding='utf-8') as f:
   w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
  for name,filtered in [('false_positives',[r for r in rows if not r['malicious_expected'] and r['malicious_predicted']]),('false_negatives',[r for r in rows if r['malicious_expected'] and not r['malicious_predicted']])]:
   with (REPORTS/f'{name}.csv').open('w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(filtered)
 return metrics
