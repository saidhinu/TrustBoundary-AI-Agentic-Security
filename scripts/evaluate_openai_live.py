"""Opt-in hosted classification benchmark. Uses only synthetic prompt-injection fixtures.

No real API calls are made when OPENAI_API_KEY is absent. Bills the configured
OpenAI API account; inspect costs and quotas before running. Results are kept
separate from offline benchmarks and never replace the original baseline.
"""
import argparse,csv,json,os,time,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from trustboundary.detection import Detector

def main():
 p=argparse.ArgumentParser()
 p.add_argument('--corpus',default=str(ROOT/'tests'/'new_challenge_v14_frozen.json'))
 p.add_argument('--max-cases',type=int,default=10)
 args=p.parse_args()
 if not os.getenv('OPENAI_API_KEY'):
  raise SystemExit('LIVE TEST NOT RUN: set OPENAI_API_KEY privately on the server. No key available.')
 data=json.loads(Path(args.corpus).read_text())
 rows=[]
 for x in data[:max(1,min(args.max_cases,60))]:
  start=time.perf_counter()
  outcome=Detector(enable_llm=True).scan(x['content'],x.get('source_type','email'))
  rows.append({'id':x['id'],'expected':x['malicious'],'detected':outcome.malicious,
               'category_labels':';'.join(outcome.categories),'model_path':outcome.model,
               'latency_ms':round((time.perf_counter()-start)*1000,1),
               'llm_success':'plus_llm' in outcome.model})
 confirmed=sum(x['llm_success'] for x in rows)
 tp=sum(x['expected'] and x['detected'] for x in rows)
 fp=sum(not x['expected'] and x['detected'] for x in rows)
 fn=sum(x['expected'] and not x['detected'] for x in rows)
 tn=sum(not x['expected'] and not x['detected'] for x in rows)
 result={'source':'live OpenAI attempts on synthetic-only input',
         'model':os.getenv('OPENAI_MODEL','gpt-4o-mini'),'tested':len(rows),
         'confirmed_live_responses':confirmed,'fallback_count':len(rows)-confirmed,
         'counts':{'TP':tp,'FP':fp,'FN':fn,'TN':tn},
         'precision':round(tp/(tp+fp),4) if tp+fp else None,
         'recall':round(tp/(tp+fn),4) if tp+fn else None,
         'false_positive_rate':round(fp/(fp+tn),4) if fp+tn else None,
         'mean_latency_ms':round(sum(x['latency_ms'] for x in rows)/len(rows),1),
         'warning':'A fallback means this is NOT an all-LLM benchmark. Verify confirmed_live_responses == tested.'}
 out=ROOT/'reports';out.mkdir(exist_ok=True)
 (out/'openai_live_aggregate.json').write_text(json.dumps(result,indent=2))
 with (out/'openai_live_cases.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
 print(json.dumps(result,indent=2))
 if confirmed!=len(rows):
  raise SystemExit('INCOMPLETE LIVE VALIDATION: one or more calls fell back to offline detector.')

if __name__=='__main__':main()
