"""External public benchmark: deepset/prompt-injections official test split.

Run once after installing `pandas pyarrow` and downloading the pinned Parquet
file. No public corpus data is redistributed with this project.

Important: dataset includes direct user prompts, not just low-trust external
retrieval content. Treat scores as out-of-domain, not a production validation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timezone
from urllib.request import urlretrieve

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from trustboundary.detection import Detector

UPSTREAM='https://huggingface.co/datasets/deepset/prompt-injections/resolve/main/data/test-00000-of-00001-701d16158af87368.parquet'
SHA256='39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e'

def run(file,output):
    file=Path(file)
    if not file.exists():
        raise SystemExit(f'No public dataset file at {file}. Download {UPSTREAM}')
    digest=hashlib.sha256(file.read_bytes()).hexdigest()
    if digest!=SHA256:
        raise SystemExit('Dataset SHA256 mismatch; refusing to report results.')
    try:
        import pandas as pd
        df=pd.read_parquet(file)
    except ImportError as exc:
        raise SystemExit('Install public evaluation dependencies: pip install pandas pyarrow') from exc
    assert {'text','label'}.issubset(df.columns)
    labels=df['label'].astype(int).tolist()
    assert set(labels)=={0,1}
    # Only original published test split (116 rows); no tuning here.
    assert len(df)==116
    detector=Detector(enable_llm=False)
    results=[]
    for i,(raw,label) in enumerate(zip(df['text'],labels)):
        decision=detector.scan(str(raw),source_type='text',force_fallback=True)
        actual=bool(label); predicted=decision.malicious
        results.append({'row':i,'true_label':int(actual),'predicted':int(predicted),
                        'result':'TP' if actual and predicted else 'FN' if actual else 'FP' if predicted else 'TN',
                        'latency_ms':decision.latency_ms})
    from collections import Counter
    c=Counter(r['result'] for r in results)
    tp,fn,fp,tn=(c[x] for x in ('TP','FN','FP','TN'))
    doc={'source':'deepset/prompt-injections (official test; 116 rows)',
         'source_url':UPSTREAM,'sha256':digest,'license':'Apache-2.0 dataset page; metadata also contains CC-BY-4.0; verify if redistributing',
         'retrieved_at_utc':datetime.now(timezone.utc).isoformat(),
         'test_cases':len(df),'attack_cases':tp+fn,'benign_cases':tn+fp,
         'TP':tp,'FN':fn,'FP':fp,'TN':tn,
         'recall':round(tp/(tp+fn),4),'precision':round(tp/(tp+fp),4) if tp+fp else None,
         'false_positive_rate':round(fp/(fp+tn),4),
         'model':'offline deterministic rules and synthetic-fixture-trained local ML; no OpenAI',
         'caveat':'Direct-prompt dataset vs TrustBoundary indirect-injection threat model: out-of-domain test. Not production proof.'}
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(doc,indent=2)+'\n',encoding='utf-8')
    with output.with_suffix('.cases.csv').open('w',encoding='utf-8',newline='') as f:
        import csv
        w=csv.DictWriter(f,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    print(json.dumps(doc,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--dataset-file',default=str(ROOT/'data'/'deepset_test.parquet'))
    parser.add_argument('--download',action='store_true',help='Download data from upstream (Internet required)')
    parser.add_argument('--output',default=str(ROOT/'reports'/'external_deepset_test.json'))
    args=parser.parse_args()
    if args.download:
        Path(args.dataset_file).parent.mkdir(parents=True,exist_ok=True)
        urlretrieve(UPSTREAM,args.dataset_file)
    run(args.dataset_file,args.output)
