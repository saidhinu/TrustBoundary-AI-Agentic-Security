"""GroupKFold validation on synthetic dev fixtures, grouped by template family.

This assesses a newly fitted TF-IDF/LogReg classifier, not the integrated
heuristic + ML end-to-end detector, and does NOT imply independence from the
manual template authoring process.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import GroupKFold
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from trustboundary.fixtures import evaluation_dataset


def family(x):
    ident=x['id'];kind=x['kind']
    if kind=='attack':
        # 20 rows in each category reuse 4 exact injection templates.
        category,templateid,index=ident.split('-')
        return f'{category}-{templateid}-template{(int(index)-1)%4}'
    if kind=='benign':return f'B-template{(int(ident.split("-")[1])-1)%10}'
    return f'Q-template{(int(ident.split("-")[1])-1)%5}'


def run():
    data=evaluation_dataset()
    # Dev-split only. We group repeated template families rather than rows.
    data=[x for x in data if x['split']=='development']
    X=[x['text'] for x in data]; y=[int(x['malicious']) for x in data]
    groups=[family(x) for x in data]
    folds=GroupKFold(n_splits=5)
    tp=tn=fp=fn=0; fold_rows=[]
    for i,(train,test) in enumerate(folds.split(X,y,groups)):
        model=Pipeline([('vectorize',TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),min_df=2,max_features=12000)),
            ('classify',LogisticRegression(max_iter=500,class_weight='balanced'))])
        model.fit([X[j] for j in train],[y[j] for j in train])
        predictions=model.predict([X[j] for j in test]);counts=Counter()
        for j,pred in zip(test,predictions):
            counts['TP' if y[j]==1 and pred==1 else 'FN' if y[j]==1 else 'FP' if pred==1 else 'TN']+=1
        for key in ('TP','TN','FP','FN'):globals()[key.lower()] if False else None
        tp+=counts['TP'];tn+=counts['TN'];fp+=counts['FP'];fn+=counts['FN']
        fold_rows.append({'fold':i+1,'rows':len(test),'template_families':len({groups[j] for j in test}),**counts})
    result={'source':'Synthetic development fixture families only','n':len(X),'groups':len(set(groups)),'method':'GroupKFold(5), TF-IDF char 3-5 + logistic regression, 0.5 threshold',
            'TP':tp,'TN':tn,'FP':fp,'FN':fn,'recall':tp/(tp+fn) if tp+fn else None,'fpr':fp/(fp+tn) if fp+tn else None,
            'precision':tp/(tp+fp) if tp+fp else None,'folds':fold_rows,'date_utc':datetime.now(timezone.utc).isoformat(),
            'limitation':'Not an external, independently authored corpus. Does not evaluate the full rules + ML pipeline.'}
    out=ROOT/'reports'/'synthetic_groupkfold.json';out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return result

if __name__=='__main__':run()
