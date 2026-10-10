"""Small genuinely trained local statistical classifier.

Train only on development fixture variants; held-out evaluation uses other
wording variants. The model is deliberately NOT production validated.
"""
from functools import lru_cache
from .fixtures import evaluation_dataset,NORMAL

@lru_cache(maxsize=1)
def get_classifier():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    dev=[s for s in evaluation_dataset() if s['split']=='development']
    pipe=Pipeline([('vectorize',TfidfVectorizer(analyzer='char_wb',ngram_range=(3,5),min_df=2,max_features=12000)),
      ('classify',LogisticRegression(max_iter=500,class_weight='balanced'))])
    examples=[x['text'] for x in dev]
    labels=[int(x['malicious']) for x in dev]
    # Avoid accidental labeling of the common merchant context as an attack.
    # Learn injected suffixes and explicit clean versions of the same context.
    for x in dev:
        if x['malicious'] and '\n\n' in x['text']:
            examples.append(x['text'].split('\n\n',1)[-1]);labels.append(1)
    for i in range(150):
        examples.append(NORMAL+' Tracking reference '+str(i))
        labels.append(0)
    pipe.fit(examples,labels)
    return pipe

def predict_risk(text:str)->float:
    clf=get_classifier()
    return round(float(clf.predict_proba([text[:10000]])[0,1]),4)
