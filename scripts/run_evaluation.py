from trustboundary.evaluation import evaluate
import json
if __name__=='__main__':
 print(json.dumps(evaluate('heldout'),indent=2))
