from ..detection.risk_engine import analyze,Config,digest
from ..simulation.generator import generate,SCENARIOS
from collections import Counter
import time

def metrics(labels,pred):
    tp=sum(y and p for y,p in zip(labels,pred));tn=sum(not y and not p for y,p in zip(labels,pred));fp=sum(not y and p for y,p in zip(labels,pred));fn=sum(y and not p for y,p in zip(labels,pred))
    div=lambda a,b:a/b if b else None
    return {'accuracy':div(tp+tn,len(labels)),'precision':div(tp,tp+fp),'recall':div(tp,tp+fn),'f1':div(2*tp,2*tp+fp+fn),'false_positive_rate':div(fp,fp+tn),'false_negative_rate':div(fn,fn+tp),'confusion_matrix':{'TP':tp,'TN':tn,'FP':fp,'FN':fn}}
def evaluate(seed,cfg):
    start=time.perf_counter();groups=[]
    # Assign complete executions before window creation. Same held-out traces for every method.
    for split,offset in [('validation',0),('test',1000)]:
        for idx,s in enumerate(SCENARIOS):
            for repeat in range(3):
                sid=f'{split}-{idx}-{repeat}';events=generate(s,seed+offset+idx*10+repeat,12+repeat*4,sid)
                groups.append({'split':split,'id':sid,'label':s=='Ransomware-like disruption','events':events,'scenario':s,'hash':digest(events)})
    methods={};thresholds={};details=[]
    for name in ['FCBC','Without rename lineage','Without cross-process','Without benign evidence','Process-count baseline','Volume baseline']:
        scores={'validation':[],'test':[]};labels={'validation':[],'test':[]}
        for g in groups:
            c=cfg.model_copy(deep=True)
            if name=='Without rename lineage':c.rename_enabled=False
            if name=='Without cross-process':c.weights['C']=0
            if name=='Without benign evidence':c.weights['B']=0
            if name=='Process-count baseline':score=max(Counter(e['process_id'] for e in g['events']).values())
            elif name=='Volume baseline':score=len(g['events'])
            else:
                context={'provenance':'Synthetic authorized workload fixture'} if g['scenario'] in ['Backup workload','Compression'] else None
                if name=='Without cross-process':
                    pids={e['process_id'] for e in g['events']}
                    all_windows=[w for pid in sorted(pids) for w in analyze([e for e in g['events'] if e['process_id']==pid],c,context)['windows']]
                else:all_windows=analyze(g['events'],c,context)['windows']
                valid=[w['score'] for w in all_windows if w['score'] is not None]
                if not valid:raise ValueError('Evaluation configuration produces no eligible windows')
                score=max(valid)
            scores[g['split']].append(score);labels[g['split']].append(g['label'])
        candidates=sorted(set(scores['validation']));candidates+=[max(candidates)+1e-6]
        threshold=max(candidates,key=lambda t:((metrics(labels['validation'],[x>=t for x in scores['validation']])['f1'] or 0),t))
        thresholds[name]=threshold;methods[name]=metrics(labels['test'],[x>=threshold for x in scores['test']])
        details.append({'method':name,'test_scores':scores['test'],'test_labels':labels['test']})
    return {'synthetic':True,'unit':'execution; maximum eligible window score','limitations':'Small synthetic fixtures, not real-world detection evidence. Fixed research weights; thresholds selected only on validation executions. These traces are intentionally simple.','seed':seed,'config':cfg.model_dump(),'thresholds':thresholds,'methods':methods,'groups':[{k:v for k,v in g.items() if k!='events'} for g in groups],'details':details,'seconds':time.perf_counter()-start}
