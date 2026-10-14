from pydantic import BaseModel,Field,model_validator
from typing import Literal
from .feature_extractor import features
from .window_builder import windows
from .identity_resolver import reference
from .episode_builder import build
import hashlib,json,time,platform,importlib.metadata

class Config(BaseModel):
    duration:float=Field(default=30,ge=1,le=3600)
    stride:float=Field(default=10,ge=1,le=3600)
    episode_gap:float=Field(default=60,ge=1,le=86400)
    threshold:float=Field(default=.55,ge=-1,le=4)
    weights:dict[str,float]=Field(default_factory=lambda:{'D':.35,'C':.2,'P':.25,'X':.2,'B':.2})
    min_identity_coverage:float=Field(default=.8,ge=0,le=1)
    incomplete:Literal['include','drop']='include'
    late_policy:Literal['sort_recorded']='sort_recorded'
    rename_enabled:bool=True
    destructive_operations:list[Literal['Write','Rename','Delete']]=['Write','Rename','Delete']
    @model_validator(mode='after')
    def check(self):
        if set(self.weights)!=set('DCPXB') or any(not 0<=v<=1 for v in self.weights.values()):raise ValueError('Provide D,C,P,X,B weights in [0,1]')
        if self.stride>self.duration:raise ValueError('Stride must not exceed duration')
        return self

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()
def analyze(events,cfg,benign_context=None):
    started=time.perf_counter();out=[]
    for w in windows(events,cfg.duration,cfg.stride,cfg.incomplete):
        f,eps,coverage,warnings=features(w['events'],cfg,benign_context)
        contributions={k:None if v is None else round(v*cfg.weights[k]*(-1 if k=='B' else 1),8) for k,v in f.items()}
        eligible=coverage>=cfg.min_identity_coverage and all(f[k] is not None or cfg.weights[k]==0 for k in 'DCPX')
        score=round(sum(v for v in contributions.values() if v is not None),8) if eligible else None
        out.append({**{k:v for k,v in w.items() if k!='events'},'event_count':len(w['events']),'features':f,'contributions':contributions,'score':score,'threshold':cfg.threshold,'classification':'Insufficient telemetry' if score is None else ('Review' if score>=cfg.threshold else 'Below threshold'),'coverage':coverage,'warnings':warnings+(['Right boundary exceeds last observed event'] if w['incomplete'] else []),'evidence':[reference(e) for e in w['events']],'episode_ids':[ep['id'] for ep in eps],'episodes':eps})
    elapsed=time.perf_counter()-started
    return {'windows':out,'episodes':build(events,cfg.episode_gap,cfg.rename_enabled),'manifest':{'engine_version':'2.0-research-1','dataset_hash':digest(events),'config':cfg.model_dump(),'config_hash':digest(cfg.model_dump()),'benign_context':benign_context,'feature_contract':'docs/FEATURES.md','python':platform.python_version(),'packages':{p:importlib.metadata.version(p) for p in ['fastapi','sqlalchemy','pydantic']},'disclaimer':'Research classifications. Uncalibrated defaults; no malware diagnosis.'},'performance':{'seconds':elapsed,'events_per_second':len(events)/elapsed if elapsed else None},'counts':{'events':len(events),'files':len({tuple(ep['identity']) for ep in build(events,cfg.episode_gap,cfg.rename_enabled)}),'processes':len({(e['host_id'],e['session_id'],e['process_id']) for e in events if e['process_id'] is not None}),'alerts':sum(w['classification']=='Review' for w in out)}}
