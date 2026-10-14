import os,time,secrets,json,threading,logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import Literal
from fastapi import FastAPI,Depends,HTTPException,UploadFile,File,Form,Request,Response,WebSocket,WebSocketDisconnect,Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel,Field
from sqlalchemy import select,delete
from .database.models import *
from .auth import current,editor,admin,password_hash,verify,session_hash
from .detection.normalizer import parse
from .detection.risk_engine import Config,analyze,digest
from .simulation.generator import generate,SCENARIOS
from .evaluation.runner import evaluate
from .reports.exporter import export
pool=ThreadPoolExecutor(max_workers=2);slots=threading.BoundedSemaphore(4);attempts={};attempt_lock=threading.Lock()
log=logging.getLogger('sentinel')
@asynccontextmanager
async def lifespan(app):
    # Schema is managed by Alembic, not implicitly rewritten at startup.
    with Session() as db:
        username=os.getenv('ADMIN_USERNAME','admin');pw=os.getenv('ADMIN_PASSWORD')
        if pw and not db.scalar(select(User).where(User.username==username)):
            if len(pw)<12:raise RuntimeError('ADMIN_PASSWORD must have at least 12 characters')
            db.add(User(username=username,password=password_hash(pw),role='admin'));db.commit()
        for r in db.scalars(select(Run).where(Run.status.in_(['queued','processing']))):r.status='failed';r.error='Interrupted by server restart. Start a new analysis.'
        db.commit()
    yield
app=FastAPI(title='FCBC Sentinel API',version='2.0.0',lifespan=lifespan,docs_url=None,redoc_url=None)
@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'"})
    return response
@app.exception_handler(ValueError)
async def bad_value(request,error):return JSONResponse({'detail':str(error)},status_code=422)
def audit(db,u,action,target):db.add(Audit(actor=u.id,action=action,target=target))
def owned(db,cls,key,u):
    obj=db.get(cls,key)
    if not obj or obj.owner!=u.id:raise HTTPException(404,'Record not found')
    return obj
def dataset_dict(d):return {k:getattr(d,k) for k in ['id','name','sha256','count','synthetic','context','created']}
def run_dict(r,full=False):return {k:getattr(r,k) for k in (['id','dataset_id','status','config','error','created']+(['result'] if full else []))}
def save_dataset(db,u,name,events,synthetic=False,context=None):
    d=Dataset(owner=u.id,name=Path(name.replace('\\','/')).name[:200],sha256=digest(events),count=len(events),synthetic=int(synthetic),context=context);db.add(d);db.flush()
    db.add_all([FileEvent(dataset_id=d.id,data=e) for e in events]);audit(db,u,'dataset.created',d.id);db.commit();return dataset_dict(d)
class Login(BaseModel):
    username:str=Field(max_length=100)
    password:str=Field(max_length=200)
@app.post('/api/auth/login')
def login(body:Login,request:Request,response:Response):
    origin=request.headers.get('origin')
    if origin and origin!=str(request.base_url).rstrip('/') and origin not in os.getenv('ALLOWED_ORIGINS','http://localhost:5173,http://127.0.0.1:5173').split(','):raise HTTPException(403,'Origin not allowed')
    key=request.client.host
    with attempt_lock:
        now=time.time();failures=[x for x in attempts.get(key,[]) if now-x<300];attempts[key]=failures
        if len(failures)>=10:raise HTTPException(429,'Too many attempts. Wait five minutes.')
        failures.append(now)
    with Session() as db:
        u=db.scalar(select(User).where(User.username==body.username))
        if not u or not verify(body.password,u.password):raise HTTPException(401,'Invalid username or password')
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
        db.add(LoginSession(id=session_hash(token),user_id=u.id,csrf=csrf,expires=time.time()+28800));audit(db,u,'auth.login',u.id);db.commit()
    response.set_cookie('sentinel_session',token,httponly=True,samesite='strict',secure=os.getenv('COOKIE_SECURE','false').lower()=='true',max_age=28800)
    return {'username':u.username,'role':u.role,'csrf':csrf}
@app.get('/api/auth/me')
def me(request:Request,u=Depends(current)):
    with Session() as db:s=db.get(LoginSession,session_hash(request.cookies['sentinel_session']));return {'username':u.username,'role':u.role,'csrf':s.csrf}
@app.post('/api/auth/logout')
def logout(request:Request,response:Response,u=Depends(current)):
    with Session() as db:db.execute(delete(LoginSession).where(LoginSession.id==session_hash(request.cookies['sentinel_session'])));db.commit()
    response.delete_cookie('sentinel_session');return {'ok':True}
@app.get('/api/health')
def health():return {'status':'ok','engine':'2.0-research-1','mode':'recorded telemetry only'}
@app.get('/api/settings')
def settings(u=Depends(current)):return u.settings or Config().model_dump()
@app.put('/api/settings')
def save_settings(body:Config,u=Depends(editor)):
    with Session() as db:db.get(User,u.id).settings=body.model_dump();audit(db,u,'settings.updated',u.id);db.commit()
    return body
@app.post('/api/datasets/upload')
async def upload(file:UploadFile=File(...),mapping:str=Form('{}'),u=Depends(editor)):
    raw=await file.read(10*1024*1024+1)
    try:
        m=json.loads(mapping)
        if not isinstance(m,dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in m.items()):raise ValueError('Mapping must map canonical fields to source column names')
        events=parse(raw,file.filename or '',m)
    except (ValueError,UnicodeError) as ex:raise HTTPException(422,str(ex))
    with Session() as db:return save_dataset(db,u,file.filename or 'telemetry',events)
@app.get('/api/datasets')
def datasets(u=Depends(current)):
    with Session() as db:return [dataset_dict(d) for d in db.scalars(select(Dataset).where(Dataset.owner==u.id).order_by(Dataset.created.desc()))]
@app.get('/api/datasets/{key}')
def dataset(key:str,u=Depends(current)):
    with Session() as db:
        d=owned(db,Dataset,key,u);return {**dataset_dict(d),'preview':[e.data for e in db.scalars(select(FileEvent).where(FileEvent.dataset_id==key).limit(20))]}
@app.delete('/api/datasets/{key}')
def remove_dataset(key:str,u=Depends(editor)):
    with Session() as db:
        d=owned(db,Dataset,key,u)
        if db.scalar(select(Run).where(Run.dataset_id==key,Run.status.in_(['queued','processing']))):raise HTTPException(409,'Wait for analysis to finish')
        db.delete(d);audit(db,u,'dataset.deleted',key);db.commit()
    return {'ok':True}
class Context(BaseModel):
    provenance:str=Field(min_length=10,max_length=2000)
@app.put('/api/datasets/{key}/context')
def attest(key:str,body:Context,u=Depends(admin)):
    with Session() as db:
        d=owned(db,Dataset,key,u);d.context={'provenance':body.provenance,'attested_by':u.username,'at':time.time()};audit(db,u,'benign-context.attested',key);db.commit();return dataset_dict(d)
class Simulation(BaseModel):
    scenario:str
    seed:int=42
    files:int=Field(default=20,ge=1,le=100)
@app.post('/api/simulation/generate')
def simulation(body:Simulation,u=Depends(editor)):
    events=generate(body.scenario,body.seed,body.files)
    context={'provenance':'Synthetic authorized-workload fixture','seed':body.seed} if body.scenario in ['Backup workload','Compression'] else None
    with Session() as db:return save_dataset(db,u,body.scenario,events,True,context)
class RunRequest(BaseModel):
    dataset_id:str
    config:Config=Field(default_factory=Config)
def process_run(key):
    try:
        with Session() as db:
            r=db.get(Run,key);r.status='processing';db.commit();d=db.get(Dataset,r.dataset_id)
            events=[e.data for e in db.scalars(select(FileEvent).where(FileEvent.dataset_id==d.id))]
            result=analyze(sorted(events,key=lambda e:(e['ts'],e['host_id'],e['session_id'],e['event_id'])),Config(**r.config),d.context)
            r.result=result;r.status='complete'
            db.add_all([Episode(run_id=key,data=e) for e in result['episodes']]);db.add_all([Window(run_id=key,data=w) for w in result['windows']])
            db.add_all([Alert(run_id=key,data=w) for w in result['windows'] if w['classification']=='Review']);db.commit()
    except Exception as ex:
        log.exception('Analysis failed: %s',key)
        with Session() as db:
            r=db.get(Run,key)
            if r:r.status='failed';r.error=str(ex) if isinstance(ex,ValueError) else 'Internal analysis failure. See server logs.';db.commit()
    finally:slots.release()
@app.post('/api/analysis/run',status_code=202)
def run(body:RunRequest,u=Depends(editor)):
    with Session() as db:
        owned(db,Dataset,body.dataset_id,u)
        if not slots.acquire(blocking=False):raise HTTPException(429,'Analysis queue full; try again shortly')
        try:
            r=Run(owner=u.id,dataset_id=body.dataset_id,config=body.config.model_dump());db.add(r);db.flush();audit(db,u,'analysis.started',r.id);db.commit();pool.submit(process_run,r.id)
        except Exception:slots.release();raise
        return run_dict(r)
@app.get('/api/analysis')
def runs(u=Depends(current)):
    with Session() as db:return [run_dict(r) for r in db.scalars(select(Run).where(Run.owner==u.id).order_by(Run.created.desc()))]
@app.get('/api/analysis/{key}/status')
def status(key:str,u=Depends(current)):
    with Session() as db:return run_dict(owned(db,Run,key,u))
@app.get('/api/analysis/{key}/results')
def results(key:str,u=Depends(current)):
    with Session() as db:
        r=owned(db,Run,key,u);return {**run_dict(r,True),'dataset':dataset_dict(db.get(Dataset,r.dataset_id))}
@app.websocket('/api/analysis/{key}/stream')
async def stream(ws:WebSocket,key:str):
    import asyncio
    with Session() as db:
        s=db.get(LoginSession,session_hash(ws.cookies.get('sentinel_session','')));r=db.get(Run,key)
        if not s or s.expires<time.time() or not r or r.owner!=s.user_id:await ws.close(code=1008);return
    await ws.accept()
    try:
        for _ in range(600):
            with Session() as db:r=db.get(Run,key);payload=run_dict(r)
            await ws.send_json(payload)
            if r.status in ['complete','failed']:break
            await asyncio.sleep(.5)
    except WebSocketDisconnect:pass
    finally:
        try:await ws.close()
        except RuntimeError:pass
@app.get('/api/events')
def events(dataset_id:str,q:str='',host:str='',session:str='',process:str='',operation:str='',start:float|None=None,end:float|None=None,sort:Literal['timestamp','event_id','operation']='timestamp',descending:bool=False,page:int=Query(1,ge=1),size:int=Query(25,ge=1,le=500),u=Depends(current)):
    with Session() as db:
        owned(db,Dataset,dataset_id,u);rows=[e.data for e in db.scalars(select(FileEvent).where(FileEvent.dataset_id==dataset_id))]
    rows=[e for e in rows if (not q or q.lower() in json.dumps(e).lower()) and (not host or e['host_id']==host) and (not session or e['session_id']==session) and (not process or e['process_id']==process) and (not operation or e['operation']==operation) and (start is None or e['ts']>=start) and (end is None or e['ts']<end)]
    rows.sort(key=lambda e:e[sort],reverse=descending);return {'total':len(rows),'items':rows[(page-1)*size:page*size]}
@app.get('/api/episodes')
def episodes(run_id:str,u=Depends(current)):
    with Session() as db:owned(db,Run,run_id,u);return [e.data for e in db.scalars(select(Episode).where(Episode.run_id==run_id))]
@app.get('/api/correlations')
def correlations(run_id:str,host:str='',session:str='',process:str='',operation:str='',window_id:str='',risk:str='',u=Depends(current)):
    with Session() as db:r=owned(db,Run,run_id,u);data=r.result or {'episodes':[],'windows':[]}
    eps=data['episodes']
    if window_id or risk:
        matched=[w for w in data['windows'] if (not window_id or w['id']==window_id) and (not risk or w['classification']==risk)]
        refs={(e['host_id'],e['session_id'],e['event_id']) for w in matched for e in w['evidence']}
        eps=[{**ep,'events':[e for e in ep['events'] if (e['host_id'],e['session_id'],e['event_id']) in refs]} for ep in eps]
    eps=[ep for ep in eps if ep['events'] and (not host or ep['identity'][0]==host) and (not session or ep['identity'][1]==session) and (not process or process in ep['processes']) and (not operation or any(e['operation']==operation for e in ep['events']))]
    nodes=[];edges=[];seen=set()
    for i,ep in enumerate(eps[:100]):
        nodes.append({'id':ep['id'],'position':{'x':360,'y':i*170},'data':{'label':f"{ep['identity'][-1]} · {len(ep['events'])} events",'evidence':ep}})
        for j,p in enumerate(ep['processes']):
            pid=json.dumps(ep['identity'][:2]+[p])
            if pid not in seen:nodes.append({'id':pid,'position':{'x':0,'y':len(seen)*100},'data':{'label':'Process '+p,'evidence':{'scope':ep['identity'][:2],'process_id':p}}});seen.add(pid)
            edges.append({'id':pid+ep['id'],'source':pid,'target':ep['id'],'label':'observed operations'})
        for j,rename in enumerate(ep['renames']):
            rid=ep['id']+'-rename-'+str(j);nodes.append({'id':rid,'position':{'x':740+j*260,'y':i*170},'data':{'label':('Verified' if rename['verified'] else 'Uncertain')+' rename','evidence':rename}})
            edges.append({'id':rid+'-edge','source':ep['id'],'target':rid,'label':'verified lineage' if rename['verified'] else 'unverified observation','style':{'strokeDasharray':'0' if rename['verified'] else '5 5'}})
    return {'nodes':nodes,'edges':edges,'total_episodes':len(eps),'limited':len(eps)>100}
@app.get('/api/alerts')
def alerts(run_id:str|None=None,status:str='',q:str='',u=Depends(current)):
    with Session() as db:
        stmt=select(Alert).join(Run).where(Run.owner==u.id)
        if run_id:stmt=stmt.where(Alert.run_id==run_id)
        if status:stmt=stmt.where(Alert.status==status)
        return [{**a.data,'window_id':a.data['id'],'id':a.id,'run_id':a.run_id,'status':a.status,'notes':a.notes} for a in db.scalars(stmt) if not q or q.lower() in json.dumps(a.data).lower()]
class ReviewRequest(BaseModel):
    status:Literal['New','Investigating','Resolved','False Positive']
    notes:str=Field(default='',max_length=5000)
@app.patch('/api/alerts/{key}')
def review(key:str,body:ReviewRequest,u=Depends(editor)):
    with Session() as db:
        a=db.get(Alert,key)
        if not a:raise HTTPException(404,'Alert not found')
        owned(db,Run,a.run_id,u);a.status=body.status;a.notes=body.notes;db.add(Review(alert_id=key,actor=u.id,data=body.model_dump()));audit(db,u,'alert.reviewed',key);db.commit()
    return {'ok':True}
class EvalRequest(BaseModel):
    seed:int=42
    config:Config=Field(default_factory=Config)
@app.post('/api/evaluation')
def evaluation(body:EvalRequest,u=Depends(editor)):
    data=evaluate(body.seed,body.config)
    with Session() as db:e=Evaluation(owner=u.id,data=data);db.add(e);db.flush();audit(db,u,'evaluation.created',e.id);db.commit();return {'id':e.id,**e.data}
@app.get('/api/evaluation')
def evals(u=Depends(current)):
    with Session() as db:return [{'id':e.id,'created':e.created} for e in db.scalars(select(Evaluation).where(Evaluation.owner==u.id).order_by(Evaluation.created.desc()))]
@app.get('/api/evaluation/{key}')
def eval_result(key:str,u=Depends(current)):
    with Session() as db:e=owned(db,Evaluation,key,u);return {'id':e.id,**e.data}
@app.get('/api/reports/{key}/download')
def report(key:str,format:Literal['pdf','csv','json']='json',u=Depends(current)):
    with Session() as db:
        r=owned(db,Run,key,u)
        if r.status!='complete':raise HTTPException(409,'Analysis not complete')
        data={**run_dict(r,True),'dataset':dataset_dict(db.get(Dataset,r.dataset_id))};audit(db,u,'report.downloaded',key);db.commit()
    content,mime=export(data,format);return Response(content,media_type=mime,headers={'Content-Disposition':f'attachment; filename="FCBC-{key[:8]}.{format}"'})
@app.get('/api/audit')
def audits(u=Depends(current)):
    with Session() as db:return [{'action':a.action,'target':a.target,'created':a.created} for a in db.scalars(select(Audit).where(Audit.actor==u.id).order_by(Audit.created.desc()).limit(100))]
@app.get('/docs',include_in_schema=False)
def documentation():
    from html import escape
    from fastapi.responses import HTMLResponse
    spec=app.openapi()
    rows=''.join('<tr><td>'+escape(method.upper())+'</td><td>'+escape(path)+'</td><td>'+escape(info.get('summary',''))+'</td></tr>' for path,ops in spec['paths'].items() for method,info in ops.items())
    return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><title>FCBC API documentation</title><body style="background:#101a28;color:#d7e6ef;font:16px system-ui;padding:40px"><h1>FCBC Sentinel API</h1><p>Authenticate with POST /api/auth/login. Use the returned session cookie for reads and X-CSRF-Token for mutations. Private resources are owner-scoped.</p><p><a style="color:cyan" href="/openapi.json">Complete OpenAPI JSON: parameters, schemas and responses</a></p><table cellpadding="12"><tr><th>Method</th><th>Endpoint</th><th>Purpose</th></tr>'+rows+'</table></body></html>')
front=Path(os.getenv('FRONTEND_DIST',str(Path(__file__).resolve().parents[2]/'frontend'/'dist')))
if front.exists():app.mount('/',StaticFiles(directory=front,html=True),name='frontend')
