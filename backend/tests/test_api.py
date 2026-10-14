import json,time
from app.simulation.generator import generate
from app.database.models import Session,User
from app.auth import password_hash
from app.main import app
from fastapi.testclient import TestClient

def upload(c):
    r=c.post('/api/datasets/upload',files={'file':('trace.json',json.dumps([e['source'] for e in generate('Ransomware-like disruption',42,3)]),'application/json')});assert r.status_code==200,r.text;return r.json()['id']
def wait(c,rid):
    for _ in range(100):
        r=c.get('/api/analysis/'+rid+'/results').json()
        if r['status'] in ['complete','failed']:break
        time.sleep(.02)
    assert r['status']=='complete',r;return r

def test_full_workflow(client):
    did=upload(client);assert len(client.get('/api/datasets/'+did).json()['preview'])==12
    start=client.post('/api/analysis/run',json={'dataset_id':did});assert start.status_code==202
    rid=start.json()['id'];r=wait(client,rid);assert r['result']['counts']['alerts']>0
    alerts=client.get('/api/alerts',params={'run_id':rid}).json();aid=alerts[0]['id'];assert len(aid)==32
    assert client.patch('/api/alerts/'+aid,json={'status':'Investigating','notes':'Reviewed source IDs'}).status_code==200
    assert client.get('/api/alerts',params={'run_id':rid}).json()[0]['notes']=='Reviewed source IDs'
    assert client.get('/api/episodes',params={'run_id':rid}).json();assert client.get('/api/correlations',params={'run_id':rid}).json()['edges']
    for fmt in ['pdf','csv','json']:
        response=client.get(f'/api/reports/{rid}/download?format={fmt}');assert response.status_code==200
        if fmt=='pdf':assert response.content.startswith(b'%PDF')
        if fmt=='json':assert '/synthetic/documents/' not in response.text
    with client.websocket_connect(f'/api/analysis/{rid}/stream') as ws:assert ws.receive_json()['status']=='complete'
    assert client.get('/api/events',params={'dataset_id':did,'operation':'Rename'}).json()['total']==3
    assert client.get('/api/events',params={'dataset_id':did,'size':2,'page':2}).json()['items'][0]['event_id'];assert client.get('/api/audit').json()
def test_auth_csrf_and_isolation(client):
    did=upload(client);assert client.post('/api/simulation/generate',json={'scenario':'Normal workload'},headers={'x-csrf-token':'wrong'}).status_code==403
    with TestClient(app) as stranger:assert stranger.get('/api/datasets').status_code==401
    with Session() as db:db.add(User(username='other',password=password_hash('other-password-123'),role='viewer'));db.commit()
    with TestClient(app) as other:
        r=other.post('/api/auth/login',json={'username':'other','password':'other-password-123'});other.headers['x-csrf-token']=r.json()['csrf'];assert other.get('/api/datasets/'+did).status_code==404;assert other.post('/api/simulation/generate',json={'scenario':'Normal workload'}).status_code==403;assert other.get('/api/datasets').json()==[]
def test_validation_and_settings(client):
    assert client.post('/api/datasets/upload',files={'file':('bad.json','[]','application/json')}).status_code==422
    assert client.post('/api/datasets/upload',files={'file':('bad.json','{}','application/json')},data={'mapping':'[]'}).status_code==422
    assert client.put('/api/settings',json={'duration':5,'stride':10}).status_code==422
    assert client.put('/api/settings',json={'threshold':.7}).status_code==200;assert client.get('/api/settings').json()['threshold']==.7
    assert client.get('/api/events',params={'dataset_id':'missing','size':0}).status_code==422
def test_context_and_delete(client):
    did=upload(client);assert client.put('/api/datasets/'+did+'/context',json={'provenance':'Approved backup job JOB-123'}).status_code==200
    rid=client.post('/api/analysis/run',json={'dataset_id':did}).json()['id'];wait(client,rid);assert client.delete('/api/datasets/'+did).status_code==200
    assert client.get('/api/analysis/'+rid+'/results').status_code==404;assert not client.get('/api/alerts').json()
def test_logout(client):
    assert client.post('/api/auth/logout').status_code==200;assert client.get('/api/datasets').status_code==401

def test_static_and_api_documentation(client):
    assert 'FCBC Sentinel' in client.get('/').text
    assert client.get('/docs').status_code==200
    assert '/api/analysis/run' in client.get('/openapi.json').json()['paths']
