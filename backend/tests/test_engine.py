import json
import pytest
from app.detection.normalizer import normalize,parse
from app.detection.episode_builder import build
from app.detection.window_builder import windows
from app.detection.risk_engine import analyze,Config
from app.simulation.generator import generate
from app.evaluation.runner import metrics,evaluate

def event(**changes):return {'event_id':'1','host_id':'h','session_id':'s','file_namespace':'v','file_id':'f','process_id':'1','operation':'Read','path':'/a','timestamp':'2026-01-01T00:00:00Z',**changes}
@pytest.mark.parametrize('field',['timestamp','host_id','session_id','event_id','operation'])
def test_required(field):
    row=event();del row[field]
    with pytest.raises(ValueError,match='required'):normalize([row])
@pytest.mark.parametrize('timestamp',['not-time','2026-01-01T00:00:00','99999-01-01T00:00:00Z'])
def test_bad_time(timestamp):
    with pytest.raises(ValueError):normalize([event(timestamp=timestamp)])
def test_duplicate_scope():
    with pytest.raises(ValueError,match='duplicate'):normalize([event(),event()])
    assert len(normalize([event(),event(host_id='other')]))==2
def test_ordering_and_original():
    rows=normalize([event(event_id='2',timestamp='2026-01-01T00:00:02Z'),event(operation='READ')]);assert rows[0]['event_id']=='1';assert rows[0]['original_operation']=='READ'
@pytest.mark.parametrize('field',['host_id','session_id','file_namespace'])
def test_identity_boundaries(field):assert len(build(normalize([event(),event(event_id='2',**{field:'other'})])))==2
def test_no_path_identity():
    rows=normalize([event(file_id=None),event(event_id='2',file_id=None)]);assert build(rows)==[];assert analyze(rows,Config())['windows'][0]['score'] is None
def test_missing_namespace():assert not build(normalize([event(file_namespace=None)]))
def test_valid_and_invalid_lineage():
    rows=normalize([event(),event(event_id='2',timestamp='2026-01-01T00:00:01Z',operation='Rename',rename_source='/a',rename_target='/b',path='/b')]);assert build(rows)[0]['renames'][0]['verified'];rows[1]['rename_source']='/unseen';assert not build(rows)[0]['renames'][0]['verified']
def test_tied_timestamp_not_verified():assert not build(normalize([event(),event(event_id='2',operation='Rename',rename_source='/a',rename_target='/b',path='/b')]))[0]['renames'][0]['verified']
def test_episode_idle_boundary():assert len(build(normalize([event(),event(event_id='2',timestamp='2026-01-01T00:02:00Z')]),60))==2
def test_window_half_open_and_separation():
    rows=normalize([event(),event(event_id='2',timestamp='2026-01-01T00:00:10Z'),event(event_id='3',host_id='other')]);w=list(windows(rows,10,10,'include'));assert len(w)==3;assert [e['event_id'] for e in w[0]['events']]==['1'];assert w[1]['events'][0]['event_id']=='2'
def test_incomplete_drop():assert not list(windows(normalize([event()]),10,10,'drop'))
def test_feature_math_and_reproducibility():
    rows=generate('Ransomware-like disruption',42,1);one=analyze(rows,Config());two=analyze(rows,Config());w=one['windows'][0];assert w['features']=={'D':1,'C':1,'P':1,'X':.75,'B':None};assert w['score']==.95;assert one['windows']==two['windows'];assert one['manifest']==two['manifest'];assert len(w['evidence'])==4
def test_missing_pid_withholds_score():
    rows=generate('Ransomware-like disruption',42,1);rows[0]['process_id']=None;assert analyze(rows,Config())['windows'][0]['score'] is None
@pytest.mark.parametrize('scenario',['Normal workload','Backup workload','File synchronization','Compression','Harmless distributed activity'])
def test_benign_controls(scenario):assert all(w['classification']!='Review' for w in analyze(generate(scenario),Config())['windows'])
def test_untrusted_context():assert analyze(normalize([event(process_id='backup.exe',authorized=True)]),Config())['windows'][0]['features']['B'] is None
def test_verified_context_discount():
    w=analyze(generate('Backup workload'),Config(),{'provenance':'approved fixture'})['windows'][0];assert w['features']['B']==1;assert w['score']==-.2
def test_metrics_exact():
    m=metrics([True,True,False,False],[True,False,True,False]);assert m['f1']==.5;assert m['false_positive_rate']==.5;assert m['confusion_matrix']=={'TP':1,'TN':1,'FP':1,'FN':1}
def test_evaluation_split_integrity():
    r=evaluate(42,Config());v={g['id'] for g in r['groups'] if g['split']=='validation'};t={g['id'] for g in r['groups'] if g['split']=='test'};assert not v&t;assert len(v)==len(t)==18;assert len(r['methods'])==6
    for d in r['details']:assert r['methods'][d['method']]==metrics(d['test_labels'],[s>=r['thresholds'][d['method']] for s in d['test_scores']])
def test_parsers_and_mapping():
    r=event();assert parse(json.dumps([r]).encode(),'trace.json',{})[0]['event_id']=='1';assert parse(json.dumps(r).encode(),'trace.jsonl',{})[0]['event_id']=='1';r['Time']=r.pop('timestamp');assert parse(json.dumps([r]).encode(),'trace.json',{'timestamp':'Time'})[0]['event_id']=='1';assert len(parse(b'event_id,timestamp,host_id,session_id,operation\n1,2026-01-01T00:00:00Z,h,s,Read\n','trace.csv',{}))==1
@pytest.mark.parametrize('filename,data',[('x.exe',b'hello'),('x.json',b'{}'),('x.json',b'[]'),('x.csv',b'bad\nrows'),('x.json',b'\xff')])
def test_invalid_upload(filename,data):
    with pytest.raises((ValueError,UnicodeError)):parse(data,filename,{})
