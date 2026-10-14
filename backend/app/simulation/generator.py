from datetime import datetime,timezone,timedelta
import random
from ..detection.normalizer import normalize
SCENARIOS=['Normal workload','Backup workload','File synchronization','Compression','Harmless distributed activity','Ransomware-like disruption']
def generate(scenario,seed=42,files=20,session='simulation'):
    if scenario not in SCENARIOS:raise ValueError('Unknown scenario')
    rng=random.Random(seed);rows=[];base=datetime(2026,1,1,tzinfo=timezone.utc)
    for i in range(files):
        operations={'Normal workload':['Read','Metadata change'],'Backup workload':['Read','Read','Metadata change'],'File synchronization':['Read','Write'],'Compression':['Read','Read','Read'],'Harmless distributed activity':['Read','Write','Read'],'Ransomware-like disruption':['Read','Write','Rename','Delete']}[scenario]
        path=f'/synthetic/documents/file-{i}.txt'
        for j,op in enumerate(operations):
            old=path
            if op=='Rename':path+='.changed'
            row={'event_id':f'{session}-{i}-{j}','timestamp':(base+timedelta(seconds=i*.8+j*.15+rng.random()*.03)).isoformat(),'host_id':'SYNTHETIC-HOST','session_id':session,'file_namespace':'synthetic-volume','file_id':f'file-{i}','path':path,'process_id':str(100+j%3 if 'distributed' in scenario or 'disruption' in scenario else 100),'operation':op}
            if op=='Rename':row.update(rename_source=old,rename_target=path)
            rows.append(row)
    return normalize(rows)
