import csv, io, json, math
from datetime import datetime, timezone
OPS={'read':'Read','write':'Write','create':'Create','rename':'Rename','delete':'Delete','metadata change':'Metadata change','metadata_change':'Metadata change'}
def parse(data:bytes, filename:str, mapping:dict):
    if len(data)>10*1024*1024: raise ValueError('Maximum upload is 10 MiB')
    text=data.decode('utf-8-sig')
    if filename.lower().endswith('.jsonl'): rows=[json.loads(x) for x in text.splitlines() if x.strip()]
    elif filename.lower().endswith('.json'):
        rows=json.loads(text)
        if isinstance(rows,dict): rows=rows.get('events')
    elif filename.lower().endswith('.csv'): rows=list(csv.DictReader(io.StringIO(text)))
    else: raise ValueError('Use CSV, JSON or JSONL telemetry')
    if not isinstance(rows,list) or not rows or len(rows)>50000: raise ValueError('Expected 1–50,000 event objects')
    return normalize([{**r,**{k:r.get(v) for k,v in mapping.items()}} if isinstance(r,dict) else r for r in rows])
def normalize(rows):
    result=[];seen=set()
    for i,r in enumerate(rows):
        if not isinstance(r,dict): raise ValueError(f'Row {i+1}: expected object')
        for key in ['event_id','timestamp','host_id','session_id','operation']:
            if r.get(key) is None or not str(r[key]).strip(): raise ValueError(f'Row {i+1}: {key} required')
        try:
            dt=datetime.fromisoformat(str(r['timestamp']).replace('Z','+00:00'))
            if dt.tzinfo is None: raise ValueError()
            ts=dt.timestamp()
            if not math.isfinite(ts): raise ValueError()
        except Exception: raise ValueError(f'Row {i+1}: timestamp needs ISO 8601 and timezone')
        op=OPS.get(str(r['operation']).strip().lower())
        if not op: raise ValueError(f'Row {i+1}: unsupported operation {r["operation"]}')
        event={k:None if r.get(k) in (None,'') else str(r[k]) for k in ['event_id','host_id','session_id','process_id','file_id','path','rename_source','rename_target','file_namespace']}
        key=(event['host_id'],event['session_id'],event['event_id'])
        if key in seen: raise ValueError(f'Row {i+1}: duplicate scoped event ID')
        seen.add(key)
        flags=r.get('quality_flags',[])
        if isinstance(flags,str): flags=[flags] if flags else []
        if not isinstance(flags,list) or any(not isinstance(x,str) for x in flags): raise ValueError('quality_flags must be a list of strings')
        flags=list(flags)
        for k in ['file_id','process_id','file_namespace','path']:
            if event[k] is None: flags.append(f'{k} unavailable')
        event.update(timestamp=dt.astimezone(timezone.utc).isoformat(),ts=ts,operation=op,original_operation=str(r['operation']),source_event_id=r.get('source_event_id',r['event_id']),quality_flags=flags,source=r)
        result.append(event)
    return sorted(result,key=lambda e:(e['ts'],e['host_id'],e['session_id'],e['event_id']))
