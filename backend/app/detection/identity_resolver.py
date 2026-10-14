def identity(e):
    if e['file_id'] is None or e['file_namespace'] is None: return None
    return (e['host_id'],e['session_id'],e['file_namespace'],e['file_id'])
def reference(e): return {'host_id':e['host_id'],'session_id':e['session_id'],'event_id':e['event_id']}
