from .identity_resolver import identity,reference
from .rename_lineage import verify

def build(events,gap=60,rename_enabled=True):
    episodes=[];active={};previous={}
    for e in events:
        key=identity(e)
        if key is None: continue
        ep=active.get(key)
        if ep is None or e['ts']-ep['end']>gap:
            ep={'id':f'EP-{len(episodes)+1:05}','identity':list(key),'events':[],'processes':[],'renames':[],'warnings':[],'start':e['ts'],'end':e['ts']}
            episodes.append(ep);active[key]=ep;previous.pop(key,None)
        if e['operation']=='Rename':
            proven=verify(e,previous.get(key))
            ep['renames'].append({'event_id':e['event_id'],'source':e['rename_source'],'target':e['rename_target'],'verified':proven and rename_enabled,'evidence':([reference(previous[key]),reference(e)] if proven and rename_enabled else []),'reason':'Stable identity and observed prior source path' if proven and rename_enabled else 'Insufficient evidence or lineage ablated'})
            if not proven: ep['warnings'].append('Unverified rename: '+e['event_id'])
        ep['events'].append(e);ep['end']=e['ts']
        if e['process_id'] is not None and e['process_id'] not in ep['processes']:ep['processes'].append(e['process_id'])
        previous[key]=e
    return episodes
