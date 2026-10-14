from .episode_builder import build

def features(events,cfg,benign_context):
    eps=build(events,cfg.episode_gap,cfg.rename_enabled)
    disrupted=[];progressed=[]
    for ep in eps:
        verified={r['event_id'] for r in ep['renames'] if r['verified']}
        changes=[e for e in ep['events'] if e['operation']=='Delete' or e['event_id'] in verified]
        writes=[e for e in ep['events'] if e['operation']=='Write']
        reads=[e for e in ep['events'] if e['operation']=='Read']
        first_write=min((w['ts'] for w in writes),default=float('inf'))
        last_change=max((d['ts'] for d in changes),default=float('-inf'))
        first_read=min((r['ts'] for r in reads),default=float('inf'))
        next_write=min((w['ts'] for w in writes if w['ts']>first_read),default=float('inf'))
        disrupted.append(first_write<last_change)
        progressed.append(next_write<last_change)
    count=len(eps)
    known=sum(len(ep['events']) for ep in eps)
    coverage=known/len(events)
    pid_available=all(e['process_id'] is not None for ep in eps for e in ep['events'])
    feature={'D':sum(disrupted)/count if count else None,'C':sum(len(ep['processes'])>1 for ep in eps)/count if count and pid_available else None,'P':sum(progressed)/count if count else None,'X':sum(e['operation'] in cfg.destructive_operations for e in events)/len(events),'B':None}
    # Benign evidence is a separately analyst-attested context, never a workload name.
    if benign_context:
        feature['B']=sum(e['operation'] in ['Read','Create','Metadata change'] for e in events)/len(events)
    warnings=[]
    if coverage<1:warnings.append(f'Stable identity coverage {coverage:.1%}; unresolved events excluded from episode features')
    if feature['C'] is None:warnings.append('Cross-process evidence unavailable')
    if not benign_context:warnings.append('Benign context unavailable; no benign discount applied')
    warnings+=sorted({flag for e in events for flag in e['quality_flags']})
    return feature,eps,coverage,warnings
