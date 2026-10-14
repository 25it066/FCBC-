def verify(event, previous):
    # A stable identity, explicit endpoints and an earlier observed source path
    # are all required. Equal timestamps never establish causal order.
    return bool(previous and previous['path']==event['rename_source'] and event['rename_target'] and event['rename_source']!=event['rename_target'] and previous['ts']<event['ts'] and event['path']==event['rename_target'])
