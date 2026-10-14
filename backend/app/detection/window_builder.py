from collections import defaultdict
import math

def windows(events,duration,stride,incomplete):
    groups=defaultdict(list)
    for e in events:groups[(e['host_id'],e['session_id'])].append(e)
    count=0;references=0
    for scope,rows in sorted(groups.items()):
        first=rows[0]['ts'];last=rows[-1]['ts'];steps=math.floor((last-first)/stride)+1
        if steps>10000:raise ValueError('Time range creates too many windows; increase stride or split the dataset')
        for i in range(steps):
            start=first+i*stride;end=start+duration;partial=end>last
            if partial and incomplete=='drop':continue
            selected=[e for e in rows if start<=e['ts']<end]
            if not selected:continue
            count+=1
            references+=len(selected)
            if references>250000:raise ValueError("Overlapping windows exceed 250,000 evidence references; increase stride or split dataset")
            if count>10000:raise ValueError('Maximum 10,000 windows')
            yield {'id':f'W-{count:05}','host_id':scope[0],'session_id':scope[1],'start':start,'end':end,'incomplete':partial,'events':selected}
