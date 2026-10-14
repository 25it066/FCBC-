import io,json,csv,hashlib
from xml.sax.saxutils import escape
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing,Line,String

def redact(value):
    if isinstance(value,list):return [redact(v) for v in value]
    if isinstance(value,dict):return {k:('path:'+hashlib.sha256(str(v).encode()).hexdigest()[:12] if v is not None and k in ['path','rename_source','rename_target','source','target'] and not isinstance(v,dict) else redact(v)) for k,v in value.items() if k!='source' or not isinstance(v,dict)}
    return value
def export(data,fmt):
    data=redact(data)
    if fmt=='json':return json.dumps(data,indent=2).encode(),'application/json'
    if fmt=='csv':
        buf=io.StringIO();w=csv.writer(buf);w.writerow(['window','host','session','start','end','score','threshold','classification','D','C','P','X','B','event_ids'])
        def safe(x):
            s=str(x)
            return "'"+s if s[:1] in '=+-@\t\r' else s
        for x in data['result']['windows']:w.writerow([safe(v) for v in [x['id'],x['host_id'],x['session_id'],x['start'],x['end'],x['score'],x['threshold'],x['classification'],*[x['features'][k] for k in 'DCPXB'],json.dumps(x['evidence'])]])
        return buf.getvalue().encode(),'text/csv'
    b=io.BytesIO();styles=getSampleStyleSheet();parts=[]
    def p(text,style='BodyText'):parts.extend([Paragraph(escape(str(text)),styles[style]),Spacer(1,8)])
    p('FCBC SENTINEL','Title');p('File-centered behavioral analysis · Research report','Heading2')
    p('Synthetic demonstration' if data['dataset']['synthetic'] else 'User-supplied recorded telemetry','Heading2')
    p('Research classifications only. No definitive malware diagnosis. Defaults have not been calibrated on real traces. Paths are tokenized. Source metadata is omitted.')
    p('Analysis run: '+data['id']);p('Dataset: '+data['dataset']['name']);p('Created (Unix UTC): '+str(data['created']));p('SHA-256: '+data['result']['manifest']['dataset_hash'])
    p('Summary','Heading2');p(json.dumps(data['result']['counts']))
    points=[x['score'] for x in data['result']['windows'] if x['score'] is not None]
    if points:
        drawing=Drawing(450,140);lo=min(0,min(points));hi=max(1,max(points));drawing.add(Line(20,20,440,20,strokeColor=colors.grey))
        for i in range(1,len(points)):drawing.add(Line(20+(i-1)*420/max(1,len(points)-1),20+(points[i-1]-lo)/(hi-lo)*100,20+i*420/max(1,len(points)-1),20+(points[i]-lo)/(hi-lo)*100,strokeColor=colors.HexColor('#007e9c')))
        drawing.add(String(20,126,'Eligible window risk scores',fontSize=10));parts.append(drawing)
    p('Configuration and reproducibility','Heading2');p(json.dumps(data['result']['manifest'],sort_keys=True))
    for w in data['result']['windows']:
        p(f"{w['id']} · {w['classification']} · score {w['score']} / threshold {w['threshold']}",'Heading2')
        p(f"Scope {w['host_id']} / {w['session_id']} · [{w['start']}, {w['end']})")
        p('Feature contributions: '+json.dumps(w['contributions']));p('Warnings: '+'; '.join(w['warnings']))
        p('Supporting events: '+', '.join(e['event_id'] for e in w['evidence']))
        for ep in w['episodes']:p(f"{ep['id']} | identity {ep['identity']} | processes {ep['processes']} | verified renames {sum(r['verified'] for r in ep['renames'])} | events "+', '.join(e['event_id'] for e in ep['events']))
    p('Evaluation','Heading2');p('Not evaluated for this dataset. Synthetic comparison experiments are exported separately from the Evaluation Lab.')
    SimpleDocTemplate(b,title='FCBC Sentinel Analysis',author='FCBC Sentinel',leftMargin=40,rightMargin=40).build(parts)
    return b.getvalue(),'application/pdf'
