import json
def write_report(data, path):
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from xml.sax.saxutils import escape
    styles=getSampleStyleSheet(); styles['BodyText'].fontSize=9; styles['BodyText'].leading=13; styles['BodyText'].wordWrap='CJK'
    def p(s,style='BodyText'): return Paragraph(escape(str(s)).replace('\n','<br/>'),styles[style])
    story=[p('TARGETSCAN','Title'),p('Network assessment and service enumeration','Heading2'),Spacer(1,12),p(data['target'],'Heading1'),p('Pinned address: '+data['address']),p(data['time']),Spacer(1,15),p('Assessment summary','Heading2'),p('Workflow: discovery, port scan, version detection, then enumeration of discovered services.'),p('Scope: one pinned IP. Website results may describe a CDN or shared frontend; origin servers are not discovered. Versions and OS fingerprints are estimates, not confirmed vulnerabilities.')]
    table=Table([[p('Stage'),p('Status'),p('Hosts recorded')]]+[[p(s['name']),p(s['status']),p(len(s.get('hosts',[])))] for s in data['stages']],colWidths=[230,120,120])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#dceaf1')),('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),9)]))
    story += [Spacer(1,12),table,Spacer(1,12),p(f"{len(data['findings'])} rule-based findings. No numerical security score is assigned."),p('Failed, timed-out and unanswered checks are unknown. An empty finding list is not evidence that a target is secure.'),PageBreak(),p('Findings and next steps','Heading1')]
    for f in data['findings']:
        story += [p(f['severity']+' | '+f['title'],'Heading2'),p(f['endpoint']),p(f['evidence']),p('Recommendation: '+f['recommendation']),Spacer(1,12)]
    if not data['findings']: story.append(p('No supported rule produced a finding. Review discovered services and coverage below.'))
    story += [p('Scan scope','Heading2'),p(json.dumps(data['options'],indent=2)),p('All resolved addresses (only the pinned address was scanned): '+', '.join(data['resolved'])),PageBreak(),p('Service inventory and evidence','Heading1')]
    for s in data['stages']:
        story += [p(s['name']+' | '+s['status'],'Heading2')]
        if s.get('error'): story.append(p(s['error']))
        if not s.get('hosts'): story.append(p('No host results recorded.'))
        for h in s.get('hosts',[]):
            story += [p('Host status: '+h['status']+'; reason: '+h['reason'])]
            for port in h['ports']:
                svc=port['service']
                story += [p(f"{port['port']}/{port['protocol']} | {port['state']} | {svc.get('name','unknown')}",'Heading3'),p(' '.join(svc.get(k,'') for k in ['product','version','extrainfo']))]
                for script in port['scripts']: story += [p(script['id'],'Heading4'),p(script['output'][:6000])]
            for script in h['scripts']: story += [p(script['id'],'Heading3'),p(script['output'][:6000])]
            if h['os']: story.append(p('OS guesses: '+json.dumps(h['os'])))
    story += [p('Interpretation','Heading2'),p('open: listener detected. filtered: probes blocked or unanswered. timeout: unanswered or filtered; not proof of a closed port. Unknown services remain unknown; unsuccessful enumeration is inconclusive. TCP coverage is the selected port set. UDP and OS fingerprinting are not implemented. PDF script excerpts stop at 6000 characters; JSON retains collected evidence.')]
    def footer(c,d):
        c.setFont('Helvetica',8); c.drawString(36,22,'TargetScan | Authorized target assessment'); c.drawRightString(559,22,str(d.page))
    SimpleDocTemplate(str(path),leftMargin=36,rightMargin=36,topMargin=40,bottomMargin=40).build(story,onFirstPage=footer,onLaterPages=footer)

