#!/usr/bin/env python3
"""Python TCP scanner and protocol enumeration. No external scanner commands."""
import argparse
import concurrent.futures as futures
from datetime import datetime
import errno
import ftplib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time
from reporting import write_report

COMMON=[21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,27017]
HTTP_PORTS={80,8000,8080,8888}; TLS_HTTP_PORTS={443,8443}

def target_input(value):
 value=value.strip()
 try: return str(ipaddress.ip_address(value))
 except ValueError: pass
 if len(value)>253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',value): raise ValueError('Enter one IP or hostname, without URL, CIDR or options.')
 if any(not p or len(p)>63 or p.startswith('-') or p.endswith('-') for p in value.split('.')): raise ValueError('Invalid hostname')
 return value

def port_list(value):
 result=set()
 if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*',value): raise ValueError('Use ports like 22,80,443 or 1-1024')
 for item in value.split(','):
  parts=list(map(int,item.split('-'))); a=parts[0]; b=parts[-1]
  if not 1<=a<=b<=65535: raise ValueError('Ports must be between 1 and 65535; ranges must ascend')
  result.update(range(a,b+1))
 return sorted(result)

def connect(address,port,timeout):
 return socket.create_connection((address,port),timeout=timeout)

def scan_port(address,port,timeout):
 try:
  with connect(address,port,timeout): return port,'open'
 except OSError as e:
  return port,'closed' if e.errno==errno.ECONNREFUSED else 'timeout-or-error'

def tls_info(address,host,port,timeout):
 evidence={}
 context=ssl.create_default_context()
 try:
  with connect(address,port,timeout) as raw:
   with context.wrap_socket(raw,server_hostname=host) as s:
    evidence={'certificate_validated':True,'certificate':s.getpeercert(),'protocol':s.version(),'cipher':s.cipher()}
 except ssl.SSLCertVerificationError as e:
  evidence={'certificate_validated':False,'validation_error':str(e)}
  context=ssl._create_unverified_context()
  with connect(address,port,timeout) as raw:
   with context.wrap_socket(raw,server_hostname=host) as s:
    evidence.update({'protocol':s.version(),'cipher':s.cipher(),'certificate_der_bytes':len(s.getpeercert(binary_form=True))})
 return evidence

class PinnedHTTPS(http.client.HTTPSConnection):
 def __init__(self,host,address,port,timeout):
  super().__init__(host,port,timeout=timeout,context=ssl._create_unverified_context()); self.address=address
 def connect(self):
  self.sock=self._context.wrap_socket(connect(self.address,self.port,self.timeout),server_hostname=self.host)

def http_enum(address,host,port,timeout,tls=False):
 conn=PinnedHTTPS(host,address,port,timeout) if tls else http.client.HTTPConnection(address,port,timeout=timeout)
 try:
  host_header=('['+host+']') if ':' in host else host
  conn.request('GET','/',headers={'Host':host_header+':'+str(port),'User-Agent':'Python-TargetScan/1.0','Connection':'close','Accept-Encoding':'identity'})
  response=conn.getresponse(); body=response.read(65536).decode('utf-8',errors='replace')
  match=re.search(r'<title\b[^>]*>(.*?)</title>',body,re.I|re.S)
  return {'status':response.status,'reason':response.reason,'headers':response.getheaders(),'title':re.sub(r'\s+',' ',match.group(1)).strip()[:500] if match else None,'body_limit_bytes':65536,'redirect_followed':False}
 finally: conn.close()

def enumerate_port(address,host,port,timeout,anonymous=False):
 row={'port':port,'protocol':'tcp','state':'open','service':{'name':'unknown'},'scripts':[]}
 def evidence(name,data): row['scripts'].append({'id':name,'output':json.dumps(data,indent=2,ensure_ascii=True)})
 def attempt(name,fn):
  try: return fn()
  except (OSError,ValueError,EOFError,ftplib.Error,http.client.HTTPException) as e:
   evidence(name+'-error',{'status':'unknown','error':str(e)[:500]}); return None
 if port in HTTP_PORTS|TLS_HTTP_PORTS:
  secure=port in TLS_HTTP_PORTS
  if secure:
   details=attempt('tls',lambda:tls_info(address,host,port,timeout))
   if details: evidence('tls',details)
  details=attempt('http',lambda:http_enum(address,host,port,timeout,secure))
  if details: row['service']['name']='https' if secure else 'http'; evidence('http',details)
 else:
  def banner():
   with connect(address,port,timeout) as s: return s.recv(2048).decode('utf-8',errors='replace').strip()
  text=attempt('banner',banner)
  if text:
   evidence('banner',text)
   if text.startswith('SSH-'): row['service']['name']='ssh'; row['service']['version']=text[:200]
   elif text.startswith('220') and ('ftp' in text.lower() or port==21): row['service']['name']='ftp'
   elif text.startswith('220') and (port in (25,587) or 'smtp' in text.lower()): row['service']['name']='smtp'
   else: row['service']['name']='unknown (banner observed)'
  if row['service']['name']=='ftp' or port==21:
   def ftp_check():
    ftp=ftplib.FTP(timeout=timeout)
    try:
     greeting=ftp.connect(address,port); result={'greeting':greeting,'syst':ftp.sendcmd('SYST')}
     row['service']['name']='ftp'
     if anonymous:
      try: result['anonymous_login']=ftp.login('anonymous','audit@example.invalid')
      except ftplib.error_perm as e: result['anonymous_login']=str(e)
     return result
    finally: ftp.close()
   details=attempt('ftp',ftp_check)
   if details: evidence('ftp',details)
  if row['service']['name']=='smtp' or port in (25,587):
   def smtp_check():
    import smtplib
    client=smtplib.SMTP(timeout=timeout)
    try:
     client.connect(address,port); code,message=client.ehlo('audit.example.invalid')
     if code!=250: raise ValueError('EHLO rejected: '+str(code))
     row['service']['name']='smtp'; return {'ehlo':message.decode(errors='replace'),'extensions':client.esmtp_features}
    finally: client.close()
   details=attempt('smtp',smtp_check)
   if details: evidence('smtp',details)
 return row

def analyze(rows):
 found=[]
 for row in rows:
  for item in row['scripts']:
   if item['id']=='tls':
    data=json.loads(item['output'])
    if data.get('certificate_validated') is False: found.append({'severity':'Medium','title':'TLS certificate validation failed from scanner','endpoint':str(row['port'])+'/tcp','evidence':data['validation_error'],'recommendation':'Review expiry, hostname, chain and scanner trust store. Private lab CAs can legitimately be untrusted.'})
   if item['id']=='ftp':
    data=json.loads(item['output'])
    if str(data.get('anonymous_login','')).startswith('230'): found.append({'severity':'Medium','title':'Anonymous FTP login accepted','endpoint':str(row['port'])+'/tcp','evidence':data['anonymous_login'],'recommendation':'Confirm intended access and restrict permissions; no files were listed or downloaded.'})
 return found

def main():
 ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('target',nargs='?'); ap.add_argument('--ports'); ap.add_argument('--all-ports',action='store_true'); ap.add_argument('--address'); ap.add_argument('--timeout',type=float,default=2); ap.add_argument('--workers',type=int,default=40); ap.add_argument('--anonymous-ftp',action='store_true'); ap.add_argument('--output',default='reports')
 args=ap.parse_args()
 if not 0.1<=args.timeout<=30 or not 1<=args.workers<=100: ap.error('Timeout: 0.1-30 seconds; workers: 1-100')
 if args.ports and args.all_ports: ap.error('Choose --ports or --all-ports')
 try:
  host=target_input(args.target or input('Target IP or hostname: ')); addresses=sorted({r[4][0] for r in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)})
  address=str(ipaddress.ip_address(args.address)) if args.address else next((a for a in addresses if ':' not in a),addresses[0])
  if address not in addresses: raise ValueError('--address must match a resolved IP')
  ports=list(range(1,65536)) if args.all_ports else port_list(args.ports) if args.ports else COMMON
 except (ValueError,OSError) as e: ap.error(str(e))
 os.umask(0o077); out=Path(args.output)/datetime.now().strftime('%Y%m%d-%H%M%S-%f'); out.mkdir(parents=True)
 print(f'Scanning {host} at pinned IP {address}; {len(ports)} TCP ports')
 results=[]
 with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
  for result in pool.map(lambda p:scan_port(address,p,args.timeout),ports): results.append(result)
 opened=[p for p,state in results if state=='open']; print('Open ports: '+str(opened))
 (out/'ports.json').write_text(json.dumps(results,indent=2))
 rows=[]
 def make_data():
  return {'target':host,'address':address,'resolved':addresses,'time':datetime.now().astimezone().isoformat(),'options':{'port_count':len(ports),'timeout_seconds':args.timeout,'workers':args.workers,'anonymous_ftp':args.anonymous_ftp,'port_states':{s:sum(state==s for _,state in results) for s in ['open','closed','timeout-or-error']},'limitations':'TCP only. No OS fingerprint, SMB enumeration, UDP or CVE lookup. HTTP tested on 80,443,8000,8080,8443,8888 only. SSH banner only.'},'stages':[{'name':'Python TCP scan + protocol enumeration','status':'completed','hosts':[{'status':'reachable' if opened else 'unconfirmed','reason':'TCP connection observed' if opened else 'No successful TCP connection','ports':rows,'scripts':[],'os':[]}]}],'findings':analyze(rows)}
 for port in opened:
  print('Enumerating '+str(port),flush=True); rows.append(enumerate_port(address,host,port,args.timeout,args.anonymous_ftp)); (out/'report.json').write_text(json.dumps(make_data(),indent=2))
 data=make_data(); (out/'report.json').write_text(json.dumps(data,indent=2)); write_report(data,out/'report.pdf'); print('PDF: '+str((out/'report.pdf').resolve()))

if __name__=='__main__':
 try: main()
 except KeyboardInterrupt: print('Interrupted; completed evidence remains in reports.'); raise SystemExit(130)
