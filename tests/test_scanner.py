import socket
import threading
import unittest
from http.server import HTTPServer,BaseHTTPRequestHandler
from targetscan import scan_port,enumerate_port,http_enum,port_list,target_input,analyze
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.send_header('X-Host-Received',self.headers.get('Host'));self.end_headers();self.wfile.write(b'<title>Local lab</title>')
 def log_message(self,*args): pass
class Tests(unittest.TestCase):
 def test_input(self):
  for x in ['-sV','https://host','a;id','a..b','192.0.2.0/24']:
   with self.assertRaises(ValueError):target_input(x)
  self.assertEqual(port_list('22,80-82'),[22,80,81,82])
 def test_http_live_loopback(self):
  server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
  try:
   port=server.server_port;self.assertEqual(scan_port('127.0.0.1',port,1)[1],'open')
   result=http_enum('127.0.0.1','lab.example',port,1);self.assertEqual(result['title'],'Local lab');self.assertEqual(dict(result['headers'])['X-Host-Received'],'lab.example:'+str(port))
  finally:server.shutdown();server.server_close();thread.join()
 def test_ssh_live_loopback(self):
  s=socket.socket();s.bind(('127.0.0.1',0));s.listen();port=s.getsockname()[1]
  def serve():
   conn,_=s.accept()
   with conn:conn.sendall(b'SSH-2.0-LabServer\r\n')
  t=threading.Thread(target=serve);t.start()
  try:self.assertEqual(enumerate_port('127.0.0.1','localhost',port,1)['service']['name'],'ssh')
  finally:t.join();s.close()
 def test_banner_not_vulnerability(self):
  self.assertEqual(analyze([{'port':22,'scripts':[{'id':'banner','output':'old software'}]}]),[])
if __name__=='__main__':unittest.main()
