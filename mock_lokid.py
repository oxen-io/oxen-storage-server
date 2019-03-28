import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SWARMS = """0 s5ejmf538y6kk7rxmpx9aei9fze11ox84wuakzmogkenffi7yeqy.snode e3eai9uukrm1khk8w9exji1pu5bo4jmzz4gwyzyoyx6hqssge3jo.snode\n
1 zn7s1zdxsznutq4acjnrf8d6i6n4sodshotw1xwsujw5ur863e7o.snode bhbd9pp5s33x1mxyc9mqo7mzd51rkzeoft7833716abn31tuakmo.snode\n
2 az6w6yo5x7s8haubja737b64dq41hpwk33mc133nadyeumgkuo7y.snode we1qu4uq6oji1ciochaknfazaj1yn1x6dposnopn6wuju3d5gb7o.snode\n
3 p8xkou5gfy87bmaw8whk9bhzfr7xzqjscqjszmmcc67gedcyiaxy.snode 9pwnzq1ddk3yb1d8oa6qg8mup7yzze149jw8c96x7bnshjik4hxo.snode\n
4 ur7qa4czknecknfirpyaprubwpmzmmqtasafawipnrr4prykfzbo.snode o7drfi546edwq8pqhdf5hpof8ib4adenfzfexgagmh9bo868ndfy.snode
"""


class lokidHandler(BaseHTTPRequestHandler):
  def do_POST(self):
    if self.path != '/json_rpc':
      # Only doing json_rpc
      self.send_response(404)
      self.end_headers()
      return

    length = self.headers.get('Content-Length')
    if not length:
      self.send_response(404)
      self.end_headers()
      return

    message = self.rfile.read(int(length))
    j = json.loads(message)
    if j['method']!= 'get_service_nodes':
      self.send_response(405)
      self.end_headers()
      return

    self.send_response(200)
    self.send_header('Content-Type', 'application/json')
    self.end_headers()
    self.wfile.write(bytes(SWARMS, "utf8"))

def run():
  # Server settings
  server_address = ('127.0.0.1', 7777)
  httpd = HTTPServer(server_address, lokidHandler)
  print('running server...')
  httpd.serve_forever()

run()
