# loki-storage-server
Storage server for Loki Service Nodes

```
mkdir build
cd build
cmake .. -DBOOST_ROOT="path to boost"
cmake --build .
./httpserver 127.0.0.1 8080
```

Then using something like Postman (https://www.getpostman.com/) you can hit the API:

# post data
```
HTTP POST http://127.0.0.1/store
body: "hello world"
headers:
- X-Loki-recipient: "mypubkey"
- X-Loki-ttl: "86400"
- X-Loki-timestamp: "1540860811000"
- X-Loki-pow-nonce: "xxxx..."
```
# get data
```
HTTP GET http://127.0.0.1/retrieve
headers:
- X-Loki-recipient: "mypubkey"
- X-Loki-last-hash: "" (optional)
```
