import time
import json
import base64
from nacl.signing import SigningKey

def expire_all(sk, *, delta=120, timestamp=None):
    ts = timestamp if timestamp else int((time.time() + delta) * 1000)
    return json.dumps({
        "pubkey": sk.verify_key.encode().hex(),
        "expiry": ts,
        "signature": base64.b64encode(sk.sign(b"expire_all" + str(ts).encode()).signature).decode()},
        separators=(',',':'))

def expire_msgs(sk, messages, *, delta=120, timestamp=None):
    ts = timestamp if timestamp else int((time.time() + delta) * 1000)
    return json.dumps({
        "pubkey": sk.verify_key.encode().hex(),
        "expiry": ts,
        "messages": messages,
        "signature": base64.b64encode(sk.sign(b"expire" + ("".join(messages) + str(ts)).encode()).signature).decode()},
        separators=(',',':'))

def delete_all(sk):
    ts = int(time.time() * 1000)
    return json.dumps({
        "pubkey": sk.verify_key.encode().hex(),
        "expiry": ts,
        "signature": base64.b64encode(sk.sign(b"delete_all" + str(ts).encode()).signature).decode()},
        separators=(',',':'))

def delete_msgs(sk, messages):
    return json.dumps({
        "pubkey": sk.verify_key.encode().hex(),
        "messages": messages,
        "signature": base64.b64encode(sk.sign(b"delete" + "".join(messages).encode()).signature).decode()},
        separators=(',',':'))

def delete_before(sk, *, ago=120, timestamp=None):
    before = timestamp if timestamp else int((time.time() - ago) * 1000)
    return json.dumps({
        "pubkey": sk.verify_key.encode().hex(),
        "before": before,
        "signature": base64.b64encode(sk.sign(b"delete_before" + str(before).encode()).signature).decode()},
        separators=(',',':'))




def get_swarm(omq, conn, sk):
    r = omq.request(conn, "storage.get_swarm", [json.dumps({"pubkey": sk.verify_key.encode().hex()}).encode()])
    assert(len(r) == 1)
    return json.loads(r[0])
