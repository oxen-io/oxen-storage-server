import time
import json
import base64
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.signing import SigningKey
from nacl.hash import blake2b
import random

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


def get_swarm(omq, conn, sk, netid=5):
    pubkey = "{:02x}".format(netid) + (sk.verify_key if isinstance(sk, SigningKey) else sk.public_key).encode().hex()
    r = omq.request_future(conn, "storage.get_swarm", [json.dumps({"pubkey": pubkey}).encode()]).get()
    assert(len(r) == 1)
    return json.loads(r[0])


def random_swarm_members(swarm, n, exclude={}):
    return random.sample([s for s in swarm['snodes'] if s['pubkey_ed25519'] not in exclude], n)


def store_n(omq, conn, sk, basemsg, n, *, offset=0, netid=5):
    msgs = []
    pubkey = chr(netid).encode() + (sk.verify_key if isinstance(sk, SigningKey) else sk.public_key).encode()
    for i in range(n):
        data = basemsg + f"{i}".encode()
        ts = int((time.time() - i) * 1000)
        exp = int((time.time() - i + 30) * 1000)
        msgs.append({
                "data": data,
                "req": {
                    "pubkey": pubkey.hex(),
                    "timestamp": ts,
                    "expiry": exp,
                    "data": base64.b64encode(data).decode()}
                })
        msgs[-1]['future'] = omq.request_future(conn, "storage.store", [json.dumps(msgs[-1]['req']).encode()])
        msgs[-1]['hash'] = blake2b("{}{}".format(ts, exp).encode() + pubkey + msgs[-1]['data'],
                encoder=Base64Encoder).decode().rstrip('=')

    assert len({m['hash'] for m in msgs}) == len(msgs)

    for m in msgs:
        resp = m['future'].get()
        assert len(resp) == 1
        m['store'] = json.loads(resp[0].decode())

        assert len(m['store']['swarm']) >= 5
        assert not any('failed' in v for v in m['store']['swarm'].values())
        assert all(v['hash'] == m['hash'] for v in m['store']['swarm'].values())

    return msgs
