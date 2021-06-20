import pyoxenmq
import ss
import time
import base64
import random
import json
from nacl.encoding import HexEncoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey

def test_store(omq, random_sn, sk):
    swarm = ss.get_swarm(omq, random_sn, sk)

    snodes = swarm['snodes']
    sn = random.choice(snodes)
    conn = omq.connect_remote("curve://{}:{}/{}".format(sn['ip'], sn['port_omq'], sn['pubkey_x25519']))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = json.loads(omq.request(conn, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("abc 123".encode()).decode()}).encode()])[0])

    # FIXME: hash will become blake2b shortly:
    #hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123')
    hash = s['hash']

    assert len(s["swarm"]) == len(snodes)
    edkeys = {x['pubkey_ed25519'] for x in snodes}
    for k, v in s['swarm'].items():
        assert k in edkeys
        assert hash == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))


def test_store_retrieve(omq, random_sn, sk):
    swarm = ss.get_swarm(omq, random_sn, sk)

    snodes = swarm['snodes']
    sns = random.sample(snodes, 2)
    conn1 = omq.connect_remote("curve://{}:{}/{}".format(sns[0]['ip'], sns[0]['port_omq'], sns[0]['pubkey_x25519']))


    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = json.loads(omq.request(conn1, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode()}).encode()])[0])

    # FIXME:
    #hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123')
    hash = s['hash']

    assert all(v['hash'] == hash for v in s['swarm'].values())
    
    conn2 = omq.connect_remote("curve://{}:{}/{}".format(sns[1]['ip'], sns[1]['port_omq'], sns[1]['pubkey_x25519']))
    r = json.loads(omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex() }).encode()])[0])

    assert len(r['messages']) == 1
    msg = r['messages'][0]
    assert msg['data'] == base64.b64encode(b'abc 123').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash
