import pyoxenmq
import ss
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey

def test_store(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
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

    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert len(s["swarm"]) == len(swarm['snodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['snodes']}
    for k, v in s['swarm'].items():
        assert k in edkeys
        assert hash == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))


def test_store_retrieve(omq, random_sn, sk, exclude):
    sns = ss.random_swarm_members(ss.get_swarm(omq, random_sn, sk), 2, exclude)
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

    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

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


def exactly_one(iterable):
    found_one = any(iterable)
    found_more = any(iterable)
    return found_one and not found_more


def test_store_retrieve_multiple(omq, random_sn, sk, exclude):
    sns = ss.random_swarm_members(ss.get_swarm(omq, random_sn, sk), 2, exclude)
    conn1 = omq.connect_remote("curve://{}:{}/{}".format(sns[0]['ip'], sns[0]['port_omq'], sns[0]['pubkey_x25519']))


    basemsg = b"This is my message \x00<--that's a null, this is invalid utf8: \x80\xff"

    # Store 5 messages
    msgs = ss.store_n(omq, conn1, sk, basemsg, 5)

    # Retrieve all messages from the swarm (should give back the 5 we just stored):
    conn2 = omq.connect_remote("curve://{}:{}/{}".format(sns[1]['ip'], sns[1]['port_omq'], sns[1]['pubkey_x25519']))
    resp = omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex() }).encode()])

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert len(r['messages']) == 5
    for m in r['messages']:
        data = base64.b64decode(m['data'])
        source = next(x for x in msgs if x['hash'] == m['hash'])
        assert source['data'] == data
        assert source['req']['timestamp'] == m['timestamp']
        assert source['req']['expiry'] == m['expiration']

    # Store 6 more messages
    basemsg = b'another msg'
    new_msgs = ss.store_n(omq, conn2, sk, basemsg, 6, 1)

    # Retrieve using a last_hash so that we should get back only the 6:
    resp = omq.request(conn1, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "last_hash": msgs[4]['hash']
        }).encode()])

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert len(r['messages']) == 6
    for m in r['messages']:
        data = base64.b64decode(m['data'])
        source = next(x for x in new_msgs if x['hash'] == m['hash'])
        assert source['data'] == data
        assert source['req']['timestamp'] == m['timestamp']
        assert source['req']['expiry'] == m['expiration']

    # Give an unknown hash which should retrieve all:
    r = json.loads(omq.request(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "last_hash": "abcdef"
        }).encode()])[0])

