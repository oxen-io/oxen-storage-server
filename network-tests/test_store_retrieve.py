from util import sn_address
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
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("abc 123".encode()).decode()}).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])

    hash = blake2b(b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert len(s["swarm"]) == len(swarm['snodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['snodes']}
    for k, v in s['swarm'].items():
        assert k in edkeys
        assert hash == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))

    # NB: assumes the test machine is reasonably time synced
    assert(ts - 30000 <= s['t'] <= ts + 30000)


def test_store_retrieve_unauthenticated(omq, random_sn, sk, exclude):
    """Attempts to retrieve messages without authentication.  This should fail (as of HF19)."""
    sns = ss.random_swarm_members(ss.get_swarm(omq, random_sn, sk), 2, exclude)
    conn1 = omq.connect_remote(sn_address(sns[0]))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message for myself
    s = omq.request_future(conn1, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode()}).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])

    hash = blake2b(b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert all(v['hash'] == hash for v in s['swarm'].values())

    conn2 = omq.connect_remote(sn_address(sns[1]))
    r = omq.request_future(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex() }).encode()]).get()

    assert r == [b'401', b'retrieve: request signature required']


def test_store_retrieve_authenticated(omq, random_sn, sk, exclude):
    xsk = sk.to_curve25519_private_key()
    xpk = xsk.public_key
    sn_x = ss.random_swarm_members(ss.get_swarm(omq, random_sn, xsk), 1, exclude)[0]
    sn_ed = ss.random_swarm_members(ss.get_swarm(omq, random_sn, sk), 1, exclude)[0]
    conn_x = omq.connect_remote(sn_address(sn_x))
    conn_ed = omq.connect_remote(sn_address(sn_ed))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store message for myself, using both my ed25519 key and x25519 key to test different auth
    # modes
    s1 = omq.request_future(conn_x, 'storage.store', [json.dumps({
        "pubkey": '05' + xpk.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode()}).encode()])
    s2 = omq.request_future(conn_ed, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"def 456").decode()}).encode()])

    s1 = s1.get()
    assert len(s1) == 1
    s1 = json.loads(s1[0])

    hash1 = blake2b(b'\x05' + xpk.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    assert all(v['hash'] == hash1 for v in s1['swarm'].values())

    s2 = s2.get()
    assert len(s2) == 1
    s2 = json.loads(s2[0])

    hash2 = blake2b(b'\x03' + sk.verify_key.encode() + b'def 456',
            encoder=Base64Encoder).decode().rstrip('=')

    to_sign = "retrieve{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    badsig = sig[0:4] + ('z' if sig[4] != 'z' else 'a') + sig[5:]

    r_good1 = omq.request_future(conn_x, 'storage.retrieve', [
        json.dumps({
            "pubkey": '05' + xpk.encode().hex(),
            "timestamp": ts,
            "signature": sig,
            "pubkey_ed25519": sk.verify_key.encode().hex()
        }).encode()])
    r_good2 = omq.request_future(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            "signature": sig
        }).encode()])
    r_bad1 = omq.request_future(conn_x, 'storage.retrieve', [
        json.dumps({
            "pubkey": '05' + xpk.encode().hex(),
            "timestamp": ts,
            "signature": badsig,  # invalid sig
            "pubkey_ed25519": sk.verify_key.encode().hex()
        }).encode()])
    r_bad2 = omq.request_future(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            "signature": badsig  # invalid sig
        }).encode()])
    r_bad3 = omq.request_future(conn_ed, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "timestamp": ts,
            #"signature": badsig  # has timestamp but missing sig
        }).encode()])

    r_good1 = json.loads(r_good1.get()[0])
    assert len(r_good1['messages']) == 1
    msg = r_good1['messages'][0]
    assert msg['data'] == base64.b64encode(b'abc 123').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash1

    r_good2 = json.loads(r_good2.get()[0])
    assert len(r_good2['messages']) == 1
    msg = r_good2['messages'][0]
    assert msg['data'] == base64.b64encode(b'def 456').decode()
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash2

    assert r_bad1.get() == [b'401', b'retrieve signature verification failed']
    assert r_bad2.get() == [b'401', b'retrieve signature verification failed']
    assert r_bad3.get() == [b'400', b"invalid request: Required field 'signature' missing"]


def exactly_one(iterable):
    found_one = any(iterable)
    found_more = any(iterable)
    return found_one and not found_more


def test_store_retrieve_multiple(omq, random_sn, sk, exclude):
    sns = ss.random_swarm_members(ss.get_swarm(omq, random_sn, sk), 2, exclude)
    conn1 = omq.connect_remote(sn_address(sns[0]))


    basemsg = b"This is my message \x00<--that's a null, this is invalid utf8: \x80\xff"

    # Store 5 messages
    msgs = ss.store_n(omq, conn1, sk, basemsg, 5)

    # Retrieve all messages from the swarm (should give back the 5 we just stored):
    conn2 = omq.connect_remote(sn_address(sns[1]))
    ts = int(time.time() * 1000)
    resp = omq.request_future(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "timestamp": ts,
        "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
    }).encode()]).get()

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
    new_msgs = ss.store_n(omq, conn2, sk, basemsg, 6, offset=1)

    # Retrieve using a last_hash so that we should get back only the 6:
    resp = omq.request_future(conn1, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "last_hash": msgs[4]['hash'],
        "timestamp": ts,
        "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()

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
    r = omq.request_future(conn2, 'storage.retrieve', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "last_hash": "0123456789012345678901234567890123456789123",
        "timestamp": ts,
        "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()
    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['messages']) == 11


def test_store_sig_timestamp(omq, random_sn, sk, exclude):
    """Tests that sig_timestamp is used properly for the signature both sig_timestamp and timestamp
    are given."""
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ns = 123
    ttl = 86400000
    exp = ts + ttl

    # Should be fine: timestamp is current, and we sign with it (so timestamp is double double-duty
    # as both the message timestamp, and the signature timestamp):
    to_sign = f"store{ns}{ts}".encode()
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "namespace": ns,
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("msg1".encode()).decode(),
        "signature": sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])

    assert 'hash' in s


    # Simulate a 100s storage delay:
    ts -= 100_000

    # Fails because timestamp is too old for a store signature:
    to_sign = f"store{ns}{ts}".encode()
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "namespace": ns,
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("msg2".encode()).decode(),
        "signature": sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert s == [b'406', b'store signature timestamp too far from current time']

    # This should work: sig_timestamp is current, timestamp is old:
    sig_ts = int(time.time() * 1000)
    to_sign = f"store{ns}{sig_ts}".encode()
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '05' + sk.verify_key.encode().hex(),
        "namespace": ns,
        "timestamp": ts,
        "sig_timestamp": sig_ts,
        "ttl": ttl,
        "data": base64.b64encode("msg3".encode()).decode(),
        "signature": sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
