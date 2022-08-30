from util import sn_address
import ss
import subkey
import time
import base64
import json
from nacl.encoding import Base64Encoder
from nacl.hash import blake2b
from nacl.signing import SigningKey
import nacl.exceptions

def test_retrieve_subkey(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # Store a message for myself, using master key
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'namespace': 42,
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode(),
        "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    for k, v in s['swarm'].items():
        assert hash == v['hash']

    # Retrieve it using a subkey
    dude_sk = SigningKey.generate()
    c, d, D = subkey.make_subkey(sk, dude_sk.verify_key)
    to_sign = f"retrieve42{ts}".encode()
    sig = subkey.sign(to_sign, dude_sk, d, D)

    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": base64.b64encode(sig).decode(),
            "subkey": base64.b64encode(c).decode(),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash

def test_store_subkey(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    dude_sk = SigningKey.generate()
    c, d, D = subkey.make_subkey(sk, dude_sk.verify_key)

    sig = subkey.sign(f"store42{ts}".encode(), dude_sk, d, D)

    # Store a message using the subkey
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'namespace': 42,
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode("abc 123".encode()).decode(),
        "subkey": base64.b64encode(c).decode(),
        "signature": base64.b64encode(sig).decode(),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    assert s["hf"] >= [19, 0]

    hash = blake2b(f"{ts}{exp}".encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    assert len(s["swarm"]) > 0
    for k, v in s['swarm'].items():
        assert hash == v['hash']

    # Retrieve using master key:
    s = omq.request_future(conn, 'storage.retrieve', [json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": sk.sign(f"retrieve42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
            }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    assert s["hf"] >= [19, 0]
    assert len(s["messages"]) == 1
    assert s["messages"][0]["hash"] == hash

def test_expire_subkey(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    # Store using the master key
    msgs = ss.store_n(omq, conn, sk, b"omg123", 3, netid=3)

    now = int(time.time() * 1000)
    for m in msgs:
        assert m["req"]["expiry"] < now + 60_000

    dude_sk = SigningKey.generate()
    c, d, D = subkey.make_subkey(sk, dude_sk.verify_key)

    new_exp = now + 24*60*60*1000

    # Update one of the expiries from ~1min from now -> 1day from now
    sig = subkey.sign(f"expire{new_exp}{msgs[0]['hash']}".encode(), dude_sk, d, D)
    r = omq.request_future(conn, 'storage.expire', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'subkey': c.hex(),
        'messages': [msgs[0]['hash']],
        'expiry': new_exp,
        'signature': base64.b64encode(sig).decode(),
    }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['swarm']) > 0
    for pk, exp in r['swarm'].items():
        assert exp["expiry"] == new_exp
        assert exp["updated"] == [msgs[0]['hash']]

    # Attempt to update all three, using the subkey, to half a day from now.  msg[0] shouldn't get
    # updated, because subkeys are only allowed to extend.

    new_exp = now + 12*60*60*1000
    sig = subkey.sign(
            f"expire{new_exp}{''.join(m['hash'] for m in msgs)}".encode(), dude_sk, d, D)
    r = omq.request_future(conn, 'storage.expire', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'subkey': c.hex(),
        'messages': [m['hash'] for m in msgs],
        'expiry': new_exp,
        'signature': base64.b64encode(sig).decode(),
    }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['swarm']) > 0
    for pk, exp in r['swarm'].items():
        assert exp["expiry"] == new_exp
        assert set(exp["updated"]) == set([m['hash'] for m in msgs[1:]])

def test_revoke_subkey(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # Store a message for myself, using master key
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'namespace': 42,
        "timestamp": ts,
        "ttl": ttl,
        "data": base64.b64encode(b"abc 123").decode(),
        "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    hash = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    for k, v in s['swarm'].items():
        assert hash == v['hash']

    # Retrieve it using the subkey
    dude_sk = SigningKey.generate()
    c, d, D = make_subkey(sk, dude_sk.verify_key)
    to_sign = f"retrieve42{ts}".encode()
    sig = blinded_ed25519_signature(to_sign, dude_sk, d, D)

    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": base64.b64encode(sig).decode(),
            "subkey": base64.b64encode(c).decode(),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash

    # Revoke the subkey
    r = omq.request_future(conn, 'storage.revoke_subkey', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "revoke_subkey": base64.b64encode(c).decode(),
            "signature": sk.sign(f"revoke_subkey".encode() + c, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(r) == 1
    r = json.loads(r[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # Check the signature of the revoked subkey response, should be signing ( PUBKEY_HEX || SUBKEY_TAG_BYTES )
    expected_signed = ('03' + sk.verify_key.encode().hex()).encode() + c
    for k, v in r['swarm'].items():
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    # Try retrieve it again using the subkey, should fail
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": base64.b64encode(sig).decode(),
            "subkey": base64.b64encode(c).decode(),
        }).encode()]).get()
    assert r == [b'401', b'retrieve signature verification failed']

    # Revoke another 49 subkeys, the original subkey should still fail to retrieve the messages
    for i in range (49):
        more_dude_sk = SigningKey.generate()
        more_c, more_d, D = make_subkey(sk, more_dude_sk.verify_key)
        r = omq.request_future(conn, 'storage.revoke_subkey', [
            json.dumps({
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "revoke_subkey": base64.b64encode(more_c).decode(),
                "signature": sk.sign(f"revoke_subkey".encode() + more_c, encoder=Base64Encoder).signature.decode()
            }).encode()]).get()
        assert len(r) == 1

    # Try retrieve it again using the subkey, should fail again
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": base64.b64encode(sig).decode(),
            "subkey": base64.b64encode(c).decode(),
        }).encode()]).get()
    assert r == [b'401', b'retrieve signature verification failed']

    # Revoke one more subkey, the original subkey should now succeed in retrieving the messages
    more_dude_sk = SigningKey.generate()
    more_c, more_d, D = make_subkey(sk, more_dude_sk.verify_key)
    r = omq.request_future(conn, 'storage.revoke_subkey', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "revoke_subkey": base64.b64encode(more_c).decode(),
            "signature": sk.sign(f"revoke_subkey".encode() + more_c, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(r) == 1

    # Try retrieve it again using the subkey, should succeed now
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": base64.b64encode(sig).decode(),
            "subkey": base64.b64encode(c).decode(),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash
