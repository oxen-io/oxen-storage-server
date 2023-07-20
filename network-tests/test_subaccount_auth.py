from util import sn_address
import ss
import subaccount
import time
import base64
import json
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.hash import blake2b
from nacl.signing import SigningKey, VerifyKey
import nacl.exceptions

def b64(data: bytes):
    return base64.b64encode(data).decode()

def test_retrieve_subaccount(omq, random_sn, sk, exclude):
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
        "data": b64(b"abc 123"),
        "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    hash = blake2b(b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    for k, v in s['swarm'].items():
        assert hash == v['hash']

    # Retrieve it using a subaccount
    dude_sk, dude_token, dude_sig = subaccount.make_subaccount(0x03, sk)
    to_sign = f"retrieve42{ts}".encode()
    sig = dude_sk.sign(to_sign).signature

    assert dude_token.hex() == '03030000' + dude_sk.verify_key.encode().hex()

    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": b64(sig),
            "subaccount": b64(dude_token),
            "subaccount_sig": b64(dude_sig),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash

def test_store_subaccount(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    dude_sk, dude_token, dude_sig = subaccount.make_subaccount(0x03, sk)

    sig = dude_sk.sign(f"store42{ts}".encode()).signature

    # Store a message using the subaccount
    s = omq.request_future(conn, 'storage.store', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'namespace': 42,
        "timestamp": ts,
        "ttl": ttl,
        "data": b64(b"abc 123"),
        "signature": b64(sig),
        "subaccount": b64(dude_token),
        "subaccount_sig": b64(dude_sig),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    assert s["hf"] >= [19, 0]

    hash = blake2b(b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
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

def test_expire_subaccount(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    # Store using the master key
    msgs = ss.store_n(omq, conn, sk, b"omg123", 3, netid=3)

    now = int(time.time() * 1000)
    for m in msgs:
        assert m["req"]["expiry"] < now + 60_000

    dude_sk, dude_token, dude_sig = subaccount.make_subaccount(0x03, sk)

    new_exp = now + 24*60*60*1000

    # Update one of the expiries from ~1min from now -> 1day from now
    sig = dude_sk.sign(f"expire{new_exp}{msgs[0]['hash']}".encode()).signature
    r = omq.request_future(conn, 'storage.expire', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'subaccount': b64(dude_token),
        'subaccount_sig': b64(dude_sig),
        'messages': [msgs[0]['hash']],
        'expiry': new_exp,
        'signature': b64(sig),
    }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['swarm']) > 0
    for pk, exp in r['swarm'].items():
        assert exp["expiry"] == new_exp
        assert exp["updated"] == [msgs[0]['hash']]

    # Attempt to update all three, using the subaccount, to half a day from now.  msg[0] shouldn't
    # get updated, because subaccount are only allowed to extend.

    new_exp = now + 12*60*60*1000
    sig = dude_sk.sign(f"expire{new_exp}{''.join(m['hash'] for m in msgs)}".encode()).signature
    r = omq.request_future(conn, 'storage.expire', [json.dumps({
        "pubkey": '03' + sk.verify_key.encode().hex(),
        'subaccount': b64(dude_token),
        'subaccount_sig': b64(dude_sig),
        'messages': [m['hash'] for m in msgs],
        'expiry': new_exp,
        'signature': b64(sig),
    }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['swarm']) > 0
    for pk, exp in r['swarm'].items():
        assert exp["expiry"] == new_exp
        assert set(exp["updated"]) == set([m['hash'] for m in msgs[1:]])

def test_revoke_subaccount(omq, random_sn, sk, exclude):
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
        "data": b64(b"abc 123"),
        "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    hash = blake2b(b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    for k, v in s['swarm'].items():
        assert hash == v['hash']

    # Retrieve it using the subaccount
    dude_sk, dude_token, dude_sig = subaccount.make_subaccount(0x03, sk)
    to_sign = f"retrieve42{ts}".encode()
    sig = dude_sk.sign(to_sign).signature

    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": b64(sig),
            "subaccount": b64(dude_token),
            "subaccount_sig": b64(dude_sig),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash

    # Revoke the subaccount
    r = omq.request_future(conn, 'storage.revoke_subaccount', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "revoke": b64(dude_token),
            "signature": sk.sign(f"revoke_subaccount".encode() + dude_token, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(r) == 1
    r = json.loads(r[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # Check the signature of the revoked subaccount response, should be signing ( PUBKEY_HEX || SUBKEY_TAG_BYTES )
    expected_signed = ('03' + sk.verify_key.encode().hex()).encode() + dude_token
    for k, v in r['swarm'].items():
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    # Try retrieve it again using the subaccount, should fail
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": b64(sig),
            "subaccount": b64(dude_token),
            "subaccount_sig": b64(dude_sig),
        }).encode()]).get()
    assert r == [b'401', b'retrieve signature verification failed']

    # Revoke another 49 subaccount, the original subaccount should still fail to retrieve the messages
    for i in range (49):
        another_sk, another_token, another_sig = subaccount.make_subaccount(0x03, sk)
        r = omq.request_future(conn, 'storage.revoke_subaccount', [
            json.dumps({
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "revoke": b64(another_token),
                "signature": sk.sign(f"revoke_subaccount".encode() + another_token, encoder=Base64Encoder).signature.decode()
            }).encode()]).get()
        assert len(r) == 1

    # Try retrieve it again using the subaccount, should fail again
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": b64(sig),
            "subaccount": b64(dude_token),
            "subaccount_sig": b64(dude_sig),
        }).encode()]).get()
    assert r == [b'401', b'retrieve signature verification failed']

    # Revoke one more subaccount, the original subaccount should now succeed in retrieving the messages
    another_sk, another_token, another_sig = subaccount.make_subaccount(0x03, sk)
    r = omq.request_future(conn, 'storage.revoke_subaccount', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "revoke": b64(another_token),
            "signature": sk.sign(f"revoke_subaccount".encode() + another_token, encoder=Base64Encoder).signature.decode()
        }).encode()]).get()
    assert len(r) == 1

    # Try retrieve it again using the subaccount, should succeed now (because only the most recent
    # 50 revocations are kept by the swarm):
    r = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "namespace": 42,
            "timestamp": ts,
            "signature": b64(sig),
            "subaccount": b64(dude_token),
            "subaccount_sig": b64(dude_sig),
        }).encode()]).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hf"] >= [19, 0]
    assert len(r["messages"]) == 1
    assert r["messages"][0]["hash"] == hash


def test_subaccount_permissions(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    keys = []
    # keys[0] read-only
    keys.append(subaccount.make_subaccount(0x03, sk, write=False))
    # keys[1] has no perms at all
    keys.append(subaccount.make_subaccount(0x03, sk, read=False, write=False))
    # keys[2] has delete
    keys.append(subaccount.make_subaccount(0x03, sk, delete=True))
    # keys[3] has the "any prefix" flag
    keys.append(subaccount.make_subaccount(0x03, sk, any_prefix=True))

    assert keys[0][1].hex() == '03010000' + keys[0][0].verify_key.encode().hex()
    assert keys[1][1].hex() == '03000000' + keys[1][0].verify_key.encode().hex()
    assert keys[2][1].hex() == '03070000' + keys[2][0].verify_key.encode().hex()
    assert keys[3][1].hex() == '030b0000' + keys[3][0].verify_key.encode().hex()

    to_sign = f"retrieve42{ts}".encode()

    for i in range(4):
        r = omq.request_future(conn, 'storage.retrieve', [
            json.dumps({
                "pubkey": '03' + sk.verify_key.encode().hex(),
                "namespace": 42,
                "timestamp": ts,
                "signature": b64(keys[i][0].sign(to_sign).signature),
                "subaccount": b64(keys[i][1]),
                "subaccount_sig": b64(keys[i][2]),
            }).encode()]).get()

        if i == 1:
            assert r == [b'401', b'retrieve signature verification failed']
        else:
            assert len(r) == 1
            r = json.loads(r[0])
            del r["hf"]
            del r["t"]
            assert r == {"messages": [], "more": False}

    hash = blake2b(b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')

    for i in range(4):
        r = omq.request_future(conn, 'storage.store', [json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            'namespace': 42,
            "timestamp": ts,
            "ttl": ttl,
            "data": b64(b"abc 123"),
            "signature": b64(keys[i][0].sign(f"store42{ts}".encode()).signature),
            "subaccount": b64(keys[i][1]),
            "subaccount_sig": b64(keys[i][2]),
            })]).get()

        if i <= 1:
            assert r == [b'401', b'store signature verification failed']
        else:
            assert len(r) == 1
            r = json.loads(r[0])
            for k, v in r['swarm'].items():
                assert v['hash'] == hash

    for i in range(4):
        r = omq.request_future(conn, 'storage.delete', [json.dumps({
            "pubkey": '03' + sk.verify_key.encode().hex(),
            "messages": [hash],
            "signature": b64(keys[i][0].sign(f"delete{hash}".encode()).signature),
            "subaccount": b64(keys[i][1]),
            "subaccount_sig": b64(keys[i][2]),
            })]).get()

        if i == 2:
            assert len(r) == 1
            r = json.loads(r[0])
            for k, v in r['swarm'].items():
                assert v['deleted'] == [hash]
        else:
            assert r == [b'401', b'delete_msgs signature verification failed']

    for i in range(4):
        r = omq.request_future(conn, 'storage.retrieve', [
            json.dumps({
                "pubkey": '99' + sk.verify_key.encode().hex(),
                "namespace": 42,
                "timestamp": ts,
                "signature": b64(keys[i][0].sign(to_sign).signature),
                "subaccount": b64(keys[i][1]),
                "subaccount_sig": b64(keys[i][2]),
            }).encode()]).get()

        if i == 3: # Retrieving from another pubkey prefix: requires any_prefix flag
            assert len(r) == 1
            r = json.loads(r[0])
            del r["hf"]
            del r["t"]
            assert r == {"messages": [], "more": False}
        else:
            assert r == [b'401', b'retrieve signature verification failed']
