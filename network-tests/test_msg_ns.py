from util import sn_address
import ss
import time
import base64
import json
import secrets
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import SigningKey, VerifyKey


def b64(data: bytes):
    return base64.b64encode(data).decode()


def test_store_ns(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl
    # Store a message (publicly depositable namespace, divisible by 10)
    spub = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": 40,
                    "data": b64(b"abc 123"),
                }
            ).encode()
        ],
    )

    # Store a message for myself in a private namespace (not divisible by 10)
    spriv = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": -42,
                    "data": b64(b"abc 123"),
                    "signature": sk.sign(
                        f"store-42{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    )

    spub = json.loads(spub.get()[0])

    hpub = (
        blake2b(b'\x05' + sk.verify_key.encode() + b'40' + b'abc 123', encoder=Base64Encoder)
        .decode()
        .rstrip('=')
    )

    assert len(spub["swarm"]) == len(swarm['snodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['snodes']}
    for k, v in spub['swarm'].items():
        assert k in edkeys
        assert hpub == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))

    # NB: assumes the test machine is reasonably time synced
    assert ts - 30000 <= spub['t'] <= ts + 30000

    spriv = json.loads(spriv.get()[0])
    hpriv = (
        blake2b(b'\x05' + sk.verify_key.encode() + b'-42' + b'abc 123', encoder=Base64Encoder)
        .decode()
        .rstrip('=')
    )

    assert len(spriv["swarm"]) == len(swarm['snodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['snodes']}
    for k, v in spriv['swarm'].items():
        assert k in edkeys
        assert hpriv == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))

    # NB: assumes the test machine is reasonably time synced
    assert ts - 30000 <= spriv['t'] <= ts + 30000

    rpub = omq.request_future(
        conn,
        'storage.retrieve',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "namespace": 40,
                    "signature": sk.sign(
                        f"retrieve40{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    )
    rpriv = omq.request_future(
        conn,
        'storage.retrieve',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "namespace": -42,
                    "signature": sk.sign(
                        f"retrieve-42{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    )
    rdenied = omq.request_future(
        conn,
        'storage.retrieve',
        [
            json.dumps(
                {"pubkey": '05' + sk.verify_key.encode().hex(), "timestamp": ts, "namespace": 40}
            ).encode()
        ],
    )

    rpub = rpub.get()
    assert len(rpub) == 1
    rpub = json.loads(rpub[0])
    assert len(rpub["messages"]) == 1
    assert rpub["messages"][0]["hash"] == hpub

    rpriv = rpriv.get()
    assert len(rpriv) == 1
    rpriv = json.loads(rpriv[0])
    assert len(rpriv["messages"]) == 1
    assert rpriv["messages"][0]["hash"] == hpriv

    assert rdenied.get() == [b'400', b"invalid request: Required field 'signature' missing"]


def test_legacy_closed_ns(omq, random_sn, sk, exclude):
    # For legacy closed groups the secret key is generated but then immediately discarded; it's only
    # used to generate a primary key storage address:

    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # namespace -10 is a special, no-auth namespace for legacy closed group messages.
    sclosed = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": -10,
                    "data": b64(b"blah blah"),
                }
            )
        ],
    )

    sclosed = json.loads(sclosed.get()[0])
    hash = (
        blake2b(b'\x05' + sk.verify_key.encode() + b'-10' + b'blah blah', encoder=Base64Encoder)
        .decode()
        .rstrip('=')
    )

    assert len(sclosed["swarm"]) == len(swarm['snodes'])
    edkeys = {x['pubkey_ed25519'] for x in swarm['snodes']}
    for k, v in sclosed['swarm'].items():
        assert k in edkeys
        assert hash == v['hash']

        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(v['hash'].encode(), base64.b64decode(v['signature']))

    # NB: assumes the test machine is reasonably time synced
    assert ts - 30000 <= sclosed['t'] <= ts + 30000

    # Now retrieve it: this is the only namespace we can access without authentication
    r = omq.request_future(
        conn,
        'storage.retrieve',
        [json.dumps({"pubkey": '05' + sk.verify_key.encode().hex(), "namespace": -10}).encode()],
    )

    r = r.get()
    assert len(r) == 1
    r = json.loads(r[0])

    assert len(r['messages']) == 1
    msg = r['messages'][0]
    assert base64.b64decode(msg['data']) == b'blah blah'
    assert msg['timestamp'] == ts
    assert msg['expiration'] == exp
    assert msg['hash'] == hash


def test_store_invalid_ns(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    # Attempt to store a message without authentication in a non-public (% 10 != 0) namespace:
    s42 = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": 42,
                    "data": b64(b"abc 123"),
                }
            ).encode()
        ],
    )

    # Attempt to store a message in a too-big/too-small namespace:
    s32k = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": 32768,
                    "data": b64(b"abc 123"),
                }
            ).encode()
        ],
    )

    # Bad signature:
    dude_sk = SigningKey.generate()
    sdude = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": -32123,
                    "signature": dude_sk.sign(
                        f"store-32123{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                    "data": b64(b"abc 123"),
                }
            ).encode()
        ],
    )

    assert s42.get() == [b'401', b'store: signature required to store to namespace 42']
    assert s32k.get() == [
        b'400',
        b"invalid request: Invalid value given for 'namespace': value out of range",
    ]
    assert sdude.get() == [b'401', b"store signature verification failed"]


def test_public_outbox(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 60000
    exp = ts + ttl

    # Attempt to store a message without authentication in a public outbox (-1, -21, -41, ...)
    # namespace without authentication:
    s1 = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": -1,
                    "data": b64(b"abc 123"),
                }
            ).encode()
        ],
    )

    # Another store, this time *with* authentication:
    s2 = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "namespace": -1,
                    "data": b64(b"abc 456"),
                    "signature": sk.sign(
                        f"store-1{ts}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    )

    assert s1.get() == [b'401', b'store: signature required to store to namespace -1']
    r = s2.get()
    assert len(r) == 1
    r = json.loads(r[0])
    h1 = r["hash"]

    # *Unauthenticated* retrieval:
    r = omq.request_future(
        conn,
        'storage.retrieve',
        [json.dumps({"pubkey": '05' + sk.verify_key.encode().hex(), "namespace": -1}).encode()],
    ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    del r["hf"]
    del r["t"]
    assert r == {
        "messages": [{"data": b64(b'abc 456'), "expiration": exp, "hash": h1, "timestamp": ts}],
        "more": False,
    }

    # Store another message to the namespace, which should replace the earlier one
    r = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts + 1,
                    "ttl": ttl,
                    "namespace": -1,
                    "data": b64(b"abc 789"),
                    "signature": sk.sign(
                        f"store-1{ts+1}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    ).get()

    assert len(r) == 1
    r = json.loads(r[0])
    h2 = r["hash"]

    r = omq.request_future(
        conn,
        'storage.retrieve',
        [json.dumps({"pubkey": '05' + sk.verify_key.encode().hex(), "namespace": -1}).encode()],
    ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    del r["hf"]
    del r["t"]
    assert r == {
        "messages": [
            {"data": b64(b'abc 789'), "expiration": exp + 1, "hash": h2, "timestamp": ts + 1}
        ],
        "more": False,
    }

    # Store the same message again, this time it should just update the ttl but *not* the timestamp
    # (which indicates that it properly recognized the duplicate and didn't wipe-and-store-again on
    # it).
    r = omq.request_future(
        conn,
        'storage.store',
        [
            json.dumps(
                {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts + 2,
                    "ttl": ttl,
                    "namespace": -1,
                    "data": b64(b"abc 789"),
                    "signature": sk.sign(
                        f"store-1{ts+2}".encode(), encoder=Base64Encoder
                    ).signature.decode(),
                }
            ).encode()
        ],
    ).get()

    assert len(r) == 1
    r = json.loads(r[0])
    assert r["hash"] == h2

    r = omq.request_future(
        conn,
        'storage.retrieve',
        [json.dumps({"pubkey": '05' + sk.verify_key.encode().hex(), "namespace": -1}).encode()],
    ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    del r["hf"]
    del r["t"]
    assert r == {
        "messages": [
            {"data": b64(b'abc 789'), "expiration": exp + 2, "hash": h2, "timestamp": ts + 1}
        ],
        "more": False,
    }
