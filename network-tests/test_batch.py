from util import sn_address
import ss
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder, RawEncoder
from nacl.hash import blake2b
from hashlib import sha512
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings as sodium
from oxenc import bt_serialize, bt_deserialize


def test_batch_json(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # Store two messages for myself
    s = omq.request_future(conn, 'storage.batch', [json.dumps({
        "requests": [
            {
                "method": "store",
                "params": {
                    "pubkey": '03' + sk.verify_key.encode().hex(),
                    'namespace': 42,
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": base64.b64encode(b"abc 123").decode(),
                    "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
            {
                "method": "store",
                "params": {
                    "pubkey": '03' + sk.verify_key.encode().hex(),
                    'namespace': 42,
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": base64.b64encode(b"xyz 123").decode(),
                    "signature": sk.sign(f"store42{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
        ],
        }).encode()]).get()
    assert len(s) == 1
    s = json.loads(s[0])
    assert "results" in s
    assert len(s["results"]) == 2
    assert s["results"][0]["code"] == 200
    assert s["results"][1]["code"] == 200

    hash0 = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    hash1 = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'xyz 123',
            encoder=Base64Encoder).decode().rstrip('=')
    assert s["results"][0]["body"]["hash"] == hash0
    assert s["results"][1]["body"]["hash"] == hash1


def test_batch_bt(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # Store two messages for myself
    s = omq.request_future(conn, 'storage.batch', [bt_serialize({
        "requests": [
            {
                "method": "store",
                "params": {
                    "pubkey": '03' + sk.verify_key.encode().hex(),
                    'namespace': 42,
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": b"abc 123",
                    "signature": sk.sign(f"store42{ts}".encode()).signature,
                },
            },
            {
                "method": "store",
                "params": {
                    "pubkey": '03' + sk.verify_key.encode().hex(),
                    'namespace': 42,
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": b"xyz 123",
                    "signature": sk.sign(f"store42{ts}".encode()).signature,
                },
            },
        ],
        })]).get()
    assert len(s) == 1
    s = bt_deserialize(s[0])
    assert b"results" in s
    assert len(s[b"results"]) == 2
    assert s[b"results"][0][b"code"] == 200
    assert s[b"results"][1][b"code"] == 200

    hash0 = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'abc 123',
            encoder=Base64Encoder).rstrip(b'=')
    hash1 = blake2b("{}{}".format(ts, exp).encode() + b'\x03' + sk.verify_key.encode() + b'42' + b'xyz 123',
            encoder=Base64Encoder).rstrip(b'=')
    assert s[b"results"][0][b"body"][b"hash"] == hash0
    assert s[b"results"][1][b"body"][b"hash"] == hash1


def test_sequence(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    # Sequence some commands:
    s = omq.request_future(conn, 'storage.sequence', [json.dumps({
        "requests": [
            {
                "method": "store",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": base64.b64encode(b"abc 123").decode(),
                },
            },
            {
                "method": "retrieve",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
            {
                "method": "store",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "ttl": ttl,
                    "data": base64.b64encode(b"xyz 123").decode(),
                },
            },
            {
                "method": "delete_all",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "signature": sk.sign(f"delete_all{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
            {
                "method": "retrieve",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
        ],
        }).encode()]).get()

    assert len(s) == 1
    s = json.loads(s[0])
    assert "results" in s
    assert len(s["results"]) == 5
    h0 = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'abc 123',
            encoder=Base64Encoder).decode().rstrip('=')
    h1 = blake2b("{}{}".format(ts, exp).encode() + b'\x05' + sk.verify_key.encode() + b'xyz 123',
            encoder=Base64Encoder).decode().rstrip('=')
    assert s["results"][0]["body"]["hash"] == h0
    assert s["results"][1]["body"]["messages"] == [{"data": "YWJjIDEyMw==", "expiration": ts + ttl, "hash": h0, "timestamp": ts}]
    assert s["results"][2]["body"]["hash"] == h1
    assert len(s["results"][3]["body"]["swarm"]) > 0
    for sw in s["results"][3]["body"]["swarm"].values():
        assert set(sw["deleted"]) == {h0, h1}
    assert s["results"][4]["body"]["messages"] == []


def test_failing_sequence(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, 3)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    commands = {
        "requests": [
            {
                "method": "store",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "namespace": 33, # will fail because no auth
                    "ttl": ttl,
                    "data": base64.b64encode(b"abc 123").decode(),
                },
            },
            {
                "method": "retrieve",
                "params": {
                    "pubkey": '05' + sk.verify_key.encode().hex(),
                    "timestamp": ts,
                    "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode(),
                },
            },
        ],
    }

    # Sequence some commands:
    s_s = omq.request_future(conn, 'storage.sequence', [json.dumps(commands).encode()])
    s_b = omq.request_future(conn, 'storage.batch', [json.dumps(commands).encode()])

    s_s = s_s.get()
    s_b = s_b.get()

    # The sequence should fail the store, and thus not attempt the retrieve:
    assert len(s_s) == 1
    s_s = json.loads(s_s[0])
    assert "results" in s_s
    assert len(s_s["results"]) == 1
    assert s_s["results"][0]["code"] == 401
    assert s_s["results"][0]["body"] == "store: signature required to store to namespace 33"

    # The same thing as a batch should fail but also do the retrieve:
    assert len(s_b) == 1
    s_b = json.loads(s_b[0])
    assert "results" in s_b
    assert len(s_b["results"]) == 2
    assert s_b["results"][0]["code"] == 401
    assert s_b["results"][0]["body"] == "store: signature required to store to namespace 33"
    assert s_b["results"][1]["code"] == 200
    assert s_b["results"][1]["body"]["messages"] == []
