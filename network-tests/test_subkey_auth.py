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

def make_subkey(sk, subuser_pk: VerifyKey):
    # Typically we'll do this, though in theory we can generate any old 32-byte value for c:
    a = sodium.crypto_sign_ed25519_sk_to_curve25519(sk.encode() + sk.verify_key.encode())
    c = blake2b(sk.verify_key.encode() + subuser_pk.encode(), digest_size=32, encoder=RawEncoder)
    d = sodium.crypto_core_ed25519_scalar_mul(
            a,
            sodium.crypto_core_ed25519_scalar_add(
                c, blake2b(c + sk.verify_key.encode(), key=b'OxenSSSubkey', digest_size=32, encoder=RawEncoder))
            )
    D = sodium.crypto_scalarmult_ed25519_base_noclamp(d)
    return c, d, D


def sha512_multipart(*message_parts):
    """Given any number of arguments, returns the SHA512 hash of them concatenated together.  This
    also does one level of flatting if any of the given parts are a list or tuple."""
    hasher = sha512()
    for m in message_parts:
        if isinstance(m, list) or isinstance(m, tuple):
            for mi in m:
                hasher.update(mi)
        else:
            hasher.update(m)
    return hasher.digest()


# Mostly copied from SOGS auth example; the signature math here is identical (just using d/D instead
# of ka/kA):
def blinded_ed25519_signature(message_parts, s: SigningKey, d: bytes, D: bytes):
    H_rh = sha512(s.encode()).digest()[32:]
    r = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(H_rh, D, message_parts))
    sig_R = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
    HRAM = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(sig_R, D, message_parts))
    sig_s = sodium.crypto_core_ed25519_scalar_add(
        r, sodium.crypto_core_ed25519_scalar_mul(HRAM, d)
    )
    return sig_R + sig_s


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

def test_store_subkey(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86400000
    exp = ts + ttl

    dude_sk = SigningKey.generate()
    c, d, D = make_subkey(sk, dude_sk.verify_key)

    sig = blinded_ed25519_signature(f"store42{ts}".encode(), dude_sk, d, D)

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
