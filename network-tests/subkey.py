from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from hashlib import sha512
from nacl.signing import SigningKey, VerifyKey
import nacl.bindings as sodium
from typing import Union


def make_subkey(sk, subuser_or_raw: Union[VerifyKey, bytes]):
    """
    For a subkey signature, given subkey value c, we sign with d=a(c+H(c‖A)), which has
    verification key D = (c+H(c‖A))A.

    You can pass in either a raw subkey (32 bytes) or a VerifyKey to make one from it.

    Returns length-32 bytes of each of: subkey, privkey, pubkey
    """
    if isinstance(subuser_or_raw, bytes):
        assert(len(subuser_or_raw) == 32)
        c = subuser_or_raw
    else:
        c = blake2b(sk.verify_key.encode() + subuser_or_raw.encode(), digest_size=32, encoder=RawEncoder)

    a = sodium.crypto_sign_ed25519_sk_to_curve25519(sk.encode() + sk.verify_key.encode())
    d = sodium.crypto_core_ed25519_scalar_mul(
        a,
        sodium.crypto_core_ed25519_scalar_add(
            c,
            blake2b(
                c + sk.verify_key.encode(), key=b'OxenSSSubkey', digest_size=32, encoder=RawEncoder
            ),
        ),
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
def sign(message_parts, s: SigningKey, d: bytes, D: bytes):
    H_rh = sha512(s.encode()).digest()[32:]
    r = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(H_rh, D, message_parts))
    sig_R = sodium.crypto_scalarmult_ed25519_base_noclamp(r)
    HRAM = sodium.crypto_core_ed25519_scalar_reduce(sha512_multipart(sig_R, D, message_parts))
    sig_s = sodium.crypto_core_ed25519_scalar_add(r, sodium.crypto_core_ed25519_scalar_mul(HRAM, d))
    return sig_R + sig_s
