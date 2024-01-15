from nacl.encoding import RawEncoder
from nacl.hash import blake2b
from hashlib import sha512
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PublicKey
import nacl.bindings as sodium
from typing import Union
from pyonionreq import xed25519


def make_subaccount(
    netid: int,
    sk: SigningKey,
    *,
    read: bool = True,
    write: bool = True,
    delete: bool = False,
    any_prefix: bool = False,
):
    """
    Makes a subaccount key along with subaccount tag and signature to allow that subaccount to
    authenticate as a subuser of sk.

    The subaccount will have the given read/write/delete permissions (by default, read + write).

    Returns three values:
    - a new SigningKey that can sign requests
    - subaccount token, allowing the returned SigningKey to be used
    - signature of the subaccount token by the main account holder, authorizing the subaccount.
    """

    subkey = SigningKey.generate()

    flags = bool(read) << 0 | bool(write) << 1 | bool(delete) << 2 | bool(any_prefix) << 3

    subaccount_tag = (
        netid.to_bytes(1, 'big') + flags.to_bytes(1, 'big') + b'\0\0' + subkey.verify_key.encode()
    )

    return subkey, subaccount_tag, sk.sign(subaccount_tag).signature


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
