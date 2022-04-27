import ss
from util import sn_address
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey
import nacl.exceptions

def test_expire_all(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [omq.connect_remote(sn_address(sn)) for sn in sns]

    msgs = ss.store_n(omq, conns[0], sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = msgs[2]['req']['expiry']
    to_sign = "expire_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "expiry": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.expire_all', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    
    # 0 and 1 have later expiries than 2, so they should get updated; 2's expiry is already the
    # given value, and 3/4 are <= so shouldn't get updated.
    msg_hashes = sorted(msgs[i]['hash'] for i in (0, 1))

    # signature of ( PUBKEY_HEX || EXPIRY || UPDATED[0] || ... || UPDATED[N] )
    expected_signed = "".join((my_ss_id, str(ts), *msg_hashes)).encode()
    for k, v in r['swarm'].items():
        assert v['updated'] == msg_hashes
        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(v['signature']))

    r = omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({
            "pubkey": my_ss_id,
            "timestamp": ts,
            "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode()
            }).encode()]
        ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['messages']) == 5

    assert r['messages'][0]['expiration'] == ts
    assert r['messages'][1]['expiration'] == ts
    assert r['messages'][2]['expiration'] == ts
    assert r['messages'][3]['expiration'] == msgs[3]['req']['expiry']
    assert r['messages'][4]['expiration'] == msgs[4]['req']['expiry']


def test_stale_expire_all(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sn = ss.random_swarm_members(swarm, 2, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    msgs = ss.store_n(omq, conn, sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = int((time.time() - 120) * 1000)
    to_sign = "expire_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = {
            "pubkey": my_ss_id,
            "expiry": ts,
            "signature": sig
    }

    resp = omq.request_future(conn, 'storage.expire_all', [json.dumps(params).encode()]).get()
    assert resp == [b'406', b'expire_all timestamp should be >= current time']


def test_expire(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [omq.connect_remote(sn_address(sn)) for sn in sns]

    msgs = ss.store_n(omq, conns[0], sk, b"omg123", 10)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = msgs[6]['req']['expiry']
    hashes = [msgs[i]['hash'] for i in (0, 1, 5, 6, 7, 9)] + ['bepQtTaYrzcuCXO3fZkmk/h3xkMQ3vCh94i5HzLmj3I']
    actual_update_msgs = sorted(msgs[i]['hash'] for i in (0, 1, 5))

    hashes = sorted(hashes, reverse=True)
    to_sign = ("expire" + str(ts) + "".join(hashes)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "messages": hashes,
            "expiry": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.expire', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || EXPIRY || RMSG[0] || ... || RMSG[N] || UMSG[0] || ... || UMSG[M] )
    expected_signed = "".join((my_ss_id, str(ts), *hashes, *actual_update_msgs)).encode()
    for k, v in r['swarm'].items():
        assert v['updated'] == actual_update_msgs
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({
            "pubkey": my_ss_id,
            "timestamp": ts,
            "signature": sk.sign(f"retrieve{ts}".encode(), encoder=Base64Encoder).signature.decode()
            }).encode()]
        ).get()
    assert len(r) == 1
    r = json.loads(r[0])
    assert len(r['messages']) == 10

    for i in range(10):
        assert r['messages'][i]['expiration'] == ts if i in (0, 1, 5, 6) else msgs[i]['req']['expiry']

