from util import sn_address
import ss
import time
import base64
import json
from nacl.encoding import HexEncoder, Base64Encoder
from nacl.hash import blake2b
from nacl.signing import VerifyKey
import nacl.exceptions

def test_delete_all(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [omq.connect_remote(sn_address(sn)) for sn in sns]

    msgs = ss.store_n(omq, conns[0], sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = int(time.time() * 1000)
    to_sign = "delete_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "timestamp": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.delete_all', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    msg_hashes = sorted(m['hash'] for m in msgs)

    # signature of ( PUBKEY_HEX || TIMESTAMP || DELETEDHASH[0] || ... || DELETEDHASH[N] )
    expected_signed = "".join((my_ss_id, str(ts), *msg_hashes)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == msg_hashes
        edpk = VerifyKey(k, encoder=HexEncoder)
        edpk.verify(expected_signed, base64.b64decode(v['signature']))

    r = json.loads(omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert not r['messages']


def test_stale_delete_all(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sn = ss.random_swarm_members(swarm, 2, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    msgs = ss.store_n(omq, conn, sk, b"omg123", 5)

    my_ss_id = '05' + sk.verify_key.encode().hex()

    ts = int((time.time() - 120) * 1000)
    to_sign = "delete_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = {
            "pubkey": my_ss_id,
            "timestamp": ts,
            "signature": sig
    }

    resp = omq.request_future(conn, 'storage.delete_all', [json.dumps(params).encode()]).get()
    assert resp == [b'406', b'delete_all timestamp too far from current time']

    ts = int((time.time() + 120) * 1000)
    to_sign = "delete_all{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params["signature"] = sig

    resp = omq.request_future(conn, 'storage.delete_all', [json.dumps(params).encode()]).get()
    assert resp == [b'406', b'delete_all timestamp too far from current time']


def test_delete(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk, netid=2)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [omq.connect_remote(sn_address(sn)) for sn in sns]

    msgs = ss.store_n(omq, conns[0], sk, b"omg123", 5, netid=2)

    my_ss_id = '02' + sk.verify_key.encode().hex()

    ts = int(time.time() * 1000)
    actual_del_msgs = sorted(msgs[i]['hash'] for i in (1, 4))
    # Deliberately mis-sort the requested hashes to verify that the return is sorted as expected
    del_msgs = sorted(actual_del_msgs + ['bepQtTaYrzcuCXO3fZkmk/h3xkMQ3vCh94i5HzLmj3I'], reverse=True)
    to_sign = ("delete" + "".join(del_msgs)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "messages": del_msgs,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.delete', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || RMSG[0] || ... || RMSG[N] || DMSG[0] || ... || DMSG[M] )
    expected_signed = "".join(
            (my_ss_id, *del_msgs, *actual_del_msgs)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == actual_del_msgs
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = json.loads(omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert len(r['messages']) == 3


def test_delete_before(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)
    sns = ss.random_swarm_members(swarm, 2, exclude)
    conns = [omq.connect_remote(sn_address(sn)) for sn in sns]

    msgs = ss.store_n(omq, conns[0], sk, b"omg123", 10)

    # store_n submits msgs with decreasing timestamps:
    assert all(msgs[i]['req']['timestamp'] > msgs[i+1]['req']['timestamp'] for i in range(len(msgs)-1))

    my_ss_id = '05' + sk.verify_key.encode().hex()

    # Delete the last couple messages:
    ts = msgs[8]['req']['timestamp']
    expected_del = sorted(msgs[i]['hash'] for i in range(8, len(msgs)))

    to_sign = ("delete_before" + str(ts)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "before": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.delete_before', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
    expected_signed = "".join((my_ss_id, str(ts), *expected_del)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == expected_del
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = json.loads(omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert len(r['messages']) == 8


    # Delete with no matches:
    ts = msgs[7]['req']['timestamp'] - 1
    to_sign = ("delete_before" + str(ts)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "before": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[0], 'storage.delete_before', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
    expected_signed = "".join((my_ss_id, str(ts))).encode()
    for k, v in r['swarm'].items():
        assert not v['deleted']
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = json.loads(omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert len(r['messages']) == 8


    # Delete most of the remaining:
    ts = msgs[1]['req']['timestamp']
    expected_del = sorted(msgs[i]['hash'] for i in range(1, 8))

    to_sign = ("delete_before" + str(ts)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "before": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[0], 'storage.delete_before', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
    expected_signed = "".join((my_ss_id, str(ts), *expected_del)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == expected_del
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = json.loads(omq.request_future(conns[0], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert len(r['messages']) == 1


    # Delete the last one
    ts = msgs[0]['req']['timestamp'] + 1
    expected_del = [msgs[0]['hash']]

    to_sign = ("delete_before" + str(ts)).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()
    params = json.dumps({
            "pubkey": my_ss_id,
            "before": ts,
            "signature": sig
    }).encode()

    resp = omq.request_future(conns[1], 'storage.delete_before', [params]).get()

    assert len(resp) == 1
    r = json.loads(resp[0])

    assert set(r['swarm'].keys()) == {x['pubkey_ed25519'] for x in swarm['snodes']}

    # ( PUBKEY_HEX || BEFORE || DELETEDHASH[0] || ... || DELETEDHASH[N] )
    expected_signed = "".join((my_ss_id, str(ts), *expected_del)).encode()
    for k, v in r['swarm'].items():
        assert v['deleted'] == expected_del
        edpk = VerifyKey(k, encoder=HexEncoder)
        try:
            edpk.verify(expected_signed, base64.b64decode(v['signature']))
        except nacl.exceptions.BadSignatureError as e:
            print("Bad signature from swarm member {}".format(k))
            raise e

    r = json.loads(omq.request_future(conns[1], 'storage.retrieve',
        [json.dumps({ "pubkey": my_ss_id }).encode()]
        ).get()[0])
    assert not r['messages']
