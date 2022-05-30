from util import sn_address
import ss
import time
import base64
import json
from nacl.encoding import Base64Encoder
from nacl.signing import SigningKey
import nacl.utils
import pytest

# This test runs in a few seconds, a short ttl is fine.
ttl = 600_000

# Size of the msg we store for the tests
msg_size = 70000

@pytest.fixture(scope='module')
def big_store(omq, random_sn, exclude):
    sk = SigningKey.generate()
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    pk = '03' + sk.verify_key.encode().hex()

    hashes = []
    for x in range(12):
        s = []
        for y in range(10):
            ts = int(time.time() * 1000)
            exp = ts + ttl
            msg = nacl.utils.random(msg_size)
            s.append(omq.request_future(conn, 'storage.store', [json.dumps({
                "pubkey": pk,
                "timestamp": ts,
                "ttl": ttl,
                "data": base64.b64encode(msg).decode()}).encode()]))
        for si in s:
            si = si.get()
            assert len(si) == 1
            si = json.loads(si[0])
            assert 'hash' in si
            hashes.append(si['hash'])

    return {
            'conn': conn,
            'sk': sk,
            'pk': pk,
            'hashes': hashes
            }


def test_retrieve_count(omq, big_store):

    conn = big_store['conn']
    sk = big_store['sk']
    pk = big_store['pk']
    hashes = big_store['hashes']

    ts = int(time.time() * 1000)
    to_sign = "retrieve{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()

    s5 = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 5
        })])

    s8 = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 8,
            "last_hash": hashes[-3]
        })])

    s20 = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 20,
            "last_hash": hashes[110]
        })])

    # This one is a little tricky: our last one is the limit, but we should still get more: false
    s10 = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 10,
            "last_hash": hashes[-11]
        })])

    s5 = s5.get()
    assert len(s5) == 1
    s5 = json.loads(s5[0])
    assert [x['hash'] for x in s5['messages']] == hashes[0:5]
    assert s5['more']


    s8 = s8.get()
    assert len(s8) == 1
    s8 = json.loads(s8[0])
    assert [x['hash'] for x in s8['messages']] == hashes[-2:]
    assert not s8['more']


    s20 = s20.get()
    assert len(s20) == 1
    s20 = json.loads(s20[0])
    assert [x['hash'] for x in s20['messages']] == hashes[111:]
    assert not s20['more']

    # We request 100, but should hit the implicit max size at 83
    s100 = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 100,
            "last_hash": hashes[10]
        })])

    

    s100 = s100.get()
    assert len(s100) == 1
    s100 = json.loads(s100[0])
    assert [x['hash'] for x in s100['messages']] == hashes[11:94]
    assert s100['more']


    s10 = s10.get()
    assert len(s10) == 1
    s10 = json.loads(s10[0])
    assert [x['hash'] for x in s10['messages']] == hashes[-10:]
    assert not s10['more']




def test_retrieve_size(omq, big_store):

    conn = big_store['conn']
    sk = big_store['sk']
    pk = big_store['pk']
    hashes = big_store['hashes']

    ts = int(time.time() * 1000)
    to_sign = "retrieve{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()

    s500k = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_size": 500_000,
            "last_hash": hashes[2]
        })])

    s600k = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_size": 600_000,
            "last_hash": hashes[-8]
        })])

    smax = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_size": -1,
            "last_hash": hashes[2]
        })])

    smax_nomore = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_size": -1,
            "last_hash": hashes[110]
        })])

    sthird = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_size": -3,
            "last_hash": hashes[49]
        })])

    sdefault = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "last_hash": hashes[89]
        })])

    sdefault_nomore = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "last_hash": hashes[103]
        })])

    s500k = s500k.get()
    assert len(s500k) == 1
    s500k = json.loads(s500k[0])
    assert [x['hash'] for x in s500k['messages']] == hashes[3:8]
    assert s500k['more']


    s600k = s600k.get()
    assert len(s600k) == 1
    s600k = json.loads(s600k[0])
    assert [x['hash'] for x in s600k['messages']] == hashes[-7:-1]
    assert s600k['more']


    # Max retrieve size (-1) is 7.8MB, so with 70000*4/3=93333 bytes (plus a bit) per message
    # retrieved, we should get 83 messages back.
    smax = smax.get()
    assert len(smax) == 1
    smax = json.loads(smax[0])
    assert [x['hash'] for x in smax['messages']] == hashes[3:86]
    assert smax['more']


    # 1/3 max retrieve should fit 27:
    sthird = sthird.get()
    assert len(sthird) == 1
    sthird = json.loads(sthird[0])
    assert [x['hash'] for x in sthird['messages']] == hashes[50:77]
    assert sthird['more']


    # Default is 1/5, should fit 16:
    sdefault = sdefault.get()
    assert len(sdefault) == 1
    sdefault = json.loads(sdefault[0])
    assert [x['hash'] for x in sdefault['messages']] == hashes[90:106]
    assert sdefault['more']


    smax_nomore = smax_nomore.get()
    assert len(smax_nomore) == 1
    smax_nomore = json.loads(smax_nomore[0])
    assert [x['hash'] for x in smax_nomore['messages']] == hashes[111:]
    assert not smax_nomore['more']

    
    sdefault_nomore = sdefault_nomore.get()
    assert len(sdefault_nomore) == 1
    sdefault_nomore = json.loads(sdefault_nomore[0])
    assert [x['hash'] for x in sdefault_nomore['messages']] == hashes[-16:]
    assert not sdefault_nomore['more']


def test_retrieve_size_and_count(omq, big_store):

    conn = big_store['conn']
    sk = big_store['sk']
    pk = big_store['pk']
    hashes = big_store['hashes']

    ts = int(time.time() * 1000)
    to_sign = "retrieve{}".format(ts).encode()
    sig = sk.sign(to_sign, encoder=Base64Encoder).signature.decode()

    s5_or_1M = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 5,
            "max_size": 1_000_000,
            "last_hash": hashes[19]
        })])

    s10_or_700k = omq.request_future(conn, 'storage.retrieve', [
        json.dumps({
            "pubkey": pk,
            "timestamp": ts,
            "signature": sig,
            "max_count": 10,
            "max_size": 700_000,
            "last_hash": hashes[29]
        })])

    s5_or_1M = s5_or_1M.get()
    assert len(s5_or_1M) == 1
    s5_or_1M = json.loads(s5_or_1M[0])
    assert [x['hash'] for x in s5_or_1M['messages']] == hashes[20:25]
    assert s5_or_1M['more']
    
    s10_or_700k = s10_or_700k.get()
    assert len(s10_or_700k) == 1
    s10_or_700k = json.loads(s10_or_700k[0])
    assert [x['hash'] for x in s10_or_700k['messages']] == hashes[30:37]
    assert s10_or_700k['more']
