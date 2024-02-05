from util import sn_address
import json
import ss
import time
from nacl.encoding import Base64Encoder
from nacl.hash import blake2b

m_yes = b'\x61\xeb'
b64_m_yes = 'Yes='
m_no = b'\x36\x8a\x5e'
b64_m_no = 'Nope'


def test_ifelse(omq, random_sn, sk, exclude):
    swarm = ss.get_swarm(omq, random_sn, sk)

    sn = ss.random_swarm_members(swarm, 1, exclude)[0]
    conn = omq.connect_remote(sn_address(sn))

    ts = int(time.time() * 1000)
    ttl = 86_400_000

    my_ss_id = '05' + sk.verify_key.encode().hex()

    def store_action(msg, ts):
        return {
            'method': 'store',
            'params': {'pubkey': my_ss_id, 'timestamp': ts, 'ttl': ttl, 'data': msg},
        }

    r = []
    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [
                json.dumps(
                    {
                        'if': {'hf_at_least': [2000000]},
                        'then': store_action(b64_m_yes, ts),
                        'else': store_action(b64_m_no, ts),
                    }
                )
            ],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [
                json.dumps(
                    {
                        'if': {'hf_at_least': [19], 'height_before': 1234},
                        'then': store_action(b64_m_yes, ts + 1),
                        'else': store_action(b64_m_no, ts + 1),
                    }
                )
            ],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [
                json.dumps(
                    {
                        'if': {'hf_at_least': [19], 'height_before': 123456789},
                        'then': store_action(b64_m_yes, ts + 2),
                        'else': store_action(b64_m_no, ts + 2),
                    }
                )
            ],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [
                json.dumps(
                    {
                        'if': {'hf_at_least': [19]},
                        'then': store_action(b64_m_yes, ts + 3),
                        'else': store_action(b64_m_no, ts + 3),
                    }
                )
            ],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [json.dumps({'if': {'hf_at_least': [19, 1]}, 'then': store_action(b64_m_yes, ts + 4)})],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [json.dumps({'if': {'hf_before': [19]}, 'then': store_action(b64_m_yes, ts + 5)})],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [json.dumps({'if': {'hf_at_least': [19]}, 'else': store_action(b64_m_yes, ts + 6)})],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [json.dumps({'if': {'hf_before': [19]}, 'else': store_action(b64_m_no, ts + 7)})],
        )
    )

    r.append(
        omq.request_future(
            conn,
            'storage.ifelse',
            [
                json.dumps(
                    {
                        'if': {'hf_at_least': [19]},
                        'then': {
                            'method': 'ifelse',
                            'params': {
                                'if': {'hf_at_least': [19]},
                                'then': {
                                    'method': 'ifelse',
                                    'params': {
                                        'if': {'height_at_least': 100},
                                        'then': {
                                            'method': 'ifelse',
                                            'params': {
                                                'if': {'v_at_least': [2, 2]},
                                                'then': {
                                                    'method': 'ifelse',
                                                    'params': {
                                                        'if': {'hf_before': [99999, 99]},
                                                        'then': {
                                                            'method': 'batch',
                                                            'params': {
                                                                'requests': [
                                                                    store_action(b64_m_yes, ts + 8),
                                                                    store_action(b64_m_yes, ts + 9),
                                                                    store_action(
                                                                        b64_m_yes, ts + 10
                                                                    ),
                                                                ]
                                                            },
                                                        },
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    }
                )
            ],
        )
    )

    bad = omq.request_future(
        conn,
        'storage.batch',
        [
            json.dumps(
                {
                    'requests': [
                        {
                            'method': 'ifelse',
                            'params': {
                                'if': {'hf_at_least': [19]},
                                'then': {'method': 'info', 'params': {}},
                                'else': {'method': 'info', 'params': {}},
                            },
                        }
                    ]
                }
            )
        ],
    )

    def hash(body, ts):
        return (
            blake2b(b'\x05' + sk.verify_key.encode() + body, encoder=Base64Encoder)
            .decode()
            .rstrip('=')
        )

    for i in range(len(r)):
        r[i] = r[i].get()
        print(r[i])
        assert len(r[i]) == 1
        r[i] = json.loads(r[i][0])
        if i not in (5, 6):
            assert 'result' in r[i] and r[i]['result']['code'] == 200 and 'body' in r[i]['result']

    assert not r[0]['condition']
    assert r[0]['result']['body']['hash'] == hash(m_no, ts)

    assert not r[1]['condition']
    assert r[1]['result']['body']['hash'] == hash(m_no, ts + 1)

    assert r[2]['condition']
    assert r[2]['result']['body']['hash'] == hash(m_yes, ts + 2)

    assert r[3]['condition']
    assert r[3]['result']['body']['hash'] == hash(m_yes, ts + 3)

    assert r[4]['condition']
    assert r[4]['result']['body']['hash'] == hash(m_yes, ts + 4)

    assert not r[5]['condition']
    assert 'result' not in r[5]

    assert r[6]['condition']
    assert 'result' not in r[6]

    assert not r[7]['condition']
    assert r[7]['result']['body']['hash'] == hash(m_no, ts + 7)

    x = r[8]
    assert x['condition']  # hf >= 19
    assert x['result']['code'] == 200
    x = x['result']['body']
    assert x['condition']  # hf >= 19
    assert x['result']['code'] == 200
    x = x['result']['body']
    assert x['condition']  # height >= 100
    assert x['result']['code'] == 200
    x = x['result']['body']
    assert x['condition']  # v >= 2.2
    assert x['result']['code'] == 200
    x = x['result']['body']
    assert x['condition']  # hf < 99999.99
    assert x['result']['code'] == 200
    x = x['result']['body']
    x = x['results']
    assert len(x) == 3
    assert [y['code'] for y in x] == [200, 200, 200]
    assert x[0]['body']['hash'] == hash(m_yes, ts + 8)
    assert x[1]['body']['hash'] == hash(m_yes, ts + 9)
    assert x[2]['body']['hash'] == hash(m_yes, ts + 10)
