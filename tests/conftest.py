
import pytest
import pyoxenmq
import json
import random

@pytest.fixture(scope="module")
def omq():
    omq = pyoxenmq.OxenMQ()
    omq.start()
    return omq


@pytest.fixture(scope="module")
def sns(omq):
    remote = omq.connect_remote("curve://public.loki.foundation:38161/80adaead94db3b0402a6057869bdbe63204a28e93589fd95a035480ed6c03b45")
    x = omq.request(remote, "rpc.get_service_nodes")
    assert(len(x) == 2 and x[0] == b'200')
    return json.loads(x[1])

@pytest.fixture(scope="module")
def random_sn(omq, sns):
    sn = random.choice(sns['service_node_states'])
    addr = "curve://{}:{}/{}".format(sn['public_ip'], sn['storage_lmq_port'], sn['pubkey_x25519'])
    print(addr)
    conn = omq.connect_remote(addr)
    return conn


@pytest.fixture
def sk():
    from nacl.signing import SigningKey
    return SigningKey.generate()
