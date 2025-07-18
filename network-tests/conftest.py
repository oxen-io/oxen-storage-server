import pytest
from oxenmq import OxenMQ, Address
import json
import random


def pytest_addoption(parser):
    parser.addoption("--exclude", action="store", default="")


@pytest.fixture(scope="module")
def omq():
    omq = OxenMQ()
    omq.max_message_size = 10 * 1024 * 1024
    omq.start()
    return omq


@pytest.fixture(scope="module")
def sns(omq):
    remote = omq.connect_remote(
        Address(
            "curve://public.session.foundation:38161/9c5201e30957cd44e3dcc8ad7f94f48e6914deef77390f77a439a2d7e7f4cb5c"
        )
    )
    x = omq.request_future(remote, "rpc.get_service_nodes", b'{"active_only": true}').get()
    assert len(x) == 2 and x[0] == b'200'
    return json.loads(x[1])


@pytest.fixture(scope="module")
def random_sn(omq, sns):
    sn = random.choice(sns['service_node_states'])
    addr = Address(sn['public_ip'], sn['storage_lmq_port'], bytes.fromhex(sn['pubkey_x25519']))
    conn = omq.connect_remote(addr)
    return conn


@pytest.fixture
def sk():
    from nacl.signing import SigningKey

    return SigningKey.generate()


@pytest.fixture(scope="module")
def exclude(pytestconfig):
    s = pytestconfig.getoption("exclude")
    return {s} if s and len(s) else {}
