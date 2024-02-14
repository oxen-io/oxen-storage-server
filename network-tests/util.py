from oxenmq import Address
import random


def sn_address(sn):
    return Address(sn['ip'], sn['port_omq'], bytes.fromhex(sn['pubkey_x25519']))


def random_time_delta_ms(upper: int) -> int:
    return random.randint(1, upper * 1000)
