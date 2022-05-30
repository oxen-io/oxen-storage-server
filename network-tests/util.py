from oxenmq import Address

def sn_address(sn):
    return Address(sn['ip'], sn['port_omq'], bytes.fromhex(sn['pubkey_x25519']))
