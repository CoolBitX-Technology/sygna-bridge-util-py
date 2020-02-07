from ecdsa.keys import SigningKey
from ecdsa.curves import SECP256k1
from hashlib import sha256
import json
import ecdsa

def sign_message(message: dict, private_key: str) -> str:
    """sign utf-8 message with private message"""
    message_str = json.dumps(message)
    print(type(message_str))
    print(message_str)
    message_b = message_str.encode('utf-8')
    private_key_b_obj = bytearray.fromhex(private_key)
    sk = SigningKey.from_string(private_key_b_obj, SECP256k1, hashfunc=sha256)
    sig = sk.sign(message_b, entropy=None, sigencode=ecdsa.util.sigencode_string_canonize,hashfunc=sha256)
     #
    return sig.hex()