from ecdsa import SigningKey, SECP256k1, util
import json
from hashlib import sha256

def sign_message(message: dict, private_key: str) -> str:
    """sign utf-8 message with private message"""

    """The result of json.dump is different from JSON.stringify in js, 
    because json.dumps applies some minor pretty-printing by default but JSON.stringify does not. 
    To remove all whitespace, like JSON.stringify,we need to specify the separators."""

    message_str = json.dumps(message, separators=(',', ':'))
    message_b = message_str.encode(encoding='utf-8')
    print(f'message_str = {message_str}')
    private_key_b_obj = bytearray.fromhex(private_key)
    sk = SigningKey.from_string(string=private_key_b_obj, curve=SECP256k1)
    sig = sk.sign_deterministic(data=message_b, hashfunc=sha256, sigencode=util.sigencode_string_canonize)
    return sig.hex()
