from ecdsa import SigningKey, VerifyingKey, SECP256k1
import json
from hashlib import sha256


def signMsg(message: dict, private_key: str) -> str:
    """sign utf-8 message with private message"""

    """The result of json.dump is different from JSON.stringify in js, 
    because json.dumps applies some minor pretty-printing by default but JSON.stringify does not. 
    To remove all whitespace, like JSON.stringify,we need to specify the separators."""

    message_str = json.dumps(message, separators=(',', ':'))
    message_b = message_str.encode('utf-8')
    print('message_b:'+message_b)
    private_key_b_obj = bytearray.fromhex(private_key)
    sk = SigningKey.from_string(string=private_key_b_obj, curve=SECP256k1)
    sig = sk.sign_deterministic(data=message_b, hashfunc=sha256)
    return sig.hex()


def verifyMsg(message: str, signature: str, public_key: str) -> bool:
    """ verify message(utf-8) with signature and public key"""
    message_str = json.dumps(message, separators=(',', ':'))
    message_b = message_str.encode('utf-8')
    public_key_b_obj = bytearray.fromhex(public_key)
    signature_b_obj = bytearray.fromhex(signature)
    vk = VerifyingKey.from_string(string=public_key_b_obj, curve=SECP256k1)
    is_valid = vk.verify(signature=signature_b_obj, data=message_b, hashfunc=sha256)
    return is_valid
