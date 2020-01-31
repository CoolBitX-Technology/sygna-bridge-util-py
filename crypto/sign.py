from ecdsa import SigningKey, VerifyingKey, SECP256k1
import json


def signObj(message: dict, private_key: str) -> str:
    """sign utf-8 message with private message"""
    message_str = json.dumps(message)
    print(type(message_str))
    print(message_str)
    message_b = message_str.encode('utf-8')
    private_key_b_obj = bytearray.fromhex(private_key)
    sk = SigningKey.from_string(private_key_b_obj, SECP256k1)
    sig = sk.sign(message_b)
    return sig.hex()


def verifyObj(message: str, signature: str, public_key: str) -> bool:
    """ verify message(utf-8) with signature and public key"""
    message_str = json.dumps(message)
    message_b = message_str.encode('utf-8')
    public_key_b_obj = bytearray.fromhex(public_key)
    signature_b_obj = bytearray.fromhex(signature)
    vk = VerifyingKey.from_string(public_key_b_obj, SECP256k1)
    is_valid = vk.verify(signature_b_obj, message_b)
    return is_valid


def get_canonical_signature(signature: str) -> str:
    return
