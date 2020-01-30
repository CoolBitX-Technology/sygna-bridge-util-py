from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der, sigencode_string

class ECDSA:

    def sign(message: str, private_key: str) -> str:
            """sign utf-8 message with private message"""
            sk = SigningKey.from_string(private_key, SECP256k1)
            return sk.sign(message)


    def verify(message: str, signature: str, public_key: str) -> bool:
        """ verify message(utf-8) with signature and public key"""
        vk = VerifyingKey.from_string(public_key, SECP256k1)
        return vk.verify(signature, message)


    def get_canonical_signature(signature: str) -> str:
        return
