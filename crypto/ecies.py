from ecies import encrypt, decrypt
import hashlib
from Crypto.Cipher import AES
import hmac
import json


def ecies_encrypt(message: str, public_key: str) -> str:
    """Sygna Bridge ECIES Encrypt.
        Args:
           message (str): message text to encode(in utf-8 plain text)
           public_key (str): publicKey recipient's compressed public key in hex form
        Returns:
           str. hex string of encrypt private message
        """
    msg_str = json.dumps(message)
    msg_bytes = bytes(msg_str, 'utf-8')
    enc = encrypt(public_key, msg_bytes)
    return enc.hex()


def ecies_decrypt(enc_message: str, private_key: str) -> bytes:
    """Sygna Bridge ECIES Decode.
     Args:
        enc_message (str): encode_message whole hex string encrypted by Sygna ECIES
        private_key (str)

     Returns:
        bytes.
     """
    enc_message_b = bytes.fromhex(enc_message)

    return decrypt(private_key, enc_message_b)


def aes256_cbc_encrypt(iv, key, plain_text):
    aes = AES.new(key, AES.MODE_CFB, iv)
    return aes.encrypt(plain_text)


def aes256_cbc_decrypt(iv, key, cipher_text):
    aes = AES.new(key, AES.MODE_CFB, iv)
    return aes.decrypt(cipher_text)


def sha512(message: str) -> str:
    return hashlib.sha512(message).digest()


def hma_sha1(key: str, message: str) -> str:
    digester = hmac.new(key, message, hashlib.sha1).digest()
    mac = digester.digest()
    print(mac)
    return mac
