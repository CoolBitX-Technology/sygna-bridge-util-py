import ecies
import hashlib
import hmac
from Crypto.Cipher import AES
import hmac
import json
from typing import Union
import numpy as np
import array as arr


def ecies_encrypt_II(msg: str, receiver_pk: Union[str, bytes], ) -> str:
    """
       Encrypt with receiver's secp256k1 public key

       Parameters
       ----------
       receiver_pk: Union[str, bytes]
           Receiver's public key (hex str or bytes)
       msg: bytes
           Data to encrypt

       Returns
       -------
       hex str
           Pubkey(64B)+MAC key(32B)+Encrypted data(B)=>private info
       """
    ephemeral_prv_key = ecies.generate_key()
    if isinstance(receiver_pk, str):
        receiver_pubkey = ecies.hex2pub(receiver_pk)
    elif isinstance(receiver_pk, bytes):
        receiver_pubkey = ecies.PublicKey(receiver_pk)
    else:
        raise TypeError("Invalid public key type")

    # Perform key agreement
    shared_point = receiver_pubkey.multiply(ephemeral_prv_key.secret).format(False)
    print(f'shared_secret: {shared_point.hex()}')  # 130 hex str

    # Derive a key from the shared point
    hashed_secret = hashlib.sha512(shared_point).digest()  # 128 hex str
    print(f'hashed_secret: {hashed_secret.hex()}')

    # Get mac and encrypted key
    encryption_key = hashed_secret[0: 32]
    mac_key = hashed_secret[32:len(hashed_secret)]
    print(f'encryption_key: {encryption_key.hex()}')
    print(f'mac_key: {mac_key.hex()}')

    # Encrypt
    message_str = json.dumps(msg, separators=(',', ':'))
    message_b = message_str.encode(encoding='utf-8')
    iv = [0] * 16
    cipher_text = aes256_cbc_encrypt(bytes(iv), encryption_key, message_b)
    print(f'cipher_text: {cipher_text.hex()}')

    ephemeral_pub_key = ephemeral_prv_key.public_key.format(False)
    print(f'ephemeral_pub_key: {ephemeral_pub_key.hex()}')
    print(f'ephemeral_pub_key type: {type(ephemeral_pub_key)}')

    mac_msg = b''.join([bytes(iv), ephemeral_pub_key, cipher_text])
    print(f'mac_msg: {mac_msg.hex()}')

    tag = hmac_sha1(mac_key, mac_msg)
    print(f'tag: {tag}')

    result = b''.join([ephemeral_pub_key, tag, cipher_text])
    print(result.hex())

    return result.hex()


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
    enc = ecies.encrypt(public_key, msg_bytes)
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

    return ecies.decrypt(private_key, enc_message_b)


def aes256_cbc_encrypt(iv, key, plain_text):
    aes = AES.new(key, AES.MODE_CFB, iv)
    return aes.encrypt(plain_text)


def aes256_cbc_decrypt(iv, key, cipher_text):
    aes = AES.new(key, AES.MODE_CFB, iv)
    return aes.decrypt(cipher_text)


def sha512(message: str) -> str:
    return hashlib.sha512(message).digest()


def hmac_sha1(key: str, message: str) -> bytes:
    digester = hmac.new(key, message, hashlib.sha1).digest()
    mac = digester
    print(mac)
    return mac
