def ecies_encode(message: str, public_key: str) -> str:
    """Sygna Bridge ECIES Encode.

     Args:
        message (str): message text to encode(in utf-8 plain text)
        public_key (str): publicKey recipient's uncompressed publickey in hex form

     Returns:
        str. hex string of encoded private message
     """
    return ''


def ecies_decode(encode_message: str, private_key: str) -> str:
    """Sygna Bridge ECIES Decode.

     Args:
        encode_message (str): encode_message whole hex string encrypted by Sygna ECIES
        private_key (str)

     Returns:
        str.
     """
    return ''


def aes256_cbc_encrypt(iv, key, plain_text):
    return ''


def aes256_cbc_decrypt(iv, key, cipher_text):
    return ''


def sha512(message: str) -> str:
    return ''


def hma_sha1(key: str, message: str) -> str:
    return ''
