import json
import copy
from ecdsa.keys import VerifyingKey
from ecdsa.curves import SECP256k1
from typing import Union
from config import SYGNA_BRIDGE_CENTRAL_PUBKEY


def verify_data(data: dict, public_key: str = SYGNA_BRIDGE_CENTRAL_PUBKEY) -> bool:
    """ verify data with provided public key or default sygna bridge public key

    Args:
        data (dict)
        public_key (str)
    Returns:
        bool
    """
    signature = ''
    print(f'verify_data data={data}')
    copy_data = copy.deepcopy(data)
    if 'signature' in copy_data:
        signature = copy_data['signature']
        copy_data['signature'] = ''

    return verify_message(copy_data, signature, public_key)


def verify_message(message: Union[dict, str], signature: str, public_key: str) -> bool:
    """ verify message(utf-8) with signature and public key"""
    print(f'verify_message message = {message}')
    print(f'verify_message signature = {signature}')
    print(f'verify_message public_key = {public_key}')
    message_str = json.dumps(message)
    print(f'verify_message message_str = {message_str}')
    print(f'verity_message type = {type(message_str)}')
    message_b = message_str.encode('utf-8')
    print(f'verity_message message_b = {message_b}')
    print(f'verity_message message_b type = {type(message_b)}')
    public_key_b_obj = bytearray.fromhex(public_key)
    print(f'verity_message public_key_b_obj = {public_key_b_obj}')
    print(f'verity_message public_key_b_obj type = {type(public_key_b_obj)}')
    signature_b_obj = bytearray.fromhex(signature)
    print(f'verity_message signature_b_obj = {signature_b_obj}')
    print(f'verity_message signature_b_obj type = {type(signature_b_obj)}')

    vk = VerifyingKey.from_string(public_key_b_obj, curve=SECP256k1)
    print(f'verity_message vk = {vk}')

    is_valid = vk.verify(signature_b_obj, message_b)
    return is_valid
