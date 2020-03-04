from . import ecies, sign as sygna_sign
import json
from sygna_bridge_util.validator import (
    validate_permission_schema,
    validate_permission_request_schema,
    validate_transaction_id_schema,
    validate_callback_schema,
    validate_private_key
)
from sygna_bridge_util.config import PermissionStatus


def sygna_encrypt_private_data(data: dict, public_key: str) -> str:
    """ Encrypt private info data to hex string.
    Args:
        data (dict): private info in data format
        public_key (str): recipient public key in hex string

    Returns:
        str. ECIES encoded private message.
    """
    data_str = json.dumps(data)
    return ecies.ecies_encrypt(data_str, public_key)


def sygna_decrypt_private_data(private_message: str, private_key: str) -> dict:
    """ Decode private info from recipient server."""
    decode_str = ecies.ecies_decrypt(private_message, private_key)
    return json.loads(decode_str)


def sign_data(data: dict, private_key: str) -> dict:
    """ sign data.
    Args:
        data (dict)
        private_key (str)

    Returns:
        dict. original object adding a signature field
    """
    data['signature'] = ''
    signature = sygna_sign.sign_message(data, private_key)
    print(f'sign_data signature ={signature}')
    data['signature'] = signature
    return data


def sign_permission_request(data: dict, private_key: str) -> dict:
    """ sign permission request data

    Args:
        data(dict):{
            private_info (str)
            transaction (dict)
            data_dt (str)
            Optional expire_date(int)
        }
        private_key (str)

    Returns:
        dict({private_info: str, transaction:dict, data_dt:str, expire_date?:int, signature:str})

    Raises:
        Exception('parameters are not valid')
    """
    validate_permission_request_schema(data)
    validate_private_key(private_key)

    data_to_sign = {
        'private_info': data['private_info'],
        'transaction': data['transaction'],
        'data_dt': data['data_dt']
    }
    if 'expire_date' in data:
        data_to_sign['expire_date'] = data['expire_date']
    return sign_data(data_to_sign, private_key)


def sign_callback(data: dict, private_key: str) -> dict:
    """ sign callback data

    Args:
        data (dict): {
            callback_url: str
        }
        private_key (str)

    Returns:
        dict({callback_url_string: str, signature:str})

    Raises:
        Exception('parameters are not valid')
    """
    validate_callback_schema(data)
    validate_private_key(private_key)
    data_to_sign = {
        'callback_url': data['callback_url']
    }
    return sign_data(data_to_sign, private_key)


def sign_permission(data: dict, private_key: str) -> dict:
    """ sign permission data

    Args:
        data(dict):{
            transfer_id (str)
            permission_status (str) : ACCEPTED or REJECTED
            Optional expire_date(int)
            Optional reject_code(str) : BVRC001,BVRC002,BVRC003,BVRC004 or BVRC999
            Optional reject_message(str)
        }
        private_key (str)

    Returns:
        dict({transfer_id:str, permission_status: str,expire_date?:int,reject_code?:str,reject_message?:str , signature: str})

    Raises:
        Exception('parameters are not valid')
    """
    validate_permission_schema(data)
    validate_private_key(private_key)

    data_to_sign = {
        'transfer_id': data['transfer_id'],
        'permission_status': data['permission_status'],
    }

    if 'expire_date' in data:
        data_to_sign['expire_date'] = data['expire_date']

    if data['permission_status'] == PermissionStatus.REJECTED.value:
        data_to_sign['reject_code'] = data['reject_code']
        if 'reject_message' in data:
            data_to_sign['reject_message'] = data['reject_message']
    return sign_data(data_to_sign, private_key)


def sign_transaction_id(data: dict, private_key: str) -> dict:
    """ sign transaction id data

    Args:
        data(dict):{
            transfer_id (str)
            txid (str)
        }
        private_key (str)

    Returns:
        dict({transfer_id:str, txid: str, signature: str})

    Raises:
        Exception('parameters are not valid')
    """

    validate_transaction_id_schema(data)
    validate_private_key(private_key)

    data_to_sign = {
        'transfer_id': data['transfer_id'],
        'txid': data['txid']
    }
    return sign_data(data_to_sign, private_key)
