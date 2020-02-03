from . import ecies, sign as sygna_sign
from api import (
    check_sign_callback_parameters,
    check_sign_permission_parameters,
    check_sign_permission_request_parameters,
    check_sign_tx_id_parameters,
    PermissionStatus
)
import json
from typing import Union


def sygna_encode_private_data(data: dict, public_key: str) -> str:
    """ Encrypt private info data to hex string.
    Args:
        data (dict): private info in data format
        public_key (str): recipient public key in hex string

    Returns:
        str. ECIES encoded private message.
    """
    data_str = json.dumps(data)
    return ecies.ecies_encrypt(data_str, public_key)


def sygna_decode_private_data(private_message: str, private_key: str) -> dict:
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
    data_str = json.dumps(data)
    signature = sygna_sign.sign_message(data_str, private_key)
    data['signature'] = signature.encode("hex")
    return data


def sign_permission_request(private_info: str, transaction: dict, data_dt: str, private_key: str) -> dict:
    """ sign permission request data

    Args:
        private_info (str)
        transaction (dict)
        data_dt (str)
        private_key (str)

    Returns:
        dict({private_info: str, transaction:dict, data_dt:str, signature:str})

    Raises:
        Exception('parameters are not valid')
    """
    check_sign_permission_request_parameters(
        private_info, transaction, data_dt, private_key)

    data = {
        'private_info': private_info,
        'transaction': transaction,
        'data_dt': data_dt
    }
    result = sign_data(data, private_key)
    return result


def sign_callback(callback_url: str, private_key: str) -> dict:
    """ sign callback data

    Args:
        callback_url (str)
        private_key (str)

    Returns:
        dict({callback_url_string: str, signature:str})

    Raises:
        Exception('parameters are not valid')
    """
    check_sign_callback_parameters(callback_url, private_key)
    data = {
        'callback_url': callback_url
    }
    result = sign_data(data, private_key)
    return result


def sign_permission(transfer_id: str, permission_status: Union[PermissionStatus, str], private_key: str) -> dict:
    """ sign permission data

    Args:
        transfer_id (str)
        permission_status (PermissionStatus)
        private_key (str)

    Returns:
        dict({transfer_id:str, permission_status: str, signature: str})

    Raises:
        Exception('parameters are not valid')
    """

    check_sign_permission_parameters(
        transfer_id, permission_status, private_key)

    data = {
        'transfer_id': transfer_id,
        'permission_status': permission_status.value
    }
    result = sign_data(data, private_key)
    return result


def sign_txid(transfer_id: str, txid: str, private_key: str) -> dict:
    """ sign txid data

    Args:
        transfer_id (str)
        txid (str)
        private_key (str)

    Returns:
        dict({transfer_id:str, txid: str, signature: str})

    Raises:
        Exception('parameters are not valid')
    """

    check_sign_tx_id_parameters(
        transfer_id, txid, private_key)

    data = {
        'transfer_id': transfer_id,
        'txid': txid
    }
    result = sign_data(data, private_key)
    return result
