from typing import Union
from numbers import Number

from .permission_status import PermissionStatus


def check_type(data, expect_type, variable_name: str = 'data') -> None:
    if type(expect_type) is str and expect_type == 'number':
        if isinstance(data, Number) is False:
            raise TypeError('Expect {0} to be <class \'{1}\'>, got {2}'.format(
                variable_name,
                expect_type,
                type(data))
            )
    elif type(data) is not expect_type:
        raise TypeError('Expect {0} to be {1}, got {2}'.format(
            variable_name,
            expect_type,
            type(data))
        )


def check_specific_key(data: dict, key: str, expect_value_type, dict_name: str = 'data') -> None:
    check_type(data, dict)
    if key not in data:
        raise ValueError('Missing {0} in {1}'.format(key, dict_name))
    check_type(data[key], expect_value_type, key)


def check_data_signed(data: dict) -> None:
    """check data has valid signature"""
    check_type(data, dict)
    check_specific_key(data, 'signature', str)

    if len(data['signature']) != 128:
        raise ValueError('Expect signature length to be 128.')


def check_sign_permission_request_parameters(private_info: str, transaction: dict, data_dt: str, private_key: str) -> None:
    """check parameters of sign_permission_request is valid"""
    check_type(private_key, str, 'private_key')
    check_type(private_info, str, 'private_info')
    check_type(data_dt, str, 'data_dt')
    check_type(transaction, dict, 'transaction')
    check_specific_key(transaction, 'beneficiary_addrs', list, 'transaction')
    check_specific_key(transaction, 'originator_addrs', list, 'transaction')
    check_specific_key(transaction, 'originator_vasp_code', str, 'transaction')
    check_specific_key(transaction, 'beneficiary_vasp_code',
                       str, 'transaction')
    check_specific_key(transaction, 'transaction_currency', str, 'transaction')
    check_specific_key(transaction, 'amount', 'number', 'transaction')


def check_sign_callback_parameters(callback_url: str, private_key: str) -> None:
    """check parameters of sign_callback is valid"""
    check_type(private_key, str, 'private_key')
    check_type(callback_url, str, 'callback_url')


def check_sign_permission_parameters(transfer_id: str, permission_status: Union[PermissionStatus, str], private_key: str) -> None:
    """check parameters of sign_permission is valid"""
    check_type(private_key, str, 'private_key')
    check_type(transfer_id, str, 'transfer_id')

    if not isinstance(permission_status, PermissionStatus):
        if type(permission_status) is not str or permission_status not in PermissionStatus.__members__:
            raise TypeError(
                'permission_status must be an instance of PermissionStatus Enum')


def check_sign_tx_id_parameters(transfer_id: str, txid: str, private_key: str) -> None:
    """check parameters of sign_txid is valid"""
    check_type(private_key, str, 'private_key')
    check_type(transfer_id, str, 'transfer_id')
    check_type(txid, str, 'txid')
