import pytest
from api import (
    check_type,
    check_specific_key,
    check_data_signed,
    check_sign_callback_parameters,
    check_sign_permission_parameters,
    check_sign_permission_request_parameters,
    check_sign_tx_id_parameters,
    PermissionStatus
)


def test_check_type():
    """should throw exception if type is not match"""
    with pytest.raises(TypeError) as excinfo:
        check_type('str', int)
    assert "Expect data to be <class 'int'>, got <class 'str'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        check_type({'key': 'value'}, str)
    assert "Expect data to be <class 'str'>, got <class 'dict'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        check_type({'key': 'value'}, str, 'test_data')
    assert "Expect test_data to be <class 'str'>, got <class 'dict'>" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        check_type('str', 'number', 'test_number')
    assert "Expect test_number to be <class 'number'>, got <class 'str'>" == str(
        excinfo.value)

    try:
        check_type({'key': 'value'}, dict, 'test_data')
        check_type('123', str)
        check_type(123, 'number')
        check_type(0.0000123, 'number')
    except TypeError:
        pytest.fail("Unexpected TypeError")


def test_check_specific_key():
    """should throw exception if type is not match or key is not exist"""
    with pytest.raises(TypeError) as excinfo:
        check_specific_key('str', 'test', str)
    assert "Expect data to be <class 'dict'>, got <class 'str'>" == str(
        excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        check_specific_key({'key': 'value'}, 'test', str)
    assert 'Missing test in data' == str(
        excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        check_specific_key({'key': 'value'}, 'test', str, 'test_dict')
    assert 'Missing test in test_dict' == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        check_specific_key({'key': 'value'}, 'key', int)
    assert "Expect key to be <class 'int'>, got <class 'str'>" == str(
        excinfo.value)

    try:
        check_specific_key({'key': 'value'}, 'key', str)
        check_specific_key({'number_key': 123.05}, 'number_key', 'number')
        check_specific_key({'dict_key': {'key': 'value'}},
                           'dict_key', dict)
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")


def test_check_data_signed():
    """should throw exception if type is not match or signature is not valid"""
    """data should be dict"""
    with pytest.raises(TypeError) as excinfo:
        check_data_signed('str')
    assert "Expect data to be <class 'dict'>, got <class 'str'>" == str(
        excinfo.value)

    """data should contain signature key"""
    with pytest.raises(ValueError) as excinfo:
        check_data_signed({'key': '123'})
    assert "Missing signature in data" == str(excinfo.value)

    """signature should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_data_signed({'signature': 123})
    assert "Expect signature to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """signature length should be 128"""
    with pytest.raises(ValueError) as excinfo:
        check_data_signed({'signature': 'asdjk'})
    assert "Expect signature length to be 128." == str(
        excinfo.value)

    try:
        check_data_signed(
            {
                'signature': 'fc1f09ab08ebdd072ea6da53a5691abcc18c9163b1be1f0921a5adb50e3f5077fc1f09ab08ebdd072ea6da53a5691abcc18c9163b1be1f0921a5adb50e3f5077'
            }
        )
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")


def test_check_sign_permission_request_parameters():
    """should throw exception if type is not match or parameters are not valid"""
    """private_key should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters('', {}, '', 123)
    assert "Expect private_key to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """private_info should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(123, {}, '', '')
    assert "Expect private_info to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """data_dt should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters('', {}, 123, '')
    assert "Expect data_dt to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transaction should be dict"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters('', '', '', '')
    assert "Expect transaction to be <class 'dict'>, got <class 'str'>" == str(
        excinfo.value)

    """transaction should contain beneficiary_addrs key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '', {}, '', '')
    assert "Missing beneficiary_addrs in transaction" == str(excinfo.value)

    """transaction['beneficiary_addrs'] should be list"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': 123
            },
            '',
            ''
        )
    assert "Expect beneficiary_addrs to be <class 'list'>, got <class 'int'>" == str(
        excinfo.value)

    """transaction should contain originator_addrs key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': []
            },
            '',
            ''
        )
    assert "Missing originator_addrs in transaction" == str(excinfo.value)

    """transaction['originator_addrs'] should be list"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': '123'
            },
            '',
            ''
        )
    assert "Expect originator_addrs to be <class 'list'>, got <class 'str'>" == str(
        excinfo.value)

    """transaction should contain originator_vasp_code key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': []
            },
            '',
            ''
        )
    assert "Missing originator_vasp_code in transaction" == str(excinfo.value)

    """transaction['originator_vasp_code'] should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': 123
            },
            '',
            ''
        )
    assert "Expect originator_vasp_code to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transaction should contain beneficiary_vasp_code key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123'
            },
            '',
            ''
        )
    assert "Missing beneficiary_vasp_code in transaction" == str(excinfo.value)

    """transaction['beneficiary_vasp_code'] should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123',
                'beneficiary_vasp_code': 123
            },
            '',
            ''
        )
    assert "Expect beneficiary_vasp_code to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transaction should contain transaction_currency key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123',
                'beneficiary_vasp_code': '123'
            },
            '',
            ''
        )
    assert "Missing transaction_currency in transaction" == str(excinfo.value)

    """transaction['transaction_currency'] should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123',
                'beneficiary_vasp_code': '123',
                'transaction_currency': 123
            },
            '',
            ''
        )
    assert "Expect transaction_currency to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transaction should contain amount key"""
    with pytest.raises(ValueError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123',
                'beneficiary_vasp_code': '123',
                'transaction_currency': '123'
            },
            '',
            ''
        )
    assert "Missing amount in transaction" == str(excinfo.value)

    """transaction['amount'] should be number"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_request_parameters(
            '',
            {
                'beneficiary_addrs': [],
                'originator_addrs': [],
                'originator_vasp_code': '123',
                'beneficiary_vasp_code': '123',
                'transaction_currency': '123',
                'amount': '123'
            },
            '',
            ''
        )
    assert "Expect amount to be <class 'number'>, got <class 'str'>" == str(
        excinfo.value)

    try:
        check_sign_permission_request_parameters(
            "04f76b",
            {
                "originator_vasp_code": "AAA",
                "originator_addrs": ["344"],
                "beneficiary_vasp_code": "BBB",
                "beneficiary_addrs": ["0x1234567890101010"],
                "transaction_currency": "0x80000000",
                "amount": 0.1234
            },
            "2019-07-29T06:29:00.123Z",
            'private_key'
        )
    except (TypeError, ValueError):
        pytest.fail("Unexpected TypeError or ValueError")


def test_check_sign_callback_parameters():
    """should throw exception if type is not match or parameters are not valid"""
    """private_key should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_callback_parameters('callback_url', 123)
    assert "Expect private_key to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """callback_url should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_callback_parameters(123, 'private_key')
    assert "Expect callback_url to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    try:
        check_sign_callback_parameters('callback_url', 'private_key')
    except (TypeError):
        pytest.fail("Unexpected TypeError")


def test_check_sign_permission_parameters():
    """should throw exception if type is not match or parameters are not valid"""
    """private_key should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_parameters('', '', 123)
    assert "Expect private_key to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transfer_id should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_parameters(123, '', '')
    assert "Expect transfer_id to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """permission_status should be instance of PermissionStatus Enum"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_parameters('', '', '')
    assert "permission_status must be an instance of PermissionStatus Enum" == str(
        excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        check_sign_permission_parameters('', 'ABCDE', '')
    assert "permission_status must be an instance of PermissionStatus Enum" == str(
        excinfo.value)

    try:
        check_sign_permission_parameters(
            'transfer_id', PermissionStatus.ACCEPT, 'private_key')
        check_sign_permission_parameters(
            'transfer_id', PermissionStatus.REJECT, 'private_key')
        check_sign_permission_parameters(
            'transfer_id', 'ACCEPT', 'private_key')
        check_sign_permission_parameters(
            'transfer_id', 'REJECT', 'private_key')
    except TypeError:
        pytest.fail("Unexpected TypeError")


def test_check_sign_tx_id_parameters():
    """should throw exception if type is not match or parameters are not valid"""
    """private_key should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_tx_id_parameters('', '', 123)
    assert "Expect private_key to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """transfer_id should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_tx_id_parameters(123, '', '')
    assert "Expect transfer_id to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    """txid should be str"""
    with pytest.raises(TypeError) as excinfo:
        check_sign_tx_id_parameters('', 123, '')
    assert "Expect txid to be <class 'str'>, got <class 'int'>" == str(
        excinfo.value)

    try:
        check_sign_tx_id_parameters(
            'transfer_id', 'txid', 'private_key')
    except TypeError:
        pytest.fail("Unexpected TypeError")


if __name__ == '__main__':
    test_check_type()
    test_check_specific_key()
    test_check_data_signed()
    test_check_sign_permission_request_parameters()
    test_check_sign_callback_parameters()
    test_check_sign_permission_parameters()
    test_check_sign_tx_id_parameters()
