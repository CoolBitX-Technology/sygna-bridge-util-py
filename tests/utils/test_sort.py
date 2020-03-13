import json
from sygna_bridge_util.config import PermissionStatus, RejectCode
from sygna_bridge_util.utils import (
    sort_transaction_id_data,
    sort_callback_data,
    sort_permission_data,
    sort_permission_request_data,
    sort_post_permission_data,
    sort_post_permission_request_data,
    sort_post_transaction_id_data
)


def test_sort_transaction_id_data():
    transaction_id_data = {
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': transaction_id_data['transfer_id'],
        'txid': transaction_id_data['txid']
    })
    assert json.dumps(sort_transaction_id_data(transaction_id_data)) == expected_sorted_dict_str

    transaction_id_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
    }
    assert json.dumps(sort_transaction_id_data(transaction_id_data)) == expected_sorted_dict_str

    transaction_id_data = {
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'key': 'value'
    }
    assert json.dumps(sort_transaction_id_data(transaction_id_data)) == expected_sorted_dict_str


def test_sort_callback_data():
    callback_data = {
        'callback_url': 'https://google.com'
    }
    expected_sorted_dict_str = json.dumps({
        'callback_url': 'https://google.com'
    })
    assert json.dumps(sort_callback_data(callback_data)) == expected_sorted_dict_str

    callback_data = {
        'callback_url': 'https://google.com',
        'key': 'value'
    }
    assert json.dumps(sort_callback_data(callback_data)) == expected_sorted_dict_str


def test_sort_permission_data():
    permission_data = {
        'permission_status': PermissionStatus.ACCEPTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'permission_status': PermissionStatus.ACCEPTED.value
    }
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'permission_status': PermissionStatus.ACCEPTED.value,
        'key': 'value'
    }
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'expire_date': 123,
        'permission_status': PermissionStatus.ACCEPTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'expire_date': permission_data['expire_date']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'expire_date': 123
    }
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'reject_code': permission_data['reject_code']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'expire_date': 123,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'expire_date': permission_data['expire_date'],
        'reject_code': permission_data['reject_code']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'reject_code': permission_data['reject_code'],
        'reject_message': permission_data['reject_message']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'expire_date': 123,
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': permission_data['transfer_id'],
        'permission_status': permission_data['permission_status'],
        'expire_date': permission_data['expire_date'],
        'reject_code': permission_data['reject_code'],
        'reject_message': permission_data['reject_message']
    })
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str

    permission_data = {
        'expire_date': 123,
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'key': 'value'
    }
    assert json.dumps(sort_permission_data(permission_data)) == expected_sorted_dict_str


def test_sort_permission_request_data():
    permission_request_data = {
        'data_dt': '2019-07-29T06:29:00.123Z',
        'transaction': {
            'transaction_currency': '0x80000000',
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'originator_vasp_code': 'VASPTWTP1',
            'amount': 1,
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'beneficiary_vasp_code': 'VASPTWTP2',
        },
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918'
    }
    expected_sorted_dict_str = json.dumps({
        'private_info': permission_request_data['private_info'],
        'transaction': {
            'originator_vasp_code': permission_request_data['transaction']['originator_vasp_code'],
            'originator_addrs': permission_request_data['transaction']['originator_addrs'],
            'beneficiary_vasp_code': permission_request_data['transaction']['beneficiary_vasp_code'],
            'beneficiary_addrs': permission_request_data['transaction']['beneficiary_addrs'],
            'transaction_currency': permission_request_data['transaction']['transaction_currency'],
            'amount': permission_request_data['transaction']['amount']
        },
        'data_dt': permission_request_data['data_dt']
    })

    assert json.dumps(sort_permission_request_data(permission_request_data)) == expected_sorted_dict_str

    permission_request_data = {
        'transaction': {
            'transaction_currency': '0x80000000',
            'amount': 1,
            'beneficiary_vasp_code': 'VASPTWTP2',
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'originator_vasp_code': 'VASPTWTP1',
            'originator_addrs_extra': {'DT': '001'}
        },
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
        'data_dt': '2019-07-29T06:29:00.123Z'
    }
    expected_sorted_dict_str = json.dumps({
        'private_info': permission_request_data['private_info'],
        'transaction': {
            'originator_vasp_code': permission_request_data['transaction']['originator_vasp_code'],
            'originator_addrs': permission_request_data['transaction']['originator_addrs'],
            'originator_addrs_extra': permission_request_data['transaction']['originator_addrs_extra'],
            'beneficiary_vasp_code': permission_request_data['transaction']['beneficiary_vasp_code'],
            'beneficiary_addrs': permission_request_data['transaction']['beneficiary_addrs'],
            'transaction_currency': permission_request_data['transaction']['transaction_currency'],
            'amount': permission_request_data['transaction']['amount']
        },
        'data_dt': permission_request_data['data_dt']
    })
    assert json.dumps(sort_permission_request_data(permission_request_data)) == expected_sorted_dict_str

    permission_request_data = {
        'data_dt': '2019-07-29T06:29:00.123Z',
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
        'transaction': {
            'originator_addrs_extra': {'DT': '001'},
            'transaction_currency': '0x80000000',
            'amount': 1,
            'originator_vasp_code': 'VASPTWTP1',
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'beneficiary_vasp_code': 'VASPTWTP2',
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'beneficiary_addrs_extra': {'DT': '002'}
        }
    }
    expected_sorted_dict_str = json.dumps({
        'private_info': permission_request_data['private_info'],
        'transaction': {
            'originator_vasp_code': permission_request_data['transaction']['originator_vasp_code'],
            'originator_addrs': permission_request_data['transaction']['originator_addrs'],
            'originator_addrs_extra': permission_request_data['transaction']['originator_addrs_extra'],
            'beneficiary_vasp_code': permission_request_data['transaction']['beneficiary_vasp_code'],
            'beneficiary_addrs': permission_request_data['transaction']['beneficiary_addrs'],
            'beneficiary_addrs_extra': permission_request_data['transaction']['beneficiary_addrs_extra'],
            'transaction_currency': permission_request_data['transaction']['transaction_currency'],
            'amount': permission_request_data['transaction']['amount']
        },
        'data_dt': permission_request_data['data_dt']
    })
    assert json.dumps(sort_permission_request_data(permission_request_data)) == expected_sorted_dict_str

    permission_request_data = {
        'expire_date': 123,
        'data_dt': '2019-07-29T06:29:00.123Z',
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
        'transaction': {
            'transaction_currency': '0x80000000',
            'originator_addrs_extra': {'DT': '001'},
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'beneficiary_addrs_extra': {'DT': '002'},
            'originator_vasp_code': 'VASPTWTP1',
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'amount': 1,
            'beneficiary_vasp_code': 'VASPTWTP2',

        }
    }
    expected_sorted_dict_str = json.dumps({
        'private_info': permission_request_data['private_info'],
        'transaction': {
            'originator_vasp_code': permission_request_data['transaction']['originator_vasp_code'],
            'originator_addrs': permission_request_data['transaction']['originator_addrs'],
            'originator_addrs_extra': permission_request_data['transaction']['originator_addrs_extra'],
            'beneficiary_vasp_code': permission_request_data['transaction']['beneficiary_vasp_code'],
            'beneficiary_addrs': permission_request_data['transaction']['beneficiary_addrs'],
            'beneficiary_addrs_extra': permission_request_data['transaction']['beneficiary_addrs_extra'],
            'transaction_currency': permission_request_data['transaction']['transaction_currency'],
            'amount': permission_request_data['transaction']['amount']
        },
        'data_dt': permission_request_data['data_dt'],
        'expire_date': permission_request_data['expire_date']
    })
    assert json.dumps(sort_permission_request_data(permission_request_data)) == expected_sorted_dict_str

    permission_request_data = {
        'key': 'value',
        'expire_date': 123,
        'data_dt': '2019-07-29T06:29:00.123Z',
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
        'transaction': {
            'transaction_currency': '0x80000000',
            'originator_addrs_extra': {'DT': '001'},
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'beneficiary_addrs_extra': {'DT': '002'},
            'originator_vasp_code': 'VASPTWTP1',
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'amount': 1,
            'beneficiary_vasp_code': 'VASPTWTP2',
        }
    }
    assert json.dumps(sort_permission_request_data(permission_request_data)) == expected_sorted_dict_str


def test_sort_post_transaction_id_data():
    post_transaction_id_data = {
        'signature': '1234567890',
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_transaction_id_data['transfer_id'],
        'txid': post_transaction_id_data['txid'],
        'signature': post_transaction_id_data['signature'],
    })
    assert json.dumps(sort_post_transaction_id_data(post_transaction_id_data)) == expected_sorted_dict_str

    post_transaction_id_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'signature': '1234567890',
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
    }
    assert json.dumps(sort_post_transaction_id_data(post_transaction_id_data)) == expected_sorted_dict_str

    post_transaction_id_data = {
        'signature': '1234567890',
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'key': 'value'
    }
    assert json.dumps(sort_post_transaction_id_data(post_transaction_id_data)) == expected_sorted_dict_str


def test_sort_post_post_permission_data():
    post_permission_data = {
        'signature': '1234567890',
        'permission_status': PermissionStatus.ACCEPTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'signature': '1234567890',
        'permission_status': PermissionStatus.ACCEPTED.value
    }
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'permission_status': PermissionStatus.ACCEPTED.value,
        'key': 'value',
        'signature': '1234567890'
    }
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'expire_date': 123,
        'signature': '1234567890',
        'permission_status': PermissionStatus.ACCEPTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'expire_date': post_permission_data['expire_date'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'signature': '1234567890',
        'permission_status': PermissionStatus.ACCEPTED.value,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'expire_date': 123
    }
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'signature': '1234567890',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'reject_code': post_permission_data['reject_code'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'signature': '1234567890',
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'expire_date': 123,
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'expire_date': post_permission_data['expire_date'],
        'reject_code': post_permission_data['reject_code'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'signature': '1234567890',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'reject_code': post_permission_data['reject_code'],
        'reject_message': post_permission_data['reject_message'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'expire_date': 123,
        'reject_code': RejectCode.BVRC001.value,
        'signature': '1234567890',
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    expected_sorted_dict_str = json.dumps({
        'transfer_id': post_permission_data['transfer_id'],
        'permission_status': post_permission_data['permission_status'],
        'expire_date': post_permission_data['expire_date'],
        'reject_code': post_permission_data['reject_code'],
        'reject_message': post_permission_data['reject_message'],
        'signature': post_permission_data['signature']
    })
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str

    post_permission_data = {
        'signature': '1234567890',
        'expire_date': 123,
        'reject_code': RejectCode.BVRC001.value,
        'permission_status': PermissionStatus.REJECTED.value,
        'reject_message': 'service_downtime',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'key': 'value'
    }
    assert json.dumps(sort_post_permission_data(post_permission_data)) == expected_sorted_dict_str


def test_sort_post_permission_request_data():
    post_permission_request_data = {
        'callback': {
            'signature': '1234567890',
            'callback_url': 'https://google.com'
        },
        'data': {
            'signature': '1234567890',
            'data_dt': '2019-07-29T06:29:00.123Z',
            'transaction': {
                'transaction_currency': '0x80000000',
                'originator_addrs': [
                    '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                ],
                'originator_vasp_code': 'VASPTWTP1',
                'amount': 1,
                'beneficiary_addrs': [
                    '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                ],
                'beneficiary_vasp_code': 'VASPTWTP2',
            },
            'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918'
        }
    }
    expected_sorted_dict_str = json.dumps({
        'data': {
            'private_info': post_permission_request_data['data']['private_info'],
            'transaction': {
                'originator_vasp_code': post_permission_request_data['data']['transaction']['originator_vasp_code'],
                'originator_addrs': post_permission_request_data['data']['transaction']['originator_addrs'],
                'beneficiary_vasp_code': post_permission_request_data['data']['transaction']['beneficiary_vasp_code'],
                'beneficiary_addrs': post_permission_request_data['data']['transaction']['beneficiary_addrs'],
                'transaction_currency': post_permission_request_data['data']['transaction']['transaction_currency'],
                'amount': post_permission_request_data['data']['transaction']['amount']
            },
            'data_dt': post_permission_request_data['data']['data_dt'],
            'signature': post_permission_request_data['data']['signature']
        },
        'callback': {
            'callback_url': post_permission_request_data['callback']['callback_url'],
            'signature': post_permission_request_data['callback']['signature']
        }
    })
    assert json.dumps(sort_post_permission_request_data(post_permission_request_data)) == expected_sorted_dict_str

    post_permission_request_data = {
        'callback': {
            'signature': '1234567890',
            'callback_url': 'https://google.com'
        },
        'data': {
            'data_dt': '2019-07-29T06:29:00.123Z',
            'transaction': {
                'amount': 1,
                'originator_addrs': [
                    '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                ],
                'beneficiary_vasp_code': 'VASPTWTP2',
                'transaction_currency': '0x80000000',
                'originator_vasp_code': 'VASPTWTP1',
                'originator_addrs_extra': {'DT': '001'},
                'beneficiary_addrs': [
                    '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                ],
            },
            'signature': '1234567890',
            'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918'
        }
    }
    expected_sorted_dict_str = json.dumps({
        'data': {
            'private_info': post_permission_request_data['data']['private_info'],
            'transaction': {
                'originator_vasp_code': post_permission_request_data['data']['transaction']['originator_vasp_code'],
                'originator_addrs': post_permission_request_data['data']['transaction']['originator_addrs'],
                'originator_addrs_extra': post_permission_request_data['data']['transaction']['originator_addrs_extra'],
                'beneficiary_vasp_code': post_permission_request_data['data']['transaction']['beneficiary_vasp_code'],
                'beneficiary_addrs': post_permission_request_data['data']['transaction']['beneficiary_addrs'],
                'transaction_currency': post_permission_request_data['data']['transaction']['transaction_currency'],
                'amount': post_permission_request_data['data']['transaction']['amount']
            },
            'data_dt': post_permission_request_data['data']['data_dt'],
            'signature': post_permission_request_data['data']['signature']
        },
        'callback': {
            'callback_url': post_permission_request_data['callback']['callback_url'],
            'signature': post_permission_request_data['callback']['signature']
        }
    })
    assert json.dumps(sort_post_permission_request_data(post_permission_request_data)) == expected_sorted_dict_str

    post_permission_request_data = {
        'callback': {
            'callback_url': 'https://google.com',
            'signature': '1234567890'
        },
        'data': {
            'transaction': {
                'originator_vasp_code': 'VASPTWTP1',
                'beneficiary_addrs_extra': {'DT': '002'},
                'amount': 1,
                'originator_addrs': [
                    '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                ],
                'beneficiary_vasp_code': 'VASPTWTP2',
                'beneficiary_addrs': [
                    '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                ],
                'transaction_currency': '0x80000000',
                'originator_addrs_extra': {'DT': '001'},
            },
            'signature': '1234567890',
            'data_dt': '2019-07-29T06:29:00.123Z',
            'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918'
        }
    }
    expected_sorted_dict_str = json.dumps({
        'data': {
            'private_info': post_permission_request_data['data']['private_info'],
            'transaction': {
                'originator_vasp_code': post_permission_request_data['data']['transaction']['originator_vasp_code'],
                'originator_addrs': post_permission_request_data['data']['transaction']['originator_addrs'],
                'originator_addrs_extra': post_permission_request_data['data']['transaction']['originator_addrs_extra'],
                'beneficiary_vasp_code': post_permission_request_data['data']['transaction']['beneficiary_vasp_code'],
                'beneficiary_addrs': post_permission_request_data['data']['transaction']['beneficiary_addrs'],
                'beneficiary_addrs_extra': post_permission_request_data['data']['transaction']['beneficiary_addrs_extra'],
                'transaction_currency': post_permission_request_data['data']['transaction']['transaction_currency'],
                'amount': post_permission_request_data['data']['transaction']['amount']
            },
            'data_dt': post_permission_request_data['data']['data_dt'],
            'signature': post_permission_request_data['data']['signature']
        },
        'callback': {
            'callback_url': post_permission_request_data['callback']['callback_url'],
            'signature': post_permission_request_data['callback']['signature']
        }
    })
    assert json.dumps(sort_post_permission_request_data(post_permission_request_data)) == expected_sorted_dict_str

    post_permission_request_data = {
        'callback': {
            'callback_url': 'https://google.com',
            'signature': '1234567890'
        },
        'data': {
            'expire_date': 123,
            'transaction': {
                'originator_vasp_code': 'VASPTWTP1',
                'beneficiary_addrs_extra': {'DT': '002'},
                'amount': 1,
                'originator_addrs': [
                    '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                ],
                'beneficiary_vasp_code': 'VASPTWTP2',
                'beneficiary_addrs': [
                    '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                ],
                'transaction_currency': '0x80000000',
                'originator_addrs_extra': {'DT': '001'},
            },
            'signature': '1234567890',
            'data_dt': '2019-07-29T06:29:00.123Z',
            'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918'
        }
    }
    expected_sorted_dict_str = json.dumps({
        'data': {
            'private_info': post_permission_request_data['data']['private_info'],
            'transaction': {
                'originator_vasp_code': post_permission_request_data['data']['transaction']['originator_vasp_code'],
                'originator_addrs': post_permission_request_data['data']['transaction']['originator_addrs'],
                'originator_addrs_extra': post_permission_request_data['data']['transaction']['originator_addrs_extra'],
                'beneficiary_vasp_code': post_permission_request_data['data']['transaction']['beneficiary_vasp_code'],
                'beneficiary_addrs': post_permission_request_data['data']['transaction']['beneficiary_addrs'],
                'beneficiary_addrs_extra': post_permission_request_data['data']['transaction']['beneficiary_addrs_extra'],
                'transaction_currency': post_permission_request_data['data']['transaction']['transaction_currency'],
                'amount': post_permission_request_data['data']['transaction']['amount']
            },
            'data_dt': post_permission_request_data['data']['data_dt'],
            'expire_date':post_permission_request_data['data']['expire_date'],
            'signature': post_permission_request_data['data']['signature']
        },
        'callback': {
            'callback_url': post_permission_request_data['callback']['callback_url'],
            'signature': post_permission_request_data['callback']['signature']
        }
    })
    assert json.dumps(sort_post_permission_request_data(post_permission_request_data)) == expected_sorted_dict_str


if __name__ == '__main__':
    test_sort_transaction_id_data()
    test_sort_callback_data()
    test_sort_permission_data()
    test_sort_permission_request_data()
    test_sort_post_transaction_id_data()
    test_sort_post_permission_request_data()
