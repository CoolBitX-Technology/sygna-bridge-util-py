from sygna_bridge_util.crypto import (
    sygna_encrypt_private_data,
    sygna_decrypt_private_data,
    sign_data,
    sign_permission_request,
    sign_callback,
    sign_permission,
    sign_transaction_id
)


def test_sygna_encrypt_and_decrypt_private_data():
    fake_data = {
        'originator': {
            'name': 'Antoine Griezmann',
            'date_of_birth': '1991-03-21',
        },
        'beneficiary': {
            'name': 'Leo Messi'
        }
    }
    fake_private_key = 'bf76d2680f23f6fc28111afe0179b8704c8e203a5faa5112f8aa52721f78fe6a'
    fake_public_key = '045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d15' \
                      '7483cc5e49c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085'
    encoded_private_data = sygna_encrypt_private_data(fake_data, fake_public_key)
    decoded_private_data = sygna_decrypt_private_data(encoded_private_data, fake_private_key)
    assert decoded_private_data == fake_data


def test_sign_data():
    fake_data = {'key': 'value'}
    fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    # signature from javascript util
    expected_signature = '1248290d768aca063627e76f82a49050cb565918dc4e5b17f40eda2' \
                         '1dcdc12191dffc52c4d63ec861025585a758e06b418bea00f2151305f6d51a5abfdaa06fa'
    result = sign_data(fake_data, fake_private_key)
    assert result['signature'] == expected_signature


def test_sign_permission_request():
    fake_data = {
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
        'transaction': {
            'originator_vasp_code': 'VASPTWTP1',
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'beneficiary_vasp_code': 'VASPTWTP2',
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'transaction_currency': '0x80000000',
            'amount': 1
        },
        'data_dt': '2019-07-29T06:29:00.123Z',
    }
    fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    # signature from javascript util
    expected_signature = 'dafab49e2d2b8ff92002721bbeca435f917add9cdcd57ae941662188696d0bf' \
                         'a7d068b1e0cd755e633252045e8d8a87dda66c8fe4fd67e3f1004eb3610ea4785'
    result = sign_permission_request(fake_data, fake_private_key)
    assert result['signature'] == expected_signature

    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = '1b4103317197df5359a13fd37582920f526a9bb90fcd3fa40f432ff2cb83f7e71' \
                         'b5ac2132ef360e1c3da1aeaf25b1b16f3ec60564a207b25eff17d99f6402f7c'
    result = sign_permission_request(fake_data, fake_private_key)
    assert result['signature'] == expected_signature


def test_sign_callback():
    fake_data = {
        'callback_url': 'https://google.com'
    }
    fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    # signature from javascript util
    expected_signature = '92731a15287f1c4f5e7564c196726d1c8853474e4b490098434e8bb08a2844314' \
                         'a23402514fca1a5c5981f6088f76c7704dd52f5b7bba7f5f60e9d02ac543571'
    result = sign_callback(fake_data, fake_private_key)
    assert result['signature'] == expected_signature


def test_sign_permission():
    fake_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'permission_status': 'ACCEPTED'
    }
    fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    # signature from javascript util
    expected_signature = '634dc1ee1127a94235b3e581f883d6b9f96aefc1b6b800b3dca6fc50de46f581' \
                         '74ff75594f8e997de1dabf8092b39fe37cad3f943f4f25fe9633a02756d167f9'
    result = sign_permission(fake_data, fake_private_key)
    assert result['signature'] == expected_signature

    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = '4b0faa093d6a47085d82f1c79aa3b2e379771b7d8e5ef15b9981a1f6de3160cf' \
                         '63ac15873a90aaa92ef43d9180e525a3ef3c36268242704842b454d7a469cce1'
    result = sign_permission(fake_data, fake_private_key)
    assert result['signature'] == expected_signature

    fake_data['permission_status'] = 'REJECTED'
    fake_data['reject_code'] = 'BVRC001'
    # signature from javascript util
    expected_signature = '079a7f044de2bc70391d3357922fd95aca94732f31fd7c5ec39fc67453d611f91db37' \
                         '1b79fcf016ba67c41ec46ee42805a3d90cd78e24f66de82699eaca1cd7d'
    result = sign_permission(fake_data, fake_private_key)
    assert result['signature'] == expected_signature

    fake_data['reject_code'] = 'BVRC999'
    fake_data['reject_message'] = 'service_downtime'
    # signature from javascript util
    expected_signature = '990f8033decc2c118e0e9348e03651691bc39884e49eddee474516521b916546017a8' \
                         'd00ab8dc6a900c8431aacd4c0fb263ce27edf7a09584da3df9f8ff7a601'
    result = sign_permission(fake_data, fake_private_key)
    assert result['signature'] == expected_signature


def test_sign_transaction_id():
    fake_data = {
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
    }
    fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    # signature from javascript util
    expected_signature = 'a9ee40c9b65589cbce0352809463fb496d47a4b181723c2add0c9a3cad14792a' \
                         '6d714e245b7052b23a7ff532d3a5c2454f48821f2f4503106e9c5d2b03b09554'
    result = sign_transaction_id(fake_data, fake_private_key)
    assert result['signature'] == expected_signature


if __name__ == '__main__':
    test_sygna_encrypt_and_decrypt_private_data()
    test_sign_data()
    test_sign_permission_request()
    test_sign_callback()
    test_sign_permission()
    test_sign_transaction_id()
