from .fake_data import FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY
from sygna_bridge_util.crypto import (
    sygna_encrypt_private_data,
    sygna_decrypt_private_data,
    sign_data,
    sign_permission_request,
    sign_callback,
    sign_permission,
    sign_transaction_id,
    verify_data
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
    encoded_private_data = sygna_encrypt_private_data(fake_data, FAKE_PUBLIC_KEY)
    decoded_private_data = sygna_decrypt_private_data(encoded_private_data, FAKE_PRIVATE_KEY)
    assert decoded_private_data == fake_data

    fake_data = 'qwer'
    encoded_private_data = sygna_encrypt_private_data(fake_data, FAKE_PUBLIC_KEY)
    decoded_private_data = sygna_decrypt_private_data(encoded_private_data, FAKE_PRIVATE_KEY)
    assert decoded_private_data == fake_data

    # encoded qwer by javascript util
    encoded_private_data = '0434aeb62180a8481334ce77ad790bb8be10e6c5a3dfde407bf8137538072de181c78f9a8c19638105656'\
                           '3e4b5ce914df55bdf95bff268966cfd4a4837c8ed4b34356ada64fd257d10a662c5fdc4d3aca70cc14ebef'\
                           'afd9008949f0bd2806314969dbb4ca4'
    decoded_private_data = sygna_decrypt_private_data(encoded_private_data, FAKE_PRIVATE_KEY)
    assert decoded_private_data == fake_data


def test_sign_data():
    fake_data = {'key': 'value'}
    # signature from javascript util
    expected_signature = '9539bbfc24b39696cf30d3d33935ae50aaa1a0ec3f691f06f6cc470933ffab9' \
                         '2572b6c6ecdfb93ef6aa551593a044bd5b720b60f43340db809923eea64473b91'
    result = sign_data(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_permission_request():
    fake_data = {
        'transaction': {
            'amount': 1,
            'originator_addrs': [
                '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
            ],
            'transaction_currency': '0x80000000',
            'originator_vasp_code': 'VASPTWTP1',
            'beneficiary_addrs': [
                '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
            ],
            'beneficiary_vasp_code': 'VASPTWTP2'
        },
        'data_dt': '2019-07-29T06:29:00.123Z',
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
    }
    # signature from javascript util
    expected_signature = 'c7b9c1edc35e17dc0a78858d68786e5bcb26bbc09d02a0e1747e7eeabdc59d4' \
                         'e79c6d1156359a06b1662084d782bd86f4bdc6cc5aa6696f20c5ea8e20fa328e8'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['originator_addrs_extra'] = {'DT': '001'}
    # signature from javascript util
    expected_signature = 'c0ca54c686ca3003dadec247a2cfdd83079826305edd79e3b8ea60fb25a49bd35a'\
                         '63352e186f9b69c48b3cc2f375e7e28899aa2c90e0bb5157005ad1987ed834'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['beneficiary_addrs_extra'] = {'DT': '002'}
    # signature from javascript util
    expected_signature = '8549bd107f05f90febc0dece2966a64c1edd093e1e0268608a5d23ea029045da4034'\
                         '55d764fc3b9663177de9033ac1fb95f9c381f02b26a4f49f0a3c74993256'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = '0b7b524648dec1e0c4c67f741c1922b148a03d31b4b39d76ff0d8a8d55b0d36f492ef51'\
                         'ddd132bf738b082702ce004c957649dfa046c9316219a8e5b0dce07fb'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_callback():
    fake_data = {
        'callback_url': 'https://google.com'
    }
    # signature from javascript util
    expected_signature = 'db6bef6b2201f3b7d42783ba6579758ad8d0e1bad8b2b732d499758e73c185e34' \
                         'e009f84ca68f1927c9c2ffee53bb730871a40faf555d82e28b8a211f25b213b'
    result = sign_callback(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_permission():
    fake_data = {
        'permission_status': 'ACCEPTED',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    # signature from javascript util
    expected_signature = '8500fde0806c6f8c94db848c4096cbc7deee3ee659b6dce3cb3accea8391c81' \
                         '122b46245801669b3da200e4311e8ef4012587be183bc00bed372204899a57595'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = 'e4f0893278051c4b67a0e62fe85249c6a710374a1852aa3c19525193815721e7' \
                         '4212601dc25ef52486d490efe49dd9a3d7a4a7dcaf3d40e995c9baed42bb5b9f'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['permission_status'] = 'REJECTED'
    fake_data['reject_code'] = 'BVRC001'
    # signature from javascript util
    expected_signature = 'bb61d40ea18384536f634bae35c69e62457fd1428e68b253e9f9af46797933ab4' \
                         'd895bcad915497c7722115908e857863bf0bd9591ca0ee0b68bb5caf40f3a20'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['reject_code'] = 'BVRC999'
    fake_data['reject_message'] = 'service_downtime'
    # signature from javascript util
    expected_signature = 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a' \
                         '31c2245f6d0e560645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_transaction_id():
    fake_data = {
        'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d',
        'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
    }
    # signature from javascript util
    expected_signature = '64da6f5f49be9d3103cdbee22df1b41cfac59d8eda7851c3d28c41f9b6a015' \
                         '52519759653fa16e61e0179d19be3acbf7915b6859f653909b6120041cd073eaa1'
    result = sign_transaction_id(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


if __name__ == '__main__':
    test_sygna_encrypt_and_decrypt_private_data()
    test_sign_data()
    test_sign_permission_request()
    test_sign_callback()
    test_sign_permission()
    test_sign_transaction_id()
