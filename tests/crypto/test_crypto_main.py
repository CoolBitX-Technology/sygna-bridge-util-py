from .fake_data import FAKE_PRIVATE_KEY, FAKE_PUBLIC_KEY
from sygna_bridge_util.crypto import (
    sygna_encrypt_private_data,
    sygna_decrypt_private_data,
    sign_data,
    sign_permission_request,
    sign_callback,
    sign_permission,
    sign_transaction_id,
    verify_data,
    sign_beneficiary_endpoint_url
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
    encoded_private_data = '0434aeb62180a8481334ce77ad790bb8be10e6c5a3dfde407bf8137538072de181c78f9a8c19638105656' \
                           '3e4b5ce914df55bdf95bff268966cfd4a4837c8ed4b34356ada64fd257d10a662c5fdc4d3aca70cc14ebef' \
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
            'amount': '1.0',
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
    expected_signature = '2602414daa89a80aee10a922f9c7dc22b8abe45922cc6a30c78a06ec4ee365c95' \
                         '01b4c884518cfb9e8aba09633520298848d7a6ff2d1f494f618c4f7beb0f7df'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['originator_addrs_extra'] = {'DT': '001'}
    # signature from javascript util
    expected_signature = '841884521f260d92cb681081f40e4828e82c0086156cf94bdedcbbee2e29936b36a' \
                         '0901ba1486840dc0a3b7ba9d14b1235b26a2751306a7454b8e5a2d00c197f'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['beneficiary_addrs_extra'] = {'DT': '002'}
    # signature from javascript util
    expected_signature = '9d4fd88e33998feec42249264137ac6dad8f06de8ab4c4dbfd1adb11d1dad6a506' \
                         'e0d4f43b6eda5f2ea6988897c30b58e407c92cd4119bd4816764faff1b61c6'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = '2f34684b4f050b1d4ca0404a4a7194cfa71a1a852d25ff369f8578db2d8f20655c0309b' \
                         'cfdb7e3cc034abd9f8e9ea8da7bdf4066275515a229fc89bbcf517d87'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['amount'] = '1'
    # signature from javascript util
    expected_signature = 'cbbc40dd7d6b4a3cd435131c45d65ed7733a9ed9c95ec0c9cca748033ae893105d66de311d6'\
                         'cd6e5e85be9353d42a16da46c974a3af672639f7e52389ed9c620'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_callback():
    fake_data = {
        'callback_url': 'https://api.sygna.io/api/v1.1.0/bridge/'
    }
    # signature from javascript util
    expected_signature = '2cf2aaf91bf0056078542204a97d3462c17586f46b1e4fb63fc418a6c7f8e27f37f' \
                         '61a85a8425774b77466c2f5042352b295aa7d584fcf70bbadaf3ebbaef2bd'
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


def test_sign_beneficiary_endpoint_url():
    fake_data = {
        'beneficiary_endpoint_url': 'https://api.sygna.io/api/v1.1.0/bridge/',
        'vasp_code': 'VASPUSNY1'
    }
    # signature from javascript util
    expected_signature = '72283fb8ba3ceba13bcb29e263fb283eabe4b76c9db114dfad5f9da4ef1d664077e74b1f' \
                         '27133efb7450ef5bd4b72b35f59ee609703a74f6692e9b5ca9c4f8f5'
    result = sign_beneficiary_endpoint_url(fake_data, FAKE_PRIVATE_KEY)
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
    test_sign_beneficiary_endpoint_url()
