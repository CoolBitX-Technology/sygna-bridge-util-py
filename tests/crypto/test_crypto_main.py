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
            "originator_vasp": {
                "vasp_code": "VASPJPJT4",
                "addrs": [
                    {
                        "address": "bnb1vynn9hamtqg9me7y6frja0rvfva9saprl55gl4",
                        "addr_extra_info": []
                    }
                ]
            },
            "beneficiary_vasp": {
                "vasp_code": "VASPJPJT3",
                "addrs": [
                    {
                        "address": "bnb1hj767k8nlf0jn6p3c3wvl0r0qfwfrvuxrqlxce"
                    }
                ]
            },
            "currency_id": "sygna:0x800002ca.bnb1u9j9hkst6gf09dkdvxlj7puk8c7vh68a0kkmht",
            "amount": "0.1234"
        },
        'data_dt': '2019-07-29T06:29:00.123Z',
        'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
    }
    # signature from javascript util
    expected_signature = '63dedb9a24ec18f2f90fa7b71a42e585b2c4577e86e87a8c906e73cb20dbf8bf3' \
                         'a1bdc447e2566063b460c828a432c31db1342630142a2f3ff5b00d58886fd19'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['originator_vasp']['addrs'][0]['addr_extra_info'].append({'DT': '001'})
    # signature from javascript util
    expected_signature = '5da17f9a81e97279407c033aa1348c85069d4a81708830a7f000066583e8054a1c826100' \
                         'cbfb97b8829471391a40c1333451d2c849012ae231bbcb168a5ce3c8'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['transaction']['beneficiary_vasp']['addrs'][0]['addr_extra_info'] = [{'DT': '002'}]
    # signature from javascript util
    expected_signature = '69e374312c6b6d3b60065c5108a01bec7e0e4dd1d3f4efac620c167d24d5e33c7a84d870' \
                         '2502908567e94490182c6ae49db0f0f3967b4e39baf2692a42ee3d9f'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data['expire_date'] = 4107667801000
    del fake_data['signature']
    # signature from javascript util
    expected_signature = 'bee75e030fc60bd862d1c1c917ce460366a028313a537963205b255bbfd3e8267f76279a' \
                         '27f4635817af063b9131a07ce1d918bb458bc645481c0c14da9b574b'
    result = sign_permission_request(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_callback():
    fake_data = {
        'callback_url': 'https://api.sygna.io/v2/bridge/'
    }
    # signature from javascript util
    expected_signature = '825a820f4e331acc6f53a0b745b7caba139c922131f9356f7b4d914040b9d3fa469764289e8'\
                         '1cf989a5c143aa9f0ae88fc1357ca81584041b09639faab178672'
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
    expected_signature = '7969f5a533d51b49dc6343c4ec045ae9844f534ada712310402e2fa56b55894' \
                         'b1c493e25658b0c1c0afaf6560c2fbd70fa206619ea7896bf79975a844f6e1f67'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    del fake_data['signature']
    fake_data['expire_date'] = 4107667801000
    # signature from javascript util
    expected_signature = '1148b1cc1d65a63218818191d8d7eb87836d0c9b94fbc2c955b0b94a253594a15c35' \
                         '5f940afe1567505fe859e82ac5b560c4e4ebc6b987e591e98477e5619325'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    del fake_data['signature']
    fake_data['permission_status'] = 'REJECTED'
    fake_data['reject_code'] = 'BVRC001'
    # signature from javascript util
    expected_signature = '49f199360bed6391eae898b8bead820cc3fcc636f20cd453bc935dd7e6917c2375414ba' \
                         'b45ea289dba17eaa5ef0bd8d1cb17642557aff6960aaabea89360dfd3'
    result = sign_permission(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    del fake_data['signature']
    fake_data['reject_code'] = 'BVRC999'
    fake_data['reject_message'] = 'service_downtime'
    # signature from javascript util
    expected_signature = '1145b5512ee080c740cb0ec439aba4ba8daf4b51901c9df1684e8398570331fc74c' \
                         'f879a14b253d06322b229854ee04a7393399fcd326d60d2d6be7186d3a0f5'
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
    expected_signature = 'e644fea7fafa0dc7d0cb9e290145582703ae0de675aa6763ceb9f40a9bba66a4' \
                         '19ac5be7a3329b997b38272aeca060d9855ad8f612f0899228e2eb4878e40e1f'
    result = sign_transaction_id(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True


def test_sign_beneficiary_endpoint_url():
    fake_data = {
        'callback_permission_request_url': 'https://api.sygna.io/v2/bridge/permission-request',
        'vasp_code': 'VASPUSNY1'
    }
    # signature from javascript util
    expected_signature = 'f0f80cbf7ae85ab54f49797f99ec4905a83db0ea774cf4c76d07a66620b8b18107e'\
                         '2f34237d7a0ba595d423da5bd88602a075d7e3d8934eedc551aeeccb3d1fd'
    result = sign_beneficiary_endpoint_url(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data = {
        'callback_permission_request_url': 'https://api.sygna.io/v2/bridge/permission-request',
        'vasp_code': 'VASPUSNY1',
        'callback_txid_url': 'https://api.sygna.io/v2/bridge/txid',
    }
    # signature from javascript util
    expected_signature = 'f515b493b609c6c1fb5017ba62aa7f7089bf82a56c259685f7257fdad2bb761717'\
                         '88a41b2cf526e7e85893027e3b6c5d0ff03b10f0a61db25eab6e11991570be'
    result = sign_beneficiary_endpoint_url(fake_data, FAKE_PRIVATE_KEY)
    assert result['signature'] == expected_signature

    is_valid = verify_data(result, FAKE_PUBLIC_KEY)
    assert is_valid is True

    fake_data = {
        'callback_permission_request_url': 'https://api.sygna.io/v2/bridge/permission-request',
        'vasp_code': 'VASPUSNY1',
        'callback_txid_url': 'https://api.sygna.io/v2/bridge/txid',
        'callback_validate_addr_url': 'https://api.sygna.io/v2/bridge/permission-request',
    }
    # signature from javascript util
    expected_signature = 'db7ade00683ad7a0a34b9ebf4352c388d19ead06e88a95785ed388d801424c407'\
                         'f3112aa709eab7d3bb4682df177241d78db14e6c63faccc643ef7fc11f3a4a7'
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
