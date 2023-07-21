import unittest
from unittest import mock
from unittest.mock import patch, call
import pytest
import json
from sygna_bridge_util.api import main, API

from sygna_bridge_util.config import (
    SYGNA_BRIDGE_CENTRAL_PUBKEY,
    SYGNA_BRIDGE_CENTRAL_PUBKEY_TEST,
    HTTP_TIMEOUT
)

ORIGINATOR_API_KEY = "123456789"
BENEFICIARY_API_KEY = "0987654321"
DOMAIN = "https://api.sygna.io/"


class ApiTest(unittest.TestCase):
    @patch('requests.get')
    def test_get_sb(self, mock_requests):
        """should use correct args to call get_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN + 'v2/bridge/vasp'
        instance.get_sb(url)
        assert mock_requests.call_count == 1
        assert mock_requests.call_args == call(
            url, headers={'x-api-key': ORIGINATOR_API_KEY,'User-Agent': 'util-python/2.0.2'}, timeout=HTTP_TIMEOUT)

    @patch('requests.post')
    def test_post_sb(self, mock_requests):
        """should use correct args to call post_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN + 'v2/bridge/transaction/permission'
        body = {
            'transfer_id': 'ad468f326ebcc2242c32aa6bf7084c44135a068d939e52c08b6d2e86eb9ef725',
            'permission_status': 'ACCEPTED',
            'signature': '309f14db5fe4c33e9ebd770d110a89a93c1c9f68b8e1aac18097c1078ffb5a292f4132501ab1e3bf1f9ee3c3f8a9fd9c3f94ac403a5370eb38a6cdece8d7d1cc'
        }
        instance.post_sb(url, body)
        assert mock_requests.call_count == 1
        assert mock_requests.call_args == call(
            url,
            data=json.dumps(body),
            headers={'Content-Type': 'application/json',
                     'x-api-key': ORIGINATOR_API_KEY,
                     'User-Agent': 'util-python/2.0.2'},
            timeout=HTTP_TIMEOUT)

    @patch.object(API, 'get_sb')
    @mock.patch('sygna_bridge_util.crypto.verify.verify_data')
    def test_get_vasp_list(self, mock_verify, mock_get_sb):
        """ should raise exception if api response is not valid or signature is not valid"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_get_sb.return_value = {'message': 'test exception'}
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_list()
        assert 'Request VASPs failed: {0}'.format('test exception') == str(exception.value)
        assert mock_get_sb.call_count == 1
        assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
        assert mock_verify.call_count == 0

        fake_vasp_list = {
            'vasp_data': [
                {
                    'vasp_code': 'AAAAAAAA798',
                    'vasp_name': 'AAAA',
                    'vasp_pubkey': '123456'
                },
                {
                    'vasp_code': 'ABCDKRZZ111',
                    'vasp_name': 'ASDFGHJKL111111',
                    'vasp_pubkey': '22222222222222222222222'
                }
            ]
        }
        mock_get_sb.return_value = fake_vasp_list
        try:
            vasp_list = instance.get_vasp_list(False)
            assert mock_get_sb.call_count == 2
            assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
            assert mock_verify.call_count == 0
            assert vasp_list == fake_vasp_list['vasp_data']
        except ValueError:
            pytest.fail('Unexpected ValueError')

        mock_verify.return_value = False
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_list(True)
        assert 'get VASP info error: invalid signature.' == str(exception.value)
        assert mock_get_sb.call_count == 3
        assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
        assert mock_verify.call_count == 1
        assert mock_verify.call_args == call(fake_vasp_list, SYGNA_BRIDGE_CENTRAL_PUBKEY_TEST)

        mock_verify.return_value = True
        try:
            vasp_list = instance.get_vasp_list(True)
            assert mock_get_sb.call_count == 4
            assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
            assert mock_verify.call_count == 2
            assert mock_verify.call_args == call(fake_vasp_list, SYGNA_BRIDGE_CENTRAL_PUBKEY_TEST)
            assert vasp_list == fake_vasp_list['vasp_data']
        except ValueError:
            pytest.fail('Unexpected ValueError')

        mock_verify.return_value = True
        try:
            vasp_list = instance.get_vasp_list(True, False)
            assert mock_get_sb.call_count == 5
            assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
            assert mock_verify.call_count == 3
            assert mock_verify.call_args == call(fake_vasp_list, SYGNA_BRIDGE_CENTRAL_PUBKEY_TEST)
            assert vasp_list == fake_vasp_list['vasp_data']
        except ValueError:
            pytest.fail('Unexpected ValueError')

        mock_verify.return_value = True
        try:
            vasp_list = instance.get_vasp_list(True, True)
            assert mock_get_sb.call_count == 6
            assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/vasp')
            assert mock_verify.call_count == 4
            assert mock_verify.call_args == call(fake_vasp_list, SYGNA_BRIDGE_CENTRAL_PUBKEY)
            assert vasp_list == fake_vasp_list['vasp_data']
        except ValueError:
            pytest.fail('Unexpected ValueError')

    @patch.object(API, 'get_vasp_list')
    def test_get_vasp_public_key(self, mock_get_vasp_list):
        """ should raise exception if vasp_code is not exist in api response"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_get_vasp_list.side_effect = ValueError('get_vasp_list raise exception')
        vasp_code = 'VASPJPJT4'
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_public_key(vasp_code)
        assert 'get_vasp_list raise exception' == str(exception.value)
        assert mock_get_vasp_list.call_count == 1
        assert mock_get_vasp_list.call_args == call(True, False)

        mock_get_vasp_list.side_effect = None
        fake_vasp_list = [
            {
                'vasp_code': 'AAAAAAAA798',
                'vasp_name': 'AAAA',
                'vasp_pubkey': '123456'
            },
            {
                'vasp_code': 'ABCDKRZZ111',
                'vasp_name': 'ASDFGHJKL111111',
                'vasp_pubkey': '22222222222222222222222'
            }
        ]

        mock_get_vasp_list.return_value = fake_vasp_list

        vasp_code = 'VASPJPJT4'
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_public_key(vasp_code, False)
        assert 'Invalid vasp_code' == str(exception.value)
        assert mock_get_vasp_list.call_count == 2
        assert mock_get_vasp_list.call_args == call(False, False)

        vasp_code = 'VASPJPJT4'
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_public_key(vasp_code, False, False)
        assert 'Invalid vasp_code' == str(exception.value)
        assert mock_get_vasp_list.call_count == 3
        assert mock_get_vasp_list.call_args == call(False, False)

        vasp_code = 'ABCDKRZZ111'
        try:
            vasp_public_key = instance.get_vasp_public_key(vasp_code, True)
            assert vasp_public_key == fake_vasp_list[1]['vasp_pubkey']
            assert mock_get_vasp_list.call_count == 4
            assert mock_get_vasp_list.call_args == call(True, False)
        except ValueError:
            pytest.fail('Unexpected ValueError')

        vasp_code = 'ABCDKRZZ111'
        try:
            vasp_public_key = instance.get_vasp_public_key(vasp_code, True, True)
            assert vasp_public_key == fake_vasp_list[1]['vasp_pubkey']
            assert mock_get_vasp_list.call_count == 5
            assert mock_get_vasp_list.call_args == call(True, True)
        except ValueError:
            pytest.fail('Unexpected ValueError')

    @patch.object(API, 'get_sb')
    def test_get_status(self, mock_get_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        transfer_id = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        fake_vasp_status = {
            'transferData': {
                'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
                'private_info': '09876',
                'transaction': {
                    "originator_vasp": {
                        "vasp_code": "VASPJPJT4",
                        "addrs": [
                            {
                                "address": "bnb1vynn9hamtqg9me7y6frja0rvfva9saprl55gl4",
                                "addr_extra_info": [
                                    {
                                        "memo_text": "634346542"
                                    }
                                ]
                            }
                        ]
                    },
                    "beneficiary_vasp": {
                        "vasp_code": "VASPJPJT3",
                        "addrs": [
                            {
                                "address": "bnb1hj767k8nlf0jn6p3c3wvl0r0qfwfrvuxrqlxce",
                                "addr_extra_info": [
                                    {
                                        "memo_text": "Idzl1532434853"
                                    }
                                ]
                            }
                        ]
                    },
                    "currency_id": "sygna:0x800002ca.bnb1u9j9hkst6gf09dkdvxlj7puk8c7vh68a0kkmht",
                    "amount": "0.1234"
                },
                'data_dt': '2019-08-06T13:24:15.425Z',
                'permission_request_data_signature': '12345',
                'permission_signature': '12345',
                'txid': '12345',
                'txid_signature': '12345',
                'created_at': '2019-08-06T13:24:15.425Z',
                'transfer_to_originator_time': '2020-02-14T08:51:53.742Z'
            },
            'signature': '12345'
        }
        mock_get_sb.return_value = fake_vasp_status
        vasp_status = instance.get_status(transfer_id)
        assert vasp_status == fake_vasp_status
        assert mock_get_sb.call_count == 1
        assert mock_get_sb.call_args == call(
            DOMAIN + 'v2/bridge/transaction/status?transfer_id=' + transfer_id)

    @patch.object(API, 'post_sb')
    def test_post_permission(self, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        post_permission_data = {
            'expire_date': 0,
            'signature': '123456789',
            'transfer_id': '12345',
            'permission_status': 'ACCEPTED',
            'reject_code': 'BVRC001',
            'reject_message': 'unsupported_currency'
        }

        fake_post_permission_response = {"status": "OK"}
        mock_post_sb.return_value = fake_post_permission_response
        response = instance.post_permission(post_permission_data)
        assert response == fake_post_permission_response
        assert mock_post_sb.call_count == 1
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/permission',
                                              post_permission_data)

        post_permission_data['permission_status'] = 'REJECTED'
        response = instance.post_permission(post_permission_data)
        assert response == fake_post_permission_response
        assert mock_post_sb.call_count == 2
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/permission',
                                              post_permission_data)

    @patch.object(API, 'post_sb')
    def test_post_permission_request(self, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        post_permission_request_data = {
            'callback': {
                'signature': '12345',
                'callback_url': 'https://api.sygna.io/v2/bridge/'
            },
            'data': {
                'data_dt': '2019-07-29T06:29:00.123Z',
                'expire_date': 1582255065000,
                'transaction': {
                    "originator_vasp": {
                        "vasp_code": "VASPJPJT4",
                        "addrs": [
                            {
                                "address": "bnb1vynn9hamtqg9me7y6frja0rvfva9saprl55gl4",
                                "addr_extra_info": [
                                    {
                                        "memo_text": "634346542"
                                    }
                                ]
                            }
                        ]
                    },
                    "beneficiary_vasp": {
                        "vasp_code": "VASPJPJT3",
                        "addrs": [
                            {
                                "address": "bnb1hj767k8nlf0jn6p3c3wvl0r0qfwfrvuxrqlxce",
                                "addr_extra_info": [
                                    {
                                        "memo_text": "Idzl1532434853"
                                    }
                                ]
                            }
                        ]
                    },
                    "currency_id": "sygna:0x800002ca.bnb1u9j9hkst6gf09dkdvxlj7puk8c7vh68a0kkmht",
                    "amount": "0.1234"
                },
                'signature': '12345',
                'private_info': '12345',
            }
        }
        fake_post_permission_request_response = {"transfer_id": "abcdefghijk"}
        mock_post_sb.return_value = fake_post_permission_request_response
        response = instance.post_permission_request(post_permission_request_data)
        assert response == fake_post_permission_request_response
        assert mock_post_sb.call_count == 1
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/permission-request',
                                              post_permission_request_data)

    @patch.object(API, 'post_sb')
    def test_post_transaction_id(self, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        post_transaction_id_data = {
            'txid': '123',
            'signature': '1234567890',
            'transfer_id': 'ad468f326ebcc2242c32aa6bf7084c44135a068d939e52c08b6d2e86eb9ef725',
        }

        fake_post_transaction_id_response = {"status": "ok"}
        mock_post_sb.return_value = fake_post_transaction_id_response
        response = instance.post_transaction_id(post_transaction_id_data)
        assert response == fake_post_transaction_id_response
        assert mock_post_sb.call_count == 1
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/txid',
                                              post_transaction_id_data)

    @patch.object(API, 'post_sb')
    def test_post_beneficiary_endpoint_url(self, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        post_beneficiary_endpoint_url_data = {
            'signature': 'f947d28d3aba504acd87d65be80f054497f1ebf919a2955343bde0390262c04352f1'
                         'ce8d06fdb7ba7ba43817a9cca623cbd1cb5758bf877a18d28b2c9b05b9af',
            'callback_permission_request_url': 'https://api.sygna.io/v2/bridge/permission-request',
            'vasp_code': 'VASPUSNY1'
        }
        fake_post_beneficiary_endpoint_url_response = {"status": "ok"}
        mock_post_sb.return_value = fake_post_beneficiary_endpoint_url_response
        response = instance.post_beneficiary_endpoint_url(post_beneficiary_endpoint_url_data)
        assert response == fake_post_beneficiary_endpoint_url_response
        assert mock_post_sb.call_count == 1
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/vasp/beneficiary-endpoint-url',
                                              post_beneficiary_endpoint_url_data)

        post_beneficiary_endpoint_url_data = {
            'signature': 'f947d28d3aba504acd87d65be80f054497f1ebf919a2955343bde0390262c04352f1'
                         'ce8d06fdb7ba7ba43817a9cca623cbd1cb5758bf877a18d28b2c9b05b9af',
            'callback_permission_request_url': 'https://api.sygna.io/v2/bridge/permission-request',
            'vasp_code': 'VASPUSNY1',
            'callback_txid_url': 'https://api.sygna.io/v2/bridge/txid',
        }
        response = instance.post_beneficiary_endpoint_url(post_beneficiary_endpoint_url_data)
        assert response == fake_post_beneficiary_endpoint_url_response
        assert mock_post_sb.call_count == 2
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/vasp/beneficiary-endpoint-url',
                                              post_beneficiary_endpoint_url_data)

        post_beneficiary_endpoint_url_data = {
            'signature': 'f947d28d3aba504acd87d65be80f054497f1ebf919a2955343bde0390262c04352f1'
                         'ce8d06fdb7ba7ba43817a9cca623cbd1cb5758bf877a18d28b2c9b05b9af',
            'vasp_code': 'VASPUSNY1',
            'callback_txid_url': 'https://api.sygna.io/v2/bridge/txid',
        }
        response = instance.post_beneficiary_endpoint_url(post_beneficiary_endpoint_url_data)
        assert response == fake_post_beneficiary_endpoint_url_response
        assert mock_post_sb.call_count == 3
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/vasp/beneficiary-endpoint-url',
                                              post_beneficiary_endpoint_url_data)

    @patch.object(API, 'post_sb')
    def test_post_retry(self, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        post_retry_data = {
            'vasp_code': 'VASPUSNY1'
        }
        fake_post_retry_response = {"retryItems": 1}
        mock_post_sb.return_value = fake_post_retry_response
        response = instance.post_retry(post_retry_data)
        assert response == fake_post_retry_response
        assert mock_post_sb.call_count == 1
        assert mock_post_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/retry',
                                              post_retry_data)

    @patch.object(API, 'get_sb')
    def test_get_currencies(self, mock_get_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        currency_id = 'sygna:0x80000090'
        currency_name = 'XRP'
        currency_symbol = 'XRP'

        fake_get_currencies_response = {
            "supported_coins": [
                {
                    "currency_id": "sygna:0x80000090",
                    "currency_name": "XRP",
                    "currency_symbol": "XRP",
                    "is_active": True,
                    "addr_extra_info": [
                        "tag"
                    ]
                }
            ]
        }

        mock_get_sb.return_value = fake_get_currencies_response
        response = instance.get_currencies()
        assert response == fake_get_currencies_response
        assert mock_get_sb.call_count == 1
        assert mock_get_sb.call_args == call(DOMAIN + 'v2/bridge/transaction/currencies')

        instance.get_currencies({'currency_id': currency_id})
        assert mock_get_sb.call_count == 2
        assert mock_get_sb.call_args == call(DOMAIN + f'v2/bridge/transaction/currencies?currency_id={currency_id}')

        instance.get_currencies({'currency_symbol': currency_symbol, 'currency_name': currency_name})
        assert mock_get_sb.call_count == 3
        assert mock_get_sb.call_args == call(DOMAIN + f'v2/bridge/transaction/currencies?'
                                                      f'currency_symbol={currency_symbol}'
                                                      f'&currency_name={currency_name}')


if __name__ == '__main__':
    unittest.main()
