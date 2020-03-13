import unittest
from unittest import mock
from unittest.mock import patch, call
import pytest
import json
from sygna_bridge_util.api import main, API
from sygna_bridge_util.utils import (
    sort_post_permission_data,
    sort_post_permission_request_data,
    sort_post_transaction_id_data
)
from jsonschema import ValidationError

from sygna_bridge_util.config import SYGNA_BRIDGE_CENTRAL_PUBKEY, HTTP_TIMEOUT

ORIGINATOR_API_KEY = "123456789"
BENEFICIARY_API_KEY = "0987654321"
DOMAIN = "http://google.com"


class ApiTest(unittest.TestCase):
    @patch('requests.get')
    def test_get_sb(self, mock_requests):
        """should use correct args to call get_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN + 'api/v1/bridge/vasp'
        instance.get_sb(url)
        assert mock_requests.call_count == 1
        assert mock_requests.call_args == call(
            url, headers={'api_key': ORIGINATOR_API_KEY}, timeout=HTTP_TIMEOUT)

    @patch('requests.post')
    def test_post_sb(self, mock_requests):
        """should use correct args to call post_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN + 'api/v1/bridge/transaction/permission'
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
                     'api_key': ORIGINATOR_API_KEY},
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
        assert mock_get_sb.call_args == call(DOMAIN + 'api/v1/bridge/vasp')
        assert mock_verify.call_count == 0

        fake_vasp_list = {
            'vasp_data': [
                {
                    'vasp_code': 'AAAAAAAA798',
                    'vasp_name': 'AAAA',
                    'is_sb_need_static': False,
                    'vasp_pubkey': '123456'
                },
                {
                    'vasp_code': 'ABCDKRZZ111',
                    'vasp_name': 'ASDFGHJKL111111',
                    'is_sb_need_static': True,
                    'vasp_pubkey': '22222222222222222222222'
                }
            ]
        }
        mock_get_sb.return_value = fake_vasp_list
        try:
            vasp_list = instance.get_vasp_list(False)
            assert mock_get_sb.call_count == 2
            assert mock_get_sb.call_args == call(DOMAIN + 'api/v1/bridge/vasp')
            assert mock_verify.call_count == 0
            assert vasp_list == fake_vasp_list['vasp_data']
        except ValueError:
            pytest.fail('Unexpected ValueError')

        mock_verify.return_value = False
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_list(True)
        assert 'get VASP info error: invalid signature.' == str(exception.value)
        assert mock_get_sb.call_count == 3
        assert mock_get_sb.call_args == call(DOMAIN + 'api/v1/bridge/vasp')
        assert mock_verify.call_count == 1
        assert mock_verify.call_args == call(fake_vasp_list, SYGNA_BRIDGE_CENTRAL_PUBKEY)

        mock_verify.return_value = True
        try:
            vasp_list = instance.get_vasp_list(True)
            assert mock_get_sb.call_count == 4
            assert mock_get_sb.call_args == call(DOMAIN + 'api/v1/bridge/vasp')
            assert mock_verify.call_count == 2
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
        assert mock_get_vasp_list.call_args == call(True)

        mock_get_vasp_list.side_effect = None
        fake_vasp_list = [
            {
                'vasp_code': 'AAAAAAAA798',
                'vasp_name': 'AAAA',
                'is_sb_need_static': False,
                'vasp_pubkey': '123456'
            },
            {
                'vasp_code': 'ABCDKRZZ111',
                'vasp_name': 'ASDFGHJKL111111',
                'is_sb_need_static': True,
                'vasp_pubkey': '22222222222222222222222'
            }
        ]

        mock_get_vasp_list.return_value = fake_vasp_list

        vasp_code = 'VASPJPJT4'
        with pytest.raises(ValueError) as exception:
            instance.get_vasp_public_key(vasp_code, False)
        assert 'Invalid vasp_code' == str(exception.value)
        assert mock_get_vasp_list.call_count == 2
        assert mock_get_vasp_list.call_args == call(False)

        vasp_code = 'ABCDKRZZ111'
        try:
            vasp_public_key = instance.get_vasp_public_key(vasp_code, True)
            assert vasp_public_key == fake_vasp_list[1]['vasp_pubkey']
            assert mock_get_vasp_list.call_count == 3
            assert mock_get_vasp_list.call_args == call(True)
        except ValueError:
            pytest.fail('Unexpected ValueError')

    @patch.object(API, 'get_sb')
    @patch.object(main, 'validate_transfer_id')
    def test_get_status(self, mock_validate_transfer_id, mock_get_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_validate_transfer_id.side_effect = ValidationError('validate_transfer_id raise exception')
        transfer_id = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        with pytest.raises(ValidationError) as exception:
            instance.get_status(transfer_id)
        assert 'validate_transfer_id raise exception' == str(exception.value)
        assert mock_validate_transfer_id.call_count == 1
        assert mock_validate_transfer_id.call_args == call(transfer_id)

        mock_validate_transfer_id.side_effect = None
        fake_vasp_status = {
            'transferData': {
                'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
                'private_info': '09876',
                'transaction': {
                    'originator_vasp_code': 'ABCDE',
                    'originator_addrs': [
                        '0987654321'
                    ],
                    'beneficiary_vasp_code': 'XYZ12',
                    'beneficiary_addrs': [
                        '1234567890'
                    ],
                    'transaction_currency': '0x8003c301',
                    'amount': 12345
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
        try:
            vasp_status = instance.get_status(transfer_id)
            assert vasp_status == fake_vasp_status
            assert mock_validate_transfer_id.call_count == 2
            assert mock_validate_transfer_id.call_args == call(transfer_id)
            assert mock_get_sb.call_count == 1
            assert mock_get_sb.call_args == call(DOMAIN + 'api/v1/bridge/transaction/status?transfer_id=' + transfer_id)
        except ValidationError:
            pytest.fail('Unexpected ValidationError')

    @patch.object(API, 'post_sb')
    @patch.object(main, 'validate_post_permission_schema')
    def test_post_permission(self, mock_validate_post_permission_schema, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_validate_post_permission_schema.side_effect = ValidationError(
            'validate_post_permission_schema raise exception')
        post_permission_data = {
            'expire_date': 0,
            'signature': '123456789',
            'transfer_id': '12345',
            'permission_status': 'ACCEPTED',
            'reject_code': 'BVRC001',
            'reject_message': 'unsupported_currency'
        }
        with pytest.raises(ValidationError) as exception:
            instance.post_permission(post_permission_data)
        assert 'validate_post_permission_schema raise exception' == str(exception.value)
        assert mock_validate_post_permission_schema.call_count == 1
        assert mock_validate_post_permission_schema.call_args == call(post_permission_data)

        mock_validate_post_permission_schema.side_effect = None
        fake_post_permission_response = {"status": "OK"}
        mock_post_sb.return_value = fake_post_permission_response
        sorted_post_permission_data = sort_post_permission_data(post_permission_data)
        try:
            response = instance.post_permission(post_permission_data)
            assert response == fake_post_permission_response
            assert mock_validate_post_permission_schema.call_count == 2
            assert mock_validate_post_permission_schema.call_args == call(post_permission_data)
            assert mock_post_sb.call_count == 1
            assert mock_post_sb.call_args == call(DOMAIN + 'api/v1/bridge/transaction/permission',
                                                  sorted_post_permission_data)
        except ValidationError:
            pytest.fail('Unexpected ValidationError')

        post_permission_data['permission_status'] = 'REJECTED'
        sorted_post_permission_data = sort_post_permission_data(post_permission_data)
        try:
            response = instance.post_permission(post_permission_data)
            assert response == fake_post_permission_response
            assert mock_validate_post_permission_schema.call_count == 3
            assert mock_validate_post_permission_schema.call_args == call(post_permission_data)
            assert mock_post_sb.call_count == 2
            assert mock_post_sb.call_args == call(DOMAIN + 'api/v1/bridge/transaction/permission',
                                                  sorted_post_permission_data)
        except ValidationError:
            pytest.fail('Unexpected ValidationError')

    @patch.object(API, 'post_sb')
    @patch.object(main, 'validate_post_permission_request_schema')
    def test_post_permission_request(self, mock_validate_post_permission_request_schema, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_validate_post_permission_request_schema.side_effect = ValidationError(
            'validate_post_permission_request_schema raise exception')

        post_permission_request_data = {
            'callback': {
                'signature': '12345',
                'callback_url': 'http://google.com'
            },
            'data': {
                'data_dt': '2019-07-29T06:29:00.123Z',
                'expire_date': 1582255065000,
                'transaction': {
                    'originator_addrs_extra': {'DT': '001'},
                    'originator_vasp_code': 'ABCDE',
                    'beneficiary_vasp_code': 'XYZ12',
                    'beneficiary_addrs': [
                        '0987654321'
                    ],
                    'amount': 1,
                    'originator_addrs': [
                        '1234567890'
                    ],
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                },
                'signature':'12345',
                'private_info': '12345',
            }
        }
        with pytest.raises(ValidationError) as exception:
            instance.post_permission_request(post_permission_request_data)
        assert 'validate_post_permission_request_schema raise exception' == str(exception.value)
        assert mock_validate_post_permission_request_schema.call_count == 1
        assert mock_validate_post_permission_request_schema.call_args == call(post_permission_request_data)

        mock_validate_post_permission_request_schema.side_effect = None
        fake_post_permission_request_response = {"transfer_id": "abcdefghijk"}
        mock_post_sb.return_value = fake_post_permission_request_response
        sorted_post_permission_request_data = sort_post_permission_request_data(post_permission_request_data)
        try:
            response = instance.post_permission_request(post_permission_request_data)
            assert response == fake_post_permission_request_response
            assert mock_validate_post_permission_request_schema.call_count == 2
            assert mock_validate_post_permission_request_schema.call_args == call(post_permission_request_data)
            assert mock_post_sb.call_count == 1
            assert mock_post_sb.call_args == call(DOMAIN + 'api/v1/bridge/transaction/permission-request',
                                                  sorted_post_permission_request_data)
        except ValidationError:
            pytest.fail('Unexpected ValidationError')

    @patch.object(API, 'post_sb')
    @patch.object(main, 'validate_post_transaction_id_schema')
    def test_post_transaction_id(self, mock_validate_post_transaction_id_schema, mock_post_sb):
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        mock_validate_post_transaction_id_schema.side_effect = ValidationError(
            'validate_post_txid_schema raise exception')

        post_transaction_id_data = {
            'txid': '123',
            'signature': '1234567890',
            'transfer_id': 'ad468f326ebcc2242c32aa6bf7084c44135a068d939e52c08b6d2e86eb9ef725',
        }
        with pytest.raises(ValidationError) as exception:
            instance.post_transaction_id(post_transaction_id_data)
        assert 'validate_post_txid_schema raise exception' == str(exception.value)
        assert mock_validate_post_transaction_id_schema.call_count == 1
        assert mock_validate_post_transaction_id_schema.call_args == call(post_transaction_id_data)

        mock_validate_post_transaction_id_schema.side_effect = None
        fake_post_transaction_id_response = {"status": "ok"}
        mock_post_sb.return_value = fake_post_transaction_id_response
        sorted_post_transaction_id_data = sort_post_transaction_id_data(post_transaction_id_data)
        try:
            response = instance.post_transaction_id(post_transaction_id_data)
            assert response == fake_post_transaction_id_response
            assert mock_validate_post_transaction_id_schema.call_count == 2
            assert mock_validate_post_transaction_id_schema.call_args == call(post_transaction_id_data)
            assert mock_post_sb.call_count == 1
            assert mock_post_sb.call_args == call(DOMAIN + 'api/v1/bridge/transaction/txid',
                                                  sorted_post_transaction_id_data)
        except ValidationError:
            pytest.fail('Unexpected ValidationError')


if __name__ == '__main__':
    unittest.main()
