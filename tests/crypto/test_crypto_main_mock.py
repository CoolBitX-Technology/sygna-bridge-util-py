import unittest
from unittest.mock import patch, call
import pytest
import json
import copy
from sygnabridgeutil.crypto import (
    sygna_encrypt_private_data,
    sygna_decrypt_private_data,
    sign_data,
    sign_permission_request,
    sign_callback,
    sign_permission,
    sign_txid
)
from sygnabridgeutil.crypto import main


class CryptoTest(unittest.TestCase):
    @patch('sygnabridgeutil.crypto.ecies.ecies_encrypt')
    def test_sygna_encrypt_private_data(self, mock_ecies_encrypt):
        fake_data = {'key': 'value'}
        fake_public_key = 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35'
        fake_result = '03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4'
        mock_ecies_encrypt.return_value = fake_result
        result = sygna_encrypt_private_data(fake_data, fake_public_key)
        assert mock_ecies_encrypt.call_count == 1
        assert mock_ecies_encrypt.call_args == call(json.dumps(fake_data), fake_public_key)
        assert result == fake_result

    @patch('sygnabridgeutil.crypto.ecies.ecies_decrypt')
    def test_sygna_decrypt_private_data(self, mock_ecies_decrypt):
        fake_data = 'a939a2c1f47d5d5f1a17148c7ac53b3d16b13adc9adc37e137'
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        fake_result = "{\"key\":\"value\"}"
        mock_ecies_decrypt.return_value = fake_result
        result = sygna_decrypt_private_data(fake_data, fake_private_key)
        assert mock_ecies_decrypt.call_count == 1
        assert mock_ecies_decrypt.call_args == call(fake_data, fake_private_key)
        assert result == json.loads(fake_result)

    @patch('sygnabridgeutil.crypto.sign.sign_message')
    def test_sign_data(self, mock_sign_message):
        fake_data = {'key': 'value'}
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        fake_signature = '4544fc0741c543056d51668198428a45e972bbc5023111e57a7854c'
        mock_sign_message.return_value = fake_signature
        result = sign_data(fake_data, fake_private_key)
        assert mock_sign_message.call_count == 1
        assert mock_sign_message.call_args == call(fake_data, fake_private_key)
        assert result == fake_data
        assert fake_data == {'key': 'value', 'signature': fake_signature}

    @patch.object(main, 'sign_data')
    @patch.object(main, 'validate_private_key')
    @patch.object(main, 'validate_permission_request_schema')
    def test_sign_permission_request(self,
                                     mock_validate_permission_request_schema,
                                     mock_validate_private_key,
                                     mock_sign_data):
        mock_validate_permission_request_schema.side_effect = Exception('validate_permission_request_schema '
                                                                        'raise exception')

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

        with pytest.raises(Exception) as exception:
            sign_permission_request(fake_data, fake_private_key)
        assert 'validate_permission_request_schema raise exception' == str(exception.value)
        assert mock_validate_permission_request_schema.call_count == 1
        assert mock_validate_permission_request_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 0
        assert mock_sign_data.call_count == 0

        mock_validate_permission_request_schema.side_effect = None
        mock_validate_private_key.side_effect = Exception('validate_private_key raise exception')
        with pytest.raises(Exception) as exception:
            sign_permission_request(fake_data, fake_private_key)
        assert 'validate_private_key raise exception' == str(exception.value)
        assert mock_validate_permission_request_schema.call_count == 2
        assert mock_validate_permission_request_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 1
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 0

        mock_validate_private_key.side_effect = None
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4544fc0741c543056d51668198428a45e972bbc5023111e57a7854c'
        mock_sign_data.return_value = fake_result
        result = sign_permission_request(fake_data, fake_private_key)
        assert mock_validate_permission_request_schema.call_count == 3
        assert mock_validate_permission_request_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 2
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 1
        data_to_sign = {
            'private_info': fake_data['private_info'],
            'transaction': fake_data['transaction'],
            'data_dt': fake_data['data_dt']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

        fake_data['expire_date'] = 1583146201000
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'
        mock_sign_data.return_value = fake_result
        result = sign_permission_request(fake_data, fake_private_key)
        assert mock_validate_permission_request_schema.call_count == 4
        assert mock_validate_permission_request_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 3
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 2
        data_to_sign = {
            'private_info': fake_data['private_info'],
            'transaction': fake_data['transaction'],
            'data_dt': fake_data['data_dt'],
            'expire_date': fake_data['expire_date']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

    @patch.object(main, 'sign_data')
    @patch.object(main, 'validate_private_key')
    @patch.object(main, 'validate_callback_schema')
    def test_sign_callback(self, mock_validate_callback_schema, mock_validate_private_key, mock_sign_data):
        mock_validate_callback_schema.side_effect = Exception('validate_callback_schema raise exception')
        fake_data = {
            'callback_url': 'http://google.com'
        }
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        with pytest.raises(Exception) as exception:
            sign_callback(fake_data, fake_private_key)
        assert 'validate_callback_schema raise exception' == str(exception.value)
        assert mock_validate_callback_schema.call_count == 1
        assert mock_validate_callback_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 0
        assert mock_sign_data.call_count == 0

        mock_validate_callback_schema.side_effect = None
        mock_validate_private_key.side_effect = Exception('validate_private_key raise exception')
        with pytest.raises(Exception) as exception:
            sign_callback(fake_data, fake_private_key)
        assert 'validate_private_key raise exception' == str(exception.value)
        assert mock_validate_callback_schema.call_count == 2
        assert mock_validate_callback_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 1
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 0

        mock_validate_private_key.side_effect = None
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4544fc0741c543056d51668198428a45e972bbc5023111e57a7854c'
        mock_sign_data.return_value = fake_result
        result = sign_callback(fake_data, fake_private_key)
        assert mock_validate_callback_schema.call_count == 3
        assert mock_validate_callback_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 2
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 1
        data_to_sign = {
            'callback_url': fake_data['callback_url']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

    @patch.object(main, 'sign_data')
    @patch.object(main, 'validate_private_key')
    @patch.object(main, 'validate_permission_schema')
    def test_sign_permission(self, mock_validate_permission_schema, mock_validate_private_key, mock_sign_data):
        mock_validate_permission_schema.side_effect = Exception('validate_permission_schema raise exception')
        fake_data = {
            'transfer_id': 'a465653a27ea56a7a3ec18dc4b797c7de94e0ff85cf06c227e2ca7ce3247296f',
            'permission_status': 'ACCEPTED'
        }
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        with pytest.raises(Exception) as exception:
            sign_permission(fake_data, fake_private_key)
        assert 'validate_permission_schema raise exception' == str(exception.value)
        assert mock_validate_permission_schema.call_count == 1
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 0
        assert mock_sign_data.call_count == 0

        mock_validate_permission_schema.side_effect = None
        mock_validate_private_key.side_effect = Exception('validate_private_key raise exception')
        with pytest.raises(Exception) as exception:
            sign_permission(fake_data, fake_private_key)
        assert 'validate_private_key raise exception' == str(exception.value)
        assert mock_validate_permission_schema.call_count == 2
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 1
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 0

        mock_validate_private_key.side_effect = None
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4544fc0741c543056d51668198428a45e972bbc5023111e57a7854c'
        mock_sign_data.return_value = fake_result
        result = sign_permission(fake_data, fake_private_key)
        assert mock_validate_permission_schema.call_count == 3
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 2
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 1
        data_to_sign = {
            'transfer_id': fake_data['transfer_id'],
            'permission_status': fake_data['permission_status']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

        fake_data['expire_date'] = 1583146201000
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'
        mock_sign_data.return_value = fake_result
        result = sign_permission(fake_data, fake_private_key)
        assert mock_validate_permission_schema.call_count == 4
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 3
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 2
        data_to_sign = {
            'transfer_id': fake_data['transfer_id'],
            'permission_status': fake_data['permission_status'],
            'expire_date': fake_data['expire_date']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

        fake_data['permission_status'] = 'REJECTED'
        fake_data['reject_code'] = 'BVRC999'
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d'
        mock_sign_data.return_value = fake_result
        result = sign_permission(fake_data, fake_private_key)
        assert mock_validate_permission_schema.call_count == 5
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 4
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 3
        data_to_sign = {
            'transfer_id': fake_data['transfer_id'],
            'permission_status': fake_data['permission_status'],
            'expire_date': fake_data['expire_date'],
            'reject_code': fake_data['reject_code']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

        fake_data['reject_message'] = 'service_downtime'
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = 'e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683'
        mock_sign_data.return_value = fake_result
        result = sign_permission(fake_data, fake_private_key)
        assert mock_validate_permission_schema.call_count == 6
        assert mock_validate_permission_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 5
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 4
        data_to_sign = {
            'transfer_id': fake_data['transfer_id'],
            'permission_status': fake_data['permission_status'],
            'expire_date': fake_data['expire_date'],
            'reject_code': fake_data['reject_code'],
            'reject_message': fake_data['reject_message'],
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result

    @patch.object(main, 'sign_data')
    @patch.object(main, 'validate_private_key')
    @patch.object(main, 'validate_txid_schema')
    def test_sign_txid(self, mock_validate_txid_schema, mock_validate_private_key, mock_sign_data):
        mock_validate_txid_schema.side_effect = Exception('validate_txid_schema raise exception')
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
        }
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        with pytest.raises(Exception) as exception:
            sign_txid(fake_data, fake_private_key)
        assert 'validate_txid_schema raise exception' == str(exception.value)
        assert mock_validate_txid_schema.call_count == 1
        assert mock_validate_txid_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 0
        assert mock_sign_data.call_count == 0

        mock_validate_txid_schema.side_effect = None
        mock_validate_private_key.side_effect = Exception('validate_private_key raise exception')
        with pytest.raises(Exception) as exception:
            sign_txid(fake_data, fake_private_key)
        assert 'validate_private_key raise exception' == str(exception.value)
        assert mock_validate_txid_schema.call_count == 2
        assert mock_validate_txid_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 1
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 0

        mock_validate_private_key.side_effect = None
        fake_result = copy.deepcopy(fake_data)
        fake_result['signature'] = '4544fc0741c543056d51668198428a45e972bbc5023111e57a7854c'
        mock_sign_data.return_value = fake_result
        result = sign_txid(fake_data, fake_private_key)
        assert mock_validate_txid_schema.call_count == 3
        assert mock_validate_txid_schema.call_args == call(fake_data)
        assert mock_validate_private_key.call_count == 2
        assert mock_validate_private_key.call_args == call(fake_private_key)
        assert mock_sign_data.call_count == 1
        data_to_sign = {
            'transfer_id': fake_data['transfer_id'],
            'txid': fake_data['txid']
        }
        assert mock_sign_data.call_args == call(data_to_sign, fake_private_key)
        assert result == fake_result


if __name__ == '__main__':
    unittest.main()
