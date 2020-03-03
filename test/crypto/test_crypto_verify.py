import unittest
from unittest.mock import Mock, patch, call
import pytest
import json
from ecdsa.curves import SECP256k1
from hashlib import sha256
import copy
from crypto import (
    verify_message,
    verify_data
)
from crypto import verify
from config import SYGNA_BRIDGE_CENTRAL_PUBKEY


class CryptoVerifyTest(unittest.TestCase):
    @patch('ecdsa.keys.VerifyingKey.from_string')
    def test_verify_message_mock(self, mock_verifyingKey_from_string):
        with pytest.raises(TypeError) as exception:
            verify_message(123, 'fake_signature', 'fake_public_key')
        assert 'message should be dict or str' == str(exception.value)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime'
        }
        fake_public_key = '045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d157483cc5e49' \
                          'c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085'
        fake_signature = '9594dab35733bf35501d3a37319c757c0311ce825e6274e54d860798553671b9597622618c4a3c' \
                         '05930a07c471d1910ad927225f4d9b33b864b3a14715f56bad'
        mock_verify = Mock(return_value=True)
        mock_verifyingKey_from_string.return_value = Mock(verify=mock_verify)

        result = verify_message(fake_data, fake_signature, fake_public_key)
        public_key_b_obj = bytearray.fromhex(fake_public_key)
        signature_b_obj = bytearray.fromhex(fake_signature)
        message_b = json.dumps(fake_data, separators=(',', ':')).encode('utf-8')
        assert mock_verifyingKey_from_string.call_count == 1
        assert mock_verifyingKey_from_string.call_args == call(string=public_key_b_obj, curve=SECP256k1)
        assert mock_verify.call_count == 1
        assert mock_verify.call_args == call(signature=signature_b_obj,
                                             data=message_b,
                                             hashfunc=sha256)
        assert result is True

        fake_data_str = json.dumps(fake_data, separators=(',', ':'))
        result = verify_message(fake_data, fake_signature, fake_public_key)
        message_b = fake_data_str.encode('utf-8')
        assert mock_verifyingKey_from_string.call_count == 2
        assert mock_verifyingKey_from_string.call_args == call(string=public_key_b_obj, curve=SECP256k1)
        assert mock_verify.call_count == 2
        assert mock_verify.call_args == call(signature=signature_b_obj,
                                             data=message_b,
                                             hashfunc=sha256)
        assert result is True

    def test_verify_message(self):
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime',
            'signature': ''
        }
        fake_public_key = '045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d157483cc5e49' \
                          'c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085'
        fake_signature = 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a31c2245f6d0' \
                         'e560645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'

        result = verify_message(fake_data, fake_signature, fake_public_key)
        assert result is True

    @patch.object(verify, 'verify_message')
    def test_verify_data_mock(self, mock_verify_message):
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime',
            'signature': '9594dab35733bf35501d3a37319c757c0311ce825e6274e54d860798553671b9597622618c4a3c'
                         '05930a07c471d1910ad927225f4d9b33b864b3a14715f56bad'
        }
        fake_public_key = '045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d157483cc5e49' \
                          'c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085'
        mock_verify_message.return_value = False
        result = verify_data(fake_data)

        signature = fake_data['signature']
        clone_fake_data = copy.deepcopy(fake_data)
        clone_fake_data['signature'] = ''
        assert mock_verify_message.call_count == 1
        assert mock_verify_message.call_args == call(clone_fake_data, signature, SYGNA_BRIDGE_CENTRAL_PUBKEY)
        assert result is False

        mock_verify_message.return_value = True
        result = verify_data(fake_data, fake_public_key)
        assert mock_verify_message.call_count == 2
        assert mock_verify_message.call_args == call(clone_fake_data, signature, fake_public_key)
        assert result is True

    def test_verify_data(self):
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime',
            'signature': 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a31c2245f6d0e5'
                         '60645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'
        }
        fake_public_key = '045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d157483cc5e49' \
                          'c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085'
        result = verify_data(fake_data, fake_public_key)
        assert result is True


if __name__ == '__main__':
    unittest.main()
