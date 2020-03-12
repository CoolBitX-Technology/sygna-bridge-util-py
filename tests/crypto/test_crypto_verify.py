import unittest
from unittest.mock import Mock, patch, call
import pytest
import json
from ecdsa.curves import SECP256k1
from hashlib import sha256
import copy
from sygna_bridge_util.crypto import (
    verify_message,
    verify_data
)
from sygna_bridge_util.crypto import verify
from sygna_bridge_util.config import SYGNA_BRIDGE_CENTRAL_PUBKEY
from .fake_data import FAKE_PUBLIC_KEY


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
        fake_signature = 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a3' \
                         '1c2245f6d0e560645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'
        mock_verify = Mock(return_value=True)
        mock_verifyingKey_from_string.return_value = Mock(verify=mock_verify)

        result = verify_message(fake_data, fake_signature, FAKE_PUBLIC_KEY)
        public_key_b_obj = bytearray.fromhex(FAKE_PUBLIC_KEY)
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
        result = verify_message(fake_data, fake_signature, FAKE_PUBLIC_KEY)
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
        fake_signature = 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a3' \
                         '1c2245f6d0e560645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'

        result = verify_message(fake_data, fake_signature, FAKE_PUBLIC_KEY)
        assert result is True

    @patch.object(verify, 'verify_message')
    def test_verify_data_mock(self, mock_verify_message):
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime',
            'signature': 'd4d0aff2a18a499b76dfdbe688ea7f07c16145af81dc8c351df4e008228f75790a31c2245f6d0e5'
                         '60645acde196ab19aa3871dd18fbe23dd22bb6a407efd73c9'
        }
        mock_verify_message.return_value = False
        result = verify_data(fake_data)

        signature = fake_data['signature']
        clone_fake_data = copy.deepcopy(fake_data)
        clone_fake_data['signature'] = ''
        assert mock_verify_message.call_count == 1
        assert mock_verify_message.call_args == call(clone_fake_data, signature, SYGNA_BRIDGE_CENTRAL_PUBKEY)
        assert result is False

        mock_verify_message.return_value = True
        result = verify_data(fake_data, FAKE_PUBLIC_KEY)
        assert mock_verify_message.call_count == 2
        assert mock_verify_message.call_args == call(clone_fake_data, signature, FAKE_PUBLIC_KEY)
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
        result = verify_data(fake_data, FAKE_PUBLIC_KEY)
        assert result is True


if __name__ == '__main__':
    unittest.main()
