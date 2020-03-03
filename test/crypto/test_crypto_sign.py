import unittest
from unittest.mock import Mock, patch, call
import json
from ecdsa import util
from ecdsa.curves import SECP256k1
from hashlib import sha256
from crypto import (
    sign_message
)


class CryptoSignTest(unittest.TestCase):
    @patch('ecdsa.keys.SigningKey.from_string')
    def test_sign_message(self, mock_signingkey_from_string):
        fake_data = {'key': 'value'}
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        fake_signature_bytes = bytes([1, 2, 3, 4])
        sign_deterministic = Mock(return_value=fake_signature_bytes)
        mock_signingkey_from_string.return_value = Mock(sign_deterministic=sign_deterministic)

        result = sign_message(fake_data, fake_private_key)
        message_str = json.dumps(fake_data, separators=(',', ':'))
        message_b = message_str.encode(encoding='utf-8')
        private_key_b_obj = bytearray.fromhex(fake_private_key)
        assert mock_signingkey_from_string.call_count == 1
        assert mock_signingkey_from_string.call_args == call(string=private_key_b_obj, curve=SECP256k1)
        assert sign_deterministic.call_count == 1
        assert sign_deterministic.call_args == call(data=message_b,
                                                    hashfunc=sha256,
                                                    sigencode=util.sigencode_string_canonize)
        assert result == fake_signature_bytes.hex()

    def test_sign_message(self):
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': 'REJECTED',
            'expire_date': 4107667801000,
            'reject_code': 'BVRC999',
            'reject_message': 'service_downtime'
        }
        fake_private_key = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
        result = sign_message(fake_data, fake_private_key)
        assert result == '3af437b5091256a28057472a7b944d7085d469e620de2e0121ce977d5be83269587' \
                         'b07730fc2e9dedda2aec89fd5b36bbc25db589aea104262f51e3967aaf619'


if __name__ == '__main__':
    unittest.main()
