import unittest
from unittest.mock import Mock, patch, call
import json
from ecdsa import util
from ecdsa.curves import SECP256k1
from hashlib import sha256
from sygna_bridge_util.crypto import (
    sign_message
)
from .fake_data import FAKE_PRIVATE_KEY


class CryptoSignTest(unittest.TestCase):
    @patch('ecdsa.keys.SigningKey.from_string')
    def test_sign_message(self, mock_signingkey_from_string):
        fake_data = {'key': 'value'}
        fake_signature_bytes = bytes([1, 2, 3, 4])
        sign_deterministic = Mock(return_value=fake_signature_bytes)
        mock_signingkey_from_string.return_value = Mock(sign_deterministic=sign_deterministic)

        result = sign_message(fake_data, FAKE_PRIVATE_KEY)
        message_str = json.dumps(fake_data, separators=(',', ':'))
        message_b = message_str.encode(encoding='utf-8')
        private_key_b_obj = bytearray.fromhex(FAKE_PRIVATE_KEY)
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

        result = sign_message(fake_data, FAKE_PRIVATE_KEY)
        assert result == '9594dab35733bf35501d3a37319c757c0311ce825e6274e54d860798553671b959762' \
                         '2618c4a3c05930a07c471d1910ad927225f4d9b33b864b3a14715f56bad'


if __name__ == '__main__':
    unittest.main()
