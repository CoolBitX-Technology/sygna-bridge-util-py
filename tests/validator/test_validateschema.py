import unittest
from unittest.mock import patch, call
from sygna_bridge_util.config import PermissionStatus
from jsonschema import draft7_format_checker
from sygna_bridge_util.validator import validateschema
from sygna_bridge_util.validator import (
    validate_schema,
    validate_permission_schema,
    validate_permission_request_schema,
    validate_transaction_id_schema,
    validate_callback_schema,
    validate_post_permission_schema,
    validate_post_permission_request_schema,
    validate_post_transaction_id_schema
)
from sygna_bridge_util.schemas import (
    get_permission_request_schema,
    get_permission_schema,
    get_txid_schema,
    get_callback_schema,
    get_post_permission_schema,
    get_post_permission_request_schema,
    get_post_txid_schema
)


class ValidateSchemaTest(unittest.TestCase):
    @patch.object(validateschema, 'validate')
    def test_validate_schema(self, mock_validate):
        data = {"key": "value"}
        schema = {"type": "object"}
        validate_schema(data, schema)
        assert mock_validate.call_count == 1
        assert mock_validate.call_args == call(instance=data, schema=schema, format_checker=draft7_format_checker)

    @patch.object(validateschema, 'validate_schema')
    @patch.object(validateschema, 'validate_expire_date')
    def test_validate_permission_schema(self, mock_validate_expire_date, mock_validate_schema):
        data = {"permission_status": PermissionStatus.ACCEPTED.value}
        validate_permission_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_permission_schema(data))
        assert mock_validate_expire_date.call_count == 0

        data['permission_status'] = PermissionStatus.REJECTED.value
        validate_permission_schema(data)
        assert mock_validate_schema.call_count == 2
        assert mock_validate_schema.call_args == call(data, get_permission_schema(data))
        assert mock_validate_expire_date.call_count == 0

        data['expire_date'] = 123
        validate_permission_schema(data)
        assert mock_validate_schema.call_count == 3
        assert mock_validate_schema.call_args == call(data, get_permission_schema(data))
        assert mock_validate_expire_date.call_count == 1
        assert mock_validate_expire_date.call_args == call(123)

    @patch.object(validateschema, 'validate_schema')
    @patch.object(validateschema, 'validate_expire_date')
    def test_validate_permission_request_schema(self, mock_validate_expire_date, mock_validate_schema):
        data = {"key": "value"}
        validate_permission_request_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_permission_request_schema())
        assert mock_validate_expire_date.call_count == 0

        data['expire_date'] = 123
        validate_permission_request_schema(data)
        assert mock_validate_schema.call_count == 2
        assert mock_validate_schema.call_args == call(data, get_permission_request_schema())
        assert mock_validate_expire_date.call_count == 1
        assert mock_validate_expire_date.call_args == call(123)

    @patch.object(validateschema, 'validate_schema')
    def test_validate_txid_schema(self, mock_validate_schema):
        data = {"key": "value"}
        validate_transaction_id_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_txid_schema())

    @patch.object(validateschema, 'validate_schema')
    def test_validate_callback_schema(self, mock_validate_schema):
        data = {"key": "value"}
        validate_callback_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_callback_schema())

    @patch.object(validateschema, 'validate_schema')
    @patch.object(validateschema, 'validate_expire_date')
    def test_validate_post_permission_schema(self, mock_validate_expire_date, mock_validate_schema):
        data = {"permission_status": PermissionStatus.ACCEPTED.value}
        validate_post_permission_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_post_permission_schema(data))
        assert mock_validate_expire_date.call_count == 0

        data['permission_status'] = PermissionStatus.REJECTED.value
        validate_post_permission_schema(data)
        assert mock_validate_schema.call_count == 2
        assert mock_validate_schema.call_args == call(data, get_post_permission_schema(data))
        assert mock_validate_expire_date.call_count == 0

        data['expire_date'] = 123
        validate_post_permission_schema(data)
        assert mock_validate_schema.call_count == 3
        assert mock_validate_schema.call_args == call(data, get_post_permission_schema(data))
        assert mock_validate_expire_date.call_count == 1
        assert mock_validate_expire_date.call_args == call(123)

    @patch.object(validateschema, 'validate_schema')
    @patch.object(validateschema, 'validate_expire_date')
    def test_validate_post_permission_request_schema(self, mock_validate_expire_date, mock_validate_schema):
        data = {
            'data': {
                'private_info': '12345',
                'transaction': {
                    'originator_vasp_code': 'ABCDE',
                    'originator_addrs': [
                        '1234567890'
                    ],
                    'originator_addrs_extra': {'DT': '001'},
                    'beneficiary_vasp_code': 'XYZ12',
                    'beneficiary_addrs': [
                        '0987654321'
                    ],
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature':
                    '12345'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature':
                    '12345'
            }
        }
        validate_post_permission_request_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_post_permission_request_schema())
        assert mock_validate_expire_date.call_count == 0

        data['data']['expire_date'] = 123
        validate_post_permission_request_schema(data)
        assert mock_validate_schema.call_count == 2
        assert mock_validate_schema.call_args == call(data, get_post_permission_request_schema())
        assert mock_validate_expire_date.call_count == 1
        assert mock_validate_expire_date.call_args == call(123)

    @patch.object(validateschema, 'validate_schema')
    def test_validate_post_txid_schema(self, mock_validate_schema):
        data = {"key": "value"}
        validate_post_transaction_id_schema(data)
        assert mock_validate_schema.call_count == 1
        assert mock_validate_schema.call_args == call(data, get_post_txid_schema())


if __name__ == '__main__':
    unittest.main()
