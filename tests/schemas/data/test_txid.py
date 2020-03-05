import pytest
from sygna_bridge_util.schemas import get_txid_schema
from jsonschema import validate, ValidationError, draft7_format_checker


def test_get_txid_schema():
    """should raise exception if get_txid_schema result is not expected"""
    __txid_schema = {
        'type': 'object',
        'properties': {
            'transfer_id': {
                'type': 'string',
                'minLength': 64,
                'maxLength': 64
            },
            'txid': {
                'type': 'string',
                'minLength': 1
            }
        },
        'required': [
            'transfer_id',
            'txid'
        ],
        'additionalProperties': False
    }
    assert __txid_schema == get_txid_schema()


def test_validate_txid_schema():
    """should raise exception if data is mot match schema"""

    def assert_validate_result(instance: dict, expected_message: str) -> None:
        with pytest.raises(ValidationError) as exception:
            validate(instance=instance, schema=get_txid_schema(),
                     format_checker=draft7_format_checker)
        assert expected_message == str(exception.value.message)

    data = {}
    assert_validate_result(data, "'transfer_id' is a required property")

    data['transfer_id'] = 123
    assert_validate_result(data, "'txid' is a required property")

    data['txid'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['transfer_id']))

    data['transfer_id'] = '123'
    assert_validate_result(data, "'{0}' is too short".format(data['transfer_id']))

    data['transfer_id'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b1'  # len = 65
    assert_validate_result(data, "'{0}' is too long".format(data['transfer_id']))

    data['transfer_id'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'  # len = 64
    assert_validate_result(data, "{0} is not of type 'string'".format(data['txid']))

    data['txid'] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['txid']))

    data['txid'] = '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
    try:
        validate(instance=data, schema=get_txid_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


def test_validate_txid_schema_success():
    """should validate success"""
    try:
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'txid': '9d5f8e32aa87dd5e787b766990f74cf3a961b4e439a56670b07569c846fe473d'
        }
        validate(instance=fake_data, schema=get_txid_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


if __name__ == '__main__':
    test_get_txid_schema()
    test_validate_txid_schema()
    test_validate_txid_schema_success()
