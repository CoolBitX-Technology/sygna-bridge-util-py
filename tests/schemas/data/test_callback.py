import pytest
from sygna_bridge_util.schemas import get_callback_schema
from jsonschema import validate, ValidationError, draft7_format_checker


def test_get_callback_schema():
    """should raise exception if get_callback_schema result is not expected"""
    __callback_schema = {
        'type': 'object',
        'properties': {
            'callback_url': {
                'type': 'string',
                'format': 'uri'
            }
        },
        'required': [
            'callback_url'
        ],
        'additionalProperties': False
    }
    assert __callback_schema == get_callback_schema()


def test_validate_callback_schema():
    """should raise exception if data is mot match schema"""

    def assert_validate_result(instance: dict, expected_message: str) -> None:
        with pytest.raises(ValidationError) as exception:
            validate(instance=instance, schema=get_callback_schema(),
                     format_checker=draft7_format_checker)
        assert expected_message == str(exception.value.message)

    data = {}
    assert_validate_result(data, "'callback_url' is a required property")

    data['callback_url'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['callback_url']))

    data['callback_url'] = '123456'
    assert_validate_result(data, "'{0}' is not a 'uri'".format(data['callback_url']))

    data['callback_url'] = 'http://google.com'
    try:
        validate(instance=data, schema=get_callback_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


def test_validate_callback_schema_success():
    """should validate success"""
    try:
        fake_data = {
            'callback_url': 'https://google.com'
        }
        validate(instance=fake_data, schema=get_callback_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'callback_url': 'http://google.com'
        }
        validate(instance=fake_data, schema=get_callback_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


if __name__ == '__main__':
    test_get_callback_schema()
    test_validate_callback_schema()
    test_validate_callback_schema_success()
