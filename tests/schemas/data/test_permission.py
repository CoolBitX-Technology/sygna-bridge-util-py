import pytest
from jsonschema import validate, ValidationError, draft7_format_checker
from sygna_bridge_util.config import PermissionStatus, RejectCode
from sygna_bridge_util.schemas import get_permission_schema


def test_get_permission_schema():
    """should raise exception if get_permission_schema result is not expected"""
    data = {}
    __permission_schema = {
        'type': 'object',
        'properties': {
            'transfer_id': {
                'type': 'string',
                'minLength': 64,
                'maxLength': 64
            },
            'permission_status': {
                'type': 'string',
                'minLength': 1,
                'enum': [status.value for status in PermissionStatus]
            },
            'expire_date': {
                'type': 'number',
                'minimum': 0
            },
            'reject_code': {
                'type': 'string',
                'minLength': 1,
                'enum': [code.value for code in RejectCode]
            },
            'reject_message': {
                'type': 'string',
                'minLength': 1
            }
        },
        'required': [
            'transfer_id',
            'permission_status'
        ],
        'additionalProperties': False
    }

    assert __permission_schema == get_permission_schema(data)

    data['permission_status'] = PermissionStatus.ACCEPTED.value
    assert __permission_schema == get_permission_schema(data)

    # data['permission_status'] = PermissionStatus.REJECTED.value
    # __permission_schema1 = {
    #     'type': 'object',
    #     'properties': {
    #         'transfer_id': {
    #             'type': 'string',
    #             'minLength': 64,
    #             'maxLength': 64
    #         },
    #         'permission_status': {
    #             'type': 'string',
    #             'minLength': 1,
    #             'enum': [status.value for status in PermissionStatus]
    #         },
    #         'expire_date': {
    #             'type': 'number',
    #             'minimum': 0
    #         },
    #         'reject_code': {
    #             'type': 'string',
    #             'minLength': 1,
    #             'enum': [code.value for code in RejectCode]
    #         },
    #         'reject_message': {
    #             'type': 'string',
    #             'minLength': 1
    #         }
    #     },
    #     'required': [
    #         'transfer_id',
    #         'permission_status',
    #         'reject_code'
    #     ],
    #     'additionalProperties': False
    # }
    # assert __permission_schema1 == get_permission_schema(data)
    #
    # data['reject_code'] = RejectCode.BVRC001.value
    # assert __permission_schema1 == get_permission_schema(data)
    #
    # data['reject_code'] = RejectCode.BVRC999.value
    # __permission_schema2 = {
    #     'type': 'object',
    #     'properties': {
    #         'transfer_id': {
    #             'type': 'string',
    #             'minLength': 64,
    #             'maxLength': 64
    #         },
    #         'permission_status': {
    #             'type': 'string',
    #             'minLength': 1,
    #             'enum': [status.value for status in PermissionStatus]
    #         },
    #         'expire_date': {
    #             'type': 'number',
    #             'minimum': 0
    #         },
    #         'reject_code': {
    #             'type': 'string',
    #             'minLength': 1,
    #             'enum': [code.value for code in RejectCode]
    #         },
    #         'reject_message': {
    #             'type': 'string',
    #             'minLength': 1
    #         }
    #     },
    #     'required': [
    #         'transfer_id',
    #         'permission_status',
    #         'reject_code',
    #         'reject_message'
    #     ],
    #     'additionalProperties': False
    # }
    # assert __permission_schema2 == get_permission_schema(data)


def test_validate_permission_schema():
    """should raise exception if data is mot match schema"""

    def assert_validate_result(instance: dict, expected_message: str) -> None:
        with pytest.raises(ValidationError) as exception:
            validate(instance=instance, schema=get_permission_schema(instance),
                     format_checker=draft7_format_checker)
        assert expected_message == str(exception.value.message)

    data = {}
    assert_validate_result(data, "'transfer_id' is a required property")

    data['transfer_id'] = 123
    assert_validate_result(data, "'permission_status' is a required property")

    data['permission_status'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['transfer_id']))

    data['transfer_id'] = '123'
    assert_validate_result(data, "'{0}' is too short".format(data['transfer_id']))

    data['transfer_id'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b1'  # len = 65
    assert_validate_result(data, "'{0}' is too long".format(data['transfer_id']))

    data['transfer_id'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'  # len = 64
    assert_validate_result(data, "{0} is not of type 'string'".format(data['permission_status']))

    data['permission_status'] = '123'
    assert_validate_result(data, "'{0}' is not one of {1}".format(data['permission_status'],
                                                                  [status.value for status in PermissionStatus]))

    data['permission_status'] = PermissionStatus.ACCEPTED.value
    try:
        validate(instance=data, schema=get_permission_schema(data), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')

    data['expire_date'] = '123'
    assert_validate_result(data, "'{0}' is not of type 'number'".format(data['expire_date']))

    data['expire_date'] = -1
    assert_validate_result(data, "{0} is less than the minimum of {1}".format(data['expire_date'], 0))

    data['expire_date'] = 0
    try:
        validate(instance=data, schema=get_permission_schema(data), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')

    data['permission_status'] = PermissionStatus.REJECTED.value
    # assert_validate_result(data, "'reject_code' is a required property")

    data['reject_code'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['reject_code']))

    data['reject_code'] = '123'
    assert_validate_result(data,
                           "'{0}' is not one of {1}".format(data['reject_code'], [code.value for code in RejectCode]))

    data['reject_code'] = RejectCode.BVRC001.value
    try:
        validate(instance=data, schema=get_permission_schema(data), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')

    # data['reject_code'] = RejectCode.BVRC999.value
    # assert_validate_result(data, "'reject_message' is a required property")

    data['reject_message'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['reject_message']))

    data['reject_message'] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['reject_message']))

    data['reject_message'] = '123'
    try:
        validate(instance=data, schema=get_permission_schema(data), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


def test_validate_permission_schema_success():
    """should validate success"""
    try:
        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.ACCEPTED.value
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.ACCEPTED.value,
            'expire_date': 1583146201000
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.REJECTED.value,
            'reject_code': RejectCode.BVRC001.value
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.REJECTED.value,
            'expire_date': 1583146201000,
            'reject_code': RejectCode.BVRC001.value
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.REJECTED.value,
            'reject_code': RejectCode.BVRC999.value,
            'reject_message': 'service_downtime'
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

        fake_data = {
            'transfer_id': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b',
            'permission_status': PermissionStatus.REJECTED.value,
            'expire_date': 1583146201000,
            'reject_code': RejectCode.BVRC999.value,
            'reject_message': 'service_downtime'
        }
        validate(instance=fake_data, schema=get_permission_schema(fake_data), format_checker=draft7_format_checker)

    except ValidationError:
        pytest.fail('Unexpected ValidationError')


if __name__ == '__main__':
    test_get_permission_schema()
    test_validate_permission_schema()
    test_validate_permission_schema_success()
