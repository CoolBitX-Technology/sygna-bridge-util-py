import pytest
from jsonschema import validate, ValidationError, draft7_format_checker
from sygna_bridge_util.schemas import get_post_permission_request_schema


def test_get_post_permission_request_schema():
    """should raise exception if get_post_permission_request_schema result is not expected"""
    __post_permission_request_schema = {
        'type': 'object',
        'properties': {
            'data': {
                'type': 'object',
                'properties': {
                    'private_info': {
                        'type': 'string',
                        'minLength': 1
                    },
                    'transaction': {
                        'type': 'object',
                        'properties': {
                            'originator_vasp_code': {
                                'type': 'string',
                                'minLength': 1
                            },
                            'originator_addrs': {
                                'type': 'array',
                                'minItems': 1,
                                'items': [
                                    {
                                        'type': 'string',
                                        'minLength': 1
                                    }
                                ]
                            },
                            'originator_addrs_extra': {
                                'type': 'object',
                                'minProperties': 1
                            },
                            'beneficiary_vasp_code': {
                                'type': 'string',
                                'minLength': 1
                            },
                            'beneficiary_addrs': {
                                'type': 'array',
                                'minItems': 1,
                                'items': [
                                    {
                                        'type': 'string',
                                        'minLength': 1
                                    }
                                ]
                            },
                            'beneficiary_addrs_extra': {
                                'type': 'object',
                                'minProperties': 1
                            },
                            'transaction_currency': {
                                'type': 'string',
                                'minLength': 1
                            },
                            'amount': {
                                'type': 'number',
                                'exclusiveMinimum': 0
                            }
                        },
                        'required': [
                            'originator_vasp_code',
                            'originator_addrs',
                            'beneficiary_vasp_code',
                            'beneficiary_addrs',
                            'transaction_currency',
                            'amount'
                        ],
                        'additionalProperties': False
                    },
                    'data_dt': {
                        'format': 'date-time'
                    },
                    'signature': {
                        'type': 'string',
                        'minLength': 128,
                        'maxLength': 128,
                        'pattern': '^[0123456789A-Fa-f]+$'
                    },
                    'expire_date': {
                        'type': 'number',
                        'minimum': 0
                    }
                },
                'required': [
                    'private_info',
                    'transaction',
                    'data_dt',
                    'signature'
                ],
                'additionalProperties': False
            },
            'callback': {
                'type': 'object',
                'properties': {
                    'callback_url': {
                        'type': 'string',
                        'format': 'uri'
                    },
                    'signature': {
                        'type': 'string',
                        'minLength': 128,
                        'maxLength': 128,
                        'pattern': '^[0123456789A-Fa-f]+$'
                    }
                },
                'required': [
                    'callback_url',
                    'signature'
                ],
                'additionalProperties': False
            }
        },
        'required': [
            'data',
            'callback'
        ],
        'additionalProperties': False
    }
    assert __post_permission_request_schema == get_post_permission_request_schema()


def test_validate_post_permission_request_schema():
    """should raise exception if data is mot match schema"""

    def assert_validate_result(instance: dict, expected_message: str) -> None:
        with pytest.raises(ValidationError) as exception:
            validate(instance=instance, schema=get_post_permission_request_schema(),
                     format_checker=draft7_format_checker)
        assert expected_message == str(exception.value.message)

    data = {}
    assert_validate_result(data, "'data' is a required property")

    data['data'] = '456'
    assert_validate_result(data, "'callback' is a required property")

    data['callback'] = '123'
    assert_validate_result(data, "'{0}' is not of type 'object'".format(data['data']))

    data['data'] = {}
    assert_validate_result(data, "'private_info' is a required property")

    data['data']["private_info"] = 111
    assert_validate_result(data, "'transaction' is a required property")

    data['data']["transaction"] = 222
    assert_validate_result(data, "'data_dt' is a required property")

    data['data']["data_dt"] = '333'
    assert_validate_result(data, "'signature' is a required property")

    data['data']["signature"] = 123
    assert_validate_result(data, "'{0}' is not of type 'object'".format(data['callback']))

    data['callback'] = {}
    assert_validate_result(data, "'callback_url' is a required property")

    data['callback']['callback_url'] = 123
    assert_validate_result(data, "'signature' is a required property")

    data['callback']['signature'] = 123
    assert_validate_result(data, "{0} is not of type 'string'".format(data['data']['private_info']))

    data['data']["private_info"] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['data']['private_info']))

    data['data']["private_info"] = '111'
    assert_validate_result(data, "{0} is not of type 'object'".format(data['data']['transaction']))

    data['data']['transaction'] = {}
    assert_validate_result(data, "'originator_vasp_code' is a required property")

    data['data']['transaction']['originator_vasp_code'] = 123
    assert_validate_result(data, "'originator_addrs' is a required property")

    data['data']['transaction']['originator_addrs'] = 456
    assert_validate_result(data, "'beneficiary_vasp_code' is a required property")

    data['data']['transaction']['beneficiary_vasp_code'] = 789
    assert_validate_result(data, "'beneficiary_addrs' is a required property")

    data['data']['transaction']['beneficiary_addrs'] = 987
    assert_validate_result(data, "'transaction_currency' is a required property")

    data['data']['transaction']['transaction_currency'] = 654
    assert_validate_result(data, "'amount' is a required property")

    data['data']['transaction']['amount'] = '321'
    assert_validate_result(data, "'{0}' is not a 'date-time'".format(data['data']['data_dt']))

    data['data']["data_dt"] = '2016-01-12T01:24:17.130Z'
    assert_validate_result(data, "{0} is not of type 'string'".format(data['data']['signature']))

    data['data']['signature'] = '123'
    assert_validate_result(data, "'{0}' is too short".format(data['data']['signature']))

    data['data']['signature'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e' \
                                '52ddb7875b4b1'  # len = 129
    assert_validate_result(data, "'{0}' is too long".format(data['data']['signature']))

    data['data']['signature'] = 'ggg6b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'  # len = 128
    assert_validate_result(data, "'{0}' does not match '^[0123456789A-Fa-f]+$'".format(data['data']['signature']))

    data['data']['signature'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'  # len = 128
    assert_validate_result(data, "{0} is not of type 'string'".format(data['callback']['callback_url']))

    data['callback']['callback_url'] = '123456'
    assert_validate_result(data, "'{0}' is not a 'uri'".format(data['callback']['callback_url']))

    data['callback']['callback_url'] = 'http://google.com'
    assert_validate_result(data, "{0} is not of type 'string'".format(data['callback']['signature']))

    data['callback']['signature'] = '123'
    assert_validate_result(data, "'{0}' is too short".format(data['callback']['signature']))

    data['callback']['signature'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                    'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e' \
                                    '52ddb7875b4b1'  # len = 129
    assert_validate_result(data, "'{0}' is too long".format(data['callback']['signature']))

    data['callback']['signature'] = 'ggg6b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                    'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e' \
                                    '52ddb7875b4b'  # len = 128
    assert_validate_result(data, "'{0}' does not match '^[0123456789A-Fa-f]+$'".format(data['callback']['signature']))

    data['callback']['signature'] = '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d' \
                                    'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e' \
                                    '52ddb7875b4b'  # len = 128

    assert_validate_result(data,
                           "{0} is not of type 'string'".format(data['data']['transaction']['originator_vasp_code']))

    data['data']['transaction']['originator_vasp_code'] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['data']['transaction']['originator_vasp_code']))

    data['data']['transaction']['originator_vasp_code'] = '123'
    assert_validate_result(data, "{0} is not of type 'array'".format(data['data']['transaction']['originator_addrs']))

    data['data']['transaction']['originator_addrs'] = []
    assert_validate_result(data, "{0} is too short".format(data['data']['transaction']['originator_addrs']))

    data['data']['transaction']['originator_addrs'] = [123]
    assert_validate_result(data,
                           "{0} is not of type 'string'".format(data['data']['transaction']['beneficiary_vasp_code']))

    data['data']['transaction']['beneficiary_vasp_code'] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['data']['transaction']['beneficiary_vasp_code']))

    data['data']['transaction']['beneficiary_vasp_code'] = '789'
    assert_validate_result(data, "{0} is not of type 'array'".format(data['data']['transaction']['beneficiary_addrs']))

    data['data']['transaction']['beneficiary_addrs'] = []
    assert_validate_result(data, "{0} is too short".format(data['data']['transaction']['beneficiary_addrs']))

    data['data']['transaction']['beneficiary_addrs'] = [123]
    assert_validate_result(data,
                           "{0} is not of type 'string'".format(data['data']['transaction']['transaction_currency']))

    data['data']['transaction']['transaction_currency'] = ''
    assert_validate_result(data, "'{0}' is too short".format(data['data']['transaction']['transaction_currency']))

    data['data']['transaction']['transaction_currency'] = '654'
    assert_validate_result(data, "'{0}' is not of type 'number'".format(data['data']['transaction']['amount']))

    data['data']['transaction']['amount'] = 0
    assert_validate_result(data, "{0} is less than or equal to the minimum of 0".format(
        data['data']['transaction']['amount']))

    data['data']['transaction']['amount'] = -1
    assert_validate_result(data, "{0} is less than or equal to the minimum of 0".format(
        data['data']['transaction']['amount']))

    data['data']['transaction']['amount'] = 1
    assert_validate_result(data,
                           "{0} is not of type 'string'".format(data['data']['transaction']['originator_addrs'][0]))

    data['data']['transaction']['originator_addrs'] = ['']
    assert_validate_result(data, "'{0}' is too short".format(data['data']['transaction']['originator_addrs'][0]))

    data['data']['transaction']['originator_addrs'] = ['1']
    assert_validate_result(data,
                           "{0} is not of type 'string'".format(data['data']['transaction']['beneficiary_addrs'][0]))

    data['data']['transaction']['beneficiary_addrs'] = ['']
    assert_validate_result(data, "'{0}' is too short".format(data['data']['transaction']['beneficiary_addrs'][0]))

    data['data']['transaction']['beneficiary_addrs'] = ['1']
    try:
        validate(instance=data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)
    except ValidationError as error:
        pytest.fail('Unexpected ValidationError')

    data['data']['transaction']['originator_addrs_extra'] = '1'
    assert_validate_result(data, "'{0}' is not of type 'object'".format(
        data['data']['transaction']['originator_addrs_extra']))

    data['data']['transaction']['originator_addrs_extra'] = {}
    assert_validate_result(data,
                           "{0} does not have enough properties".format(
                               data['data']['transaction']['originator_addrs_extra']))

    data['data']['transaction']['originator_addrs_extra'] = {'DT': '001'}
    data['data']['transaction']['beneficiary_addrs_extra'] = '1'
    assert_validate_result(data, "'{0}' is not of type 'object'".format(
        data['data']['transaction']['beneficiary_addrs_extra']))

    data['data']['transaction']['beneficiary_addrs_extra'] = {}
    assert_validate_result(data,
                           "{0} does not have enough properties".format(
                               data['data']['transaction']['beneficiary_addrs_extra']))

    data['data']['transaction']['beneficiary_addrs_extra'] = {'DT': '001'}
    try:
        validate(instance=data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)
    except ValidationError as error:
        pytest.fail('Unexpected ValidationError')

    data['data']['expire_date'] = '123'
    assert_validate_result(data, "'{0}' is not of type 'number'".format(data['data']['expire_date']))

    data['data']['expire_date'] = -1
    assert_validate_result(data, "{0} is less than the minimum of {1}".format(data['data']['expire_date'], 0))

    data['data']['expire_date'] = 0
    try:
        validate(instance=data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


def test_validate_post_permission_request_schema_success():
    try:
        fake_data = {
            'data': {
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
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
                'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
                'transaction': {
                    'originator_vasp_code': 'VASPTWTP1',
                    'originator_addrs': [
                        '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                    ],
                    'originator_addrs_extra': {'DT': '001'},
                    'beneficiary_vasp_code': 'VASPTWTP2',
                    'beneficiary_addrs': [
                        '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                    ],
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
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
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
                'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
                'transaction': {
                    'originator_vasp_code': 'VASPTWTP1',
                    'originator_addrs': [
                        '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                    ],
                    'originator_addrs_extra': {'DT': '001'},
                    'beneficiary_vasp_code': 'VASPTWTP2',
                    'beneficiary_addrs': [
                        '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                    ],
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
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
                'expire_date': 1583146201000,
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
                'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
                'transaction': {
                    'originator_vasp_code': 'VASPTWTP1',
                    'originator_addrs': [
                        '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                    ],
                    'originator_addrs_extra': {'DT': '001'},
                    'beneficiary_vasp_code': 'VASPTWTP2',
                    'beneficiary_addrs': [
                        '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                    ],
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'expire_date': 1583146201000,
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
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
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'expire_date': 1583146201000,
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)

        fake_data = {
            'data': {
                'private_info': '6b51d431df5d7f141cbececcf79edf3dd861c3b4069f0b11661a3eefacbba918',
                'transaction': {
                    'originator_vasp_code': 'VASPTWTP1',
                    'originator_addrs': [
                        '16bUGjvunVp7LqygLHrTvHyvbvfeuRCWAh'
                    ],
                    'originator_addrs_extra': {'DT': '001'},
                    'beneficiary_vasp_code': 'VASPTWTP2',
                    'beneficiary_addrs': [
                        '3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH'
                    ],
                    'beneficiary_addrs_extra': {'DT': '002'},
                    'transaction_currency': '0x80000000',
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'expire_date': 1583146201000,
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            },
            'callback': {
                'callback_url': 'http://google.com',
                'signature': '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52d'
                             'db7875b4b6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'
            }
        }
        validate(instance=fake_data, schema=get_post_permission_request_schema(), format_checker=draft7_format_checker)
    except ValidationError:
        pytest.fail('Unexpected ValidationError')


if __name__ == '__main__':
    test_get_post_permission_request_schema()
    test_validate_post_permission_request_schema()
    test_validate_post_permission_request_schema_success()
