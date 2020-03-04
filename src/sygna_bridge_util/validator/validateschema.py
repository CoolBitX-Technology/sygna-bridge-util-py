from jsonschema import validate, draft7_format_checker
from sygna_bridge_util.schemas import (
    get_permission_request_schema,
    get_permission_schema,
    get_txid_schema,
    get_callback_schema,
    get_post_permission_schema,
    get_post_permission_request_schema,
    get_post_txid_schema
)
from .validatedata import validate_expire_date


def validate_schema(data: dict, schema: dict) -> None:
    validate(instance=data, schema=schema, format_checker=draft7_format_checker)


def validate_permission_schema(data: dict) -> None:
    validate_schema(data, get_permission_schema(data))
    if 'expire_date' in data:
        validate_expire_date(data['expire_date'])


def validate_permission_request_schema(data: dict) -> None:
    validate_schema(data, get_permission_request_schema())
    if 'expire_date' in data:
        validate_expire_date(data['expire_date'])


def validate_transaction_id_schema(data: dict) -> None:
    validate_schema(data, get_txid_schema())


def validate_callback_schema(data: dict) -> None:
    validate_schema(data, get_callback_schema())


def validate_post_permission_schema(data: dict) -> None:
    validate_schema(data, get_post_permission_schema(data))
    if 'expire_date' in data:
        validate_expire_date(data['expire_date'])


def validate_post_permission_request_schema(data: dict) -> None:
    validate_schema(data, get_post_permission_request_schema())
    if 'expire_date' in data['data']:
        validate_expire_date(data['data']['expire_date'])


def validate_post_transaction_id_schema(data: dict) -> None:
    validate_schema(data, get_post_txid_schema())
