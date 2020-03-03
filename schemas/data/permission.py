from config import PermissionStatus, RejectCode
import copy

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


def get_permission_schema(data: dict) -> dict:
    clone_schema = copy.deepcopy(__permission_schema)
    if 'permission_status' not in data or data['permission_status'] != PermissionStatus.REJECTED.value:
        return clone_schema

    clone_schema['required'].append('reject_code')
    if 'reject_code' not in data:
        return clone_schema

    if data['reject_code'] == RejectCode.BVRC999.value:
        clone_schema['required'].append('reject_message')
    return clone_schema