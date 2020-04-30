import copy

__post_beneficiary_endpoint_url = {
    "type": "object",
    "properties": {
        "vasp_code": {
            "type": "string",
            "minLength": 1
        },
        "beneficiary_endpoint_url": {
            "type": "string",
            "format": "uri"
        },
        "signature": {
            "type": "string",
            "minLength": 128,
            "maxLength": 128,
            "pattern": "^[0123456789A-Fa-f]+$"
        }
    },
    "required": [
        "vasp_code",
        "beneficiary_endpoint_url",
        "signature"
    ],
    "additionalProperties": False
}


def get_post_beneficiary_endpoint_url_schema() -> dict:
    clone_schema = copy.deepcopy(__post_beneficiary_endpoint_url)
    return clone_schema
