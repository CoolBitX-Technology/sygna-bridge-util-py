import copy

__beneficiary_endpoint_url_schema = {
    "type": "object",
    "properties": {
        "vasp_code": {
            "type": "string",
            "minLength": 1
        },
        "beneficiary_endpoint_url": {
            "type": "string",
            "format": "uri"
        }
    },
    "required": [
        "vasp_code",
        "beneficiary_endpoint_url"
    ],
    "additionalProperties": False
}


def get_beneficiary_endpoint_url_schema() -> dict:
    clone_schema = copy.deepcopy(__beneficiary_endpoint_url_schema)
    return clone_schema
