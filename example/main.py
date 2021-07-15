from sygna_bridge_util.api import API
from sygna_bridge_util.crypto import (
    sign_data,
    verify_data,
    encrypt_private_data,
    decrypt_private_data,
    sign_beneficiary_endpoint_url,
    sign_callback,
    sign_permission,
    sign_permission_request,
    sign_transaction_id
)
from sygna_bridge_util.config import SYGNA_BRIDGE_API_TEST_DOMAIN

DOMAIN = SYGNA_BRIDGE_API_TEST_DOMAIN

ORIGINATOR_API_KEY = "{{ORIGINATOR_API_KEY}}"
ORIGINATOR_PRIVATE_KEY = "{{ORIGINATOR_PRIVATE_KEY}}"
ORIGINATOR_PUBLIC_KEY = "{{ORIGINATOR_PUBLIC_KEY}}"

BENEFICIARY_API_KEY = "{{BENEFICIARY_API_KEY}}"
BENEFICIARY_PRIVATE_KEY = "{{BENEFICIARY_PRIVATE_KEY}}"
BENEFICIARY_PUBLIC_KEY = "{{BENEFICIARY_PUBLIC_KEY}}"


def sign_and_verify():
    data = {'key': 'value'}
    signed_data = sign_data(data, ORIGINATOR_PRIVATE_KEY)
    print(f'signed_data = {signed_data}')

    is_correct = verify_data(signed_data, ORIGINATOR_PUBLIC_KEY)
    print(f'is_correct = {is_correct}')


def encrypt_and_decrypt():
    data = {'originator': {'name': 'Antoine Griezmann', 'date_of_birth': '1991-03-21'},
            'beneficiary': {'name': 'Leo Messi'}}
    encrypt_data = encrypt_private_data(data, ORIGINATOR_PUBLIC_KEY)
    print(f'encrypt_data = {encrypt_data}')

    decrypt_data = decrypt_private_data(encrypt_data, ORIGINATOR_PRIVATE_KEY)
    print(f'decrypt_data = {decrypt_data}')


def get_status():
    transfer_id = '9e28be67422352c4cdbd954f23765672e63b2b47e6746c1dcae1e5542e2ed631'
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    get_status_result = instance.get_status(transfer_id)
    print(f'get_status_result = {get_status_result}')


def get_vasp_list():
    is_need_valid = True
    is_prod = False
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    get_vasp_list_result = instance.get_vasp_list(is_need_valid, is_prod)
    print(f'get_vasp_list_result = {get_vasp_list_result}')


def get_vasp_public_key():
    is_need_valid = True
    is_prod = False
    vasp_code = 'VASPJPJT4'
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    vasp_public_key = instance.get_vasp_public_key(vasp_code, is_need_valid, is_prod)
    print(f'vasp_public_key = {vasp_public_key}')


def get_currencies():
    get_currencies_data = {
        'currency_id': 'sygna:0x80000090',
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    get_currencies_result = instance.get_currencies(
        get_currencies_data)
    print(f'get_currencies_result = {get_currencies_result}')


def post_permission_request():
    private_info = encrypt_private_data({
        "originator": {
            "originator_persons": [
                {
                    "natural_person": {
                        "name": {
                            "name_identifiers": [
                                {
                                    "primary_identifier": "Wu Xinli",
                                    "name_identifier_type": "LEGL"
                                }
                            ]
                        },
                        "national_identification": {
                            "national_identifier": "446005",
                            "national_identifier_type": "RAID",
                            "registration_authority": "RA000553"
                        },
                        "country_of_residence": "TZ"
                    }
                }
            ],
            "account_numbers": [
                "r3kmLJN5D28dHuH8vZNUZpMC43pEHpaocV"
            ]
        },
        "beneficiary": {
            "beneficiary_persons": [
                {
                    "legal_person": {
                        "name": {
                            "name_identifiers": [
                                {
                                    "legal_person_name": "ABC Limited",
                                    "legal_person_name_identifier_type": "LEGL"
                                }
                            ]
                        }
                    }
                }
            ],
            "account_numbers": [
                "rAPERVgXZavGgiGv6xBgtiZurirW2yAmY"
            ]
        }
    }, BENEFICIARY_PUBLIC_KEY)
    permission_request_data = {
        'private_info': private_info,
        "transaction": {
            "originator_vasp": {
                "vasp_code": "VASPUSNY1",
                "addrs": [
                    {
                        "address": "r3kmLJN5D28dHuH8vZNUZpMC43pEHpaocV",
                        "addr_extra_info": []
                    }
                ]
            },
            "beneficiary_vasp": {
                "vasp_code": "VASPUSNY2",
                "addrs": [
                    {
                        "address": "rAPERVgXZavGgiGv6xBgtiZurirW2yAmY",
                        "addr_extra_info": [
                            {
                                "tag": "abc"
                            }
                        ]
                    }
                ]
            },
            "currency_id": "sygna:0x80000090",
            "amount": "12.5"
        },
        'data_dt': '2020-07-13T05:56:53.088Z'
    }
    signed_permission_request_data = sign_permission_request(permission_request_data, ORIGINATOR_PRIVATE_KEY)

    callback_data = {
        'callback_url': 'https://7434116d30db72c01911efd735cfefdc.m.pipedream.net'
    }
    signed_callback_data = sign_callback(callback_data, ORIGINATOR_PRIVATE_KEY)

    post_permission_request_data = {
        'data': signed_permission_request_data,
        'callback': signed_callback_data
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_permission_request_result = instance.post_permission_request(post_permission_request_data)
    print(f'post_permission_request_result = {post_permission_request_result}')


def post_permission():
    permission_data = {
        'transfer_id': '848a357d26b7ec2f192f51d1a4a4e6b537c4e83b14deb3a151a3158a7a717feb',
        'permission_status': 'ACCEPTED',
    }
    signed_permission_data = sign_permission(permission_data, BENEFICIARY_PRIVATE_KEY)

    instance = API(BENEFICIARY_API_KEY, DOMAIN)
    post_permission_result = instance.post_permission(signed_permission_data)
    print(f'post_permission_result = {post_permission_result}')


def post_transaction_id():
    transaction_id_data = {
        'transfer_id': '848a357d26b7ec2f192f51d1a4a4e6b537c4e83b14deb3a151a3158a7a717feb',
        'txid': '12345678',
    }
    signed_transaction_id_data = sign_transaction_id(transaction_id_data, ORIGINATOR_PRIVATE_KEY)

    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_transaction_id_result = instance.post_transaction_id(signed_transaction_id_data)
    print(f'post_transaction_id_result = {post_transaction_id_result}')


def post_beneficiary_endpoint_url():
    beneficiary_endpoint_url_data = {
        'callback_permission_request_url': 'https://google.com',
        'vasp_code': 'VASPUSNY2',
        'callback_txid_url': 'https://stackoverflow.com',
        'callback_validate_addr_url': 'https://github.com',
    }
    signed_beneficiary_endpoint_url_data = sign_beneficiary_endpoint_url(beneficiary_endpoint_url_data,
                                                                         BENEFICIARY_PRIVATE_KEY)

    instance = API(BENEFICIARY_API_KEY, DOMAIN)
    post_beneficiary_endpoint_url_result = instance.post_beneficiary_endpoint_url(signed_beneficiary_endpoint_url_data)
    print(f'post_beneficiary_endpoint_url_result = {post_beneficiary_endpoint_url_result}')


def post_retry():
    retry_data = {
        'vasp_code': 'VASPUSNY2',
    }
    instance = API(BENEFICIARY_API_KEY, DOMAIN)
    post_retry_result = instance.post_retry(
        retry_data)
    print(f'post_retry_result = {post_retry_result}')


if __name__ == '__main__':
    sign_and_verify()
    # encrypt_and_decrypt()
    # get_status()
    # get_vasp_list()
    # get_vasp_public_key()
    # get_currencies()
    # post_permission_request()
    # post_permission()
    # post_transaction_id()
    # post_beneficiary_endpoint_url()
    # post_retry()
