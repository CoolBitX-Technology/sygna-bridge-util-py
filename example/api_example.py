from sygna_bridge_util.api import API

DOMAIN = 'https://test-api.sygna.io/sb/'
ORIGINATOR_API_KEY = 'a973dc6b71115c6126370191e70fe84d87150067da0ab37616eecd3ae16e288d'
BENEFICIARY_API_KEY = 'b94c6668bbdf654c805374c13bc7b675f00abc50ec994dbce322d7fb0138c875'


def get_status():
    transfer_id = '9e28be67422352c4cdbd954f23765672e63b2b47e6746c1dcae1e5542e2ed631'
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    get_status_result = instance.get_status(transfer_id)
    print(f'get_status_result = {get_status_result}')


def get_vasp_list():
    is_need_valid = True
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    get_vasp_list_result = instance.get_vasp_list(is_need_valid)
    print(f'get_vasp_list_result = {get_vasp_list_result}')


def get_vasp_public_key():
    is_need_valid = True
    vasp_code = 'VASPJPJT4'
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    vasp_public_key = instance.get_vasp_public_key(vasp_code, is_need_valid)
    print(f'vasp_public_key = {vasp_public_key}')


def post_permission():
    permission_data = {
        'transfer_id': '7ee09be947adfa9cca16effe0fdf6fb719efecced91c31f75efaa4f17c011eed',
        'permission_status': 'ACCEPTED',
        'signature': '0b03217c58d167529a850978f7fad329210c58703c18d1686bb819c88f41b12d7c0'
                     '78de678b451e0aed9de21b5b71aac9e0ce399ba0ca18a9bd002ac6235e5b8'
    }
    instance = API(BENEFICIARY_API_KEY, DOMAIN)
    post_permission_result = instance.post_permission(permission_data)
    print(f'post_permission_result = {post_permission_result}')


def post_permission_request():
    post_permission_request_data = {
        'data':
            {
                'private_info': '049a49a6e7d5f9758eeaaf7c87bed9842e6b6a4cc2f671c6080f3a2a777b07b46225cd1630'
                                'ec79e5ece15dc53e29edc5ff85677550cceb570075e866650a655a966bef5a984190f1c6235'
                                'b1b89051fc118e1d67818bd026c7ed8f91b268b4167d2b8099d4c81b3035412525d003eb9ed5'
                                '565e050a7f4d52cdbf1af4beca970d024d4dfa3aa4cf02ce4301d1062c2682e02727688b04196'
                                'ba2330927d9e7c32966fe7a349cf81cfc629416805ceccea672f8920bb8e6da591663905a7fe56'
                                'a37c0909149eeb',
                'transaction': {
                    'originator_vasp_code': 'VASPUSNY2',
                    'originator_addrs': [
                        '3KvJ1uHPShhEAWyqsBEzhfXyeh1TXKAd7D'
                    ],
                    'beneficiary_vasp_code': 'VASPUSNY1',
                    'beneficiary_addrs': [
                        '3F4ReDwiMLu8LrAiXwwD2DhH8U9xMrUzUf'
                    ],
                    'transaction_currency': '0x80000000',
                    'amount': '1.2'
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature': '219ce35edceaec45e5815134953170f0f6b7d7deb038054ec2e978411e1d0f9954b54b'
                             '40dbc22297157dab00ee83c4867d5cf67f169ca0091ae327c8ac5aad91'

            },
        'callback': {
            'callback_url': 'https://api.sygna.io/api/v1.1.0/bridge/',
            'signature': 'a32fd8dc7e0eb143d3b4e9d590170962c59b9b4b2d927342182339bb375ce08d6b84fca5dd7a5'
                         'd952332c78c45a2377d026dae0279871fb1847ad68acc61c155'
        }
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_permission_request_result = instance.post_permission_request(post_permission_request_data)
    print(f'post_permission_request_result = {post_permission_request_result}')


def post_transaction_id():
    post_transaction_id_data = {
        'transfer_id': '7ee09be947adfa9cca16effe0fdf6fb719efecced91c31f75efaa4f17c011eed',
        'txid': '12345678',
        'signature': 'e4c5d3d46a87e0c39cb64c3da47558bc92123e3dc30206ebd797c526326139894b'
                     'c8264831f580421123006218a45b7530fcaa89ed35aafd1f18d9c00afe808d'
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_transaction_id_result = instance.post_transaction_id(post_transaction_id_data)
    print(f'post_transaction_id_result = {post_transaction_id_result}')


def post_beneficiary_endpoint_url():
    post_beneficiary_endpoint_url_data = {
        'signature': '4b97136c369d40d05af5c381c6cfa2a5118c56c375caff6dc5cdca0bba2c0be739'
                     '1b398d94473e4b11aec50860b10f593202d1dc3af279fa1814e7174184c476',
        'beneficiary_endpoint_url': 'https://api.sygna.io/api/v1.1.0/bridge/',
        'vasp_code': 'VASPUSNY1'
    }
    instance = API(BENEFICIARY_API_KEY, DOMAIN)
    post_beneficiary_endpoint_url_result = instance.post_beneficiary_endpoint_url(post_beneficiary_endpoint_url_data)
    print(f'post_beneficiary_endpoint_url_result = {post_beneficiary_endpoint_url_result}')


if __name__ == '__main__':
    get_status()
    # get_vasp_list()
    # get_vasp_public_key()
    # post_permission()
    # post_permission_request()
    # post_transaction_id()
    # post_beneficiary_endpoint_url()
