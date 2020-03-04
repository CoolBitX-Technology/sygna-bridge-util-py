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
        'transfer_id': '9e28be67422352c4cdbd954f23765672e63b2b47e6746c1dcae1e5542e2ed631',
        'permission_status': 'ACCEPTED',
        'signature': '1cf7779782e9f8d8de21b590069b34c6cdc322ed52f3586d90638a9ef605418962d'
                     'e9f414eed610610fc58498af1c23e5f8d3a623903a671754f260984bfeda2'
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
                    'amount': 1
                },
                'data_dt': '2019-07-29T06:29:00.123Z',
                'signature': 'c800add1fdd30c50a7dafa156e3cb15623d5675d81b20d05e4d0c069ef284e5b724687'
                             '41e3a758a8ab92e54b879ebda1b4959d980734526ee0df0592debcc49a'

            },
        'callback': {
            'callback_url': 'http://google.com',
            'signature': 'd50350b566c6041b5a6be19cc3266fdd5ba69f3ccd80cbe528f8e3f652dd2d177ff873421e'
                         'a1550c5f4d9219515cc4194c822cf014fd22eef2fdec86a2c7fc72'
        }
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_permission_request_result = instance.post_permission_request(post_permission_request_data)
    print(f'post_permission_request_result = {post_permission_request_result}')


def post_transaction_id():
    post_transaction_id_data = {
        'transfer_id': '9e28be67422352c4cdbd954f23765672e63b2b47e6746c1dcae1e5542e2ed631',
        'txid': '12345678',
        'signature': 'c59d44e020ff2a804ecd6285bb38345166e32346b6102b27cab9670cdeaa9c5f1cd'
                     'df40c21751416d625645d5d5302b0e56992ab64fa48b0db3cd9e1c1d91ca9'
    }
    instance = API(ORIGINATOR_API_KEY, DOMAIN)
    post_transaction_id_result = instance.post_transaction_id(post_transaction_id_data)
    print(f'post_transaction_id_result = {post_transaction_id_result}')


if __name__ == '__main__':
    get_status()
    # get_vasp_list()
    # get_vasp_public_key()
    # post_permission()
    # post_permission_request()
    # post_transaction_id()
