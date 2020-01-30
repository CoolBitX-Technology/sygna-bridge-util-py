import unittest
from unittest import mock
from unittest.mock import call
import requests
from api import API
import pytest
import json
from crypto.verify import verify_data
from config import HTTP_TIMEOUT

# your keys here
ORIGINATOR_API_KEY = "1bb95eb6677172ffd7a84fa03a73cf908ecd4767068e8a4b76b70045517db159"
BENEFICIARY_API_KEY = "a2b6e41524e8063af34160762935299291b31b86170c3ed8ceb2d4eefe3979cb"
DOMAIN = "dev-api.sygna.io/sb"


class ApiTest(unittest.TestCase):
    @mock.patch('requests.get')
    def test_get_sb(self, mock_requests):
        """should use correct args to call get_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN+"api/v1/bridge/vasp"
        instance.get_sb(url)
        assert mock_requests.call_count == 1
        assert mock_requests.call_args == call(
            url, headers={'api_key': ORIGINATOR_API_KEY}, timeout=HTTP_TIMEOUT)

    @mock.patch('requests.post')
    def test_post_sb(self, mock_requests):
        """should use correct args to call post_sb"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        url = DOMAIN+"api/v1/bridge/transaction/permission"
        body = {
            "transfer_id": "ad468f326ebcc2242c32aa6bf7084c44135a068d939e52c08b6d2e86eb9ef725",
            "permission_status": "ACCEPTED",
            "signature": "309f14db5fe4c33e9ebd770d110a89a93c1c9f68b8e1aac18097c1078ffb5a292f4132501ab1e3bf1f9ee3c3f8a9fd9c3f94ac403a5370eb38a6cdece8d7d1cc"
        }
        instance.post_sb(url, body)
        assert mock_requests.call_count == 1
        assert mock_requests.call_args == call(
            url,
            data=json.dumps(body),
            headers={'Content-Type': 'application/json',
                     'api_key': ORIGINATOR_API_KEY},
            timeout=HTTP_TIMEOUT)

    @mock.patch('crypto.verify.verify_data')
    def test_get_vasp_list(self, mock_verify):
        """ should contain correct keys or raise exception if verify_data result is false"""
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        mock_verify.return_value = True
        vasp_data_list = instance.get_vasp_list()
        assert type(vasp_data_list) is list
        assert len(vasp_data_list) > 0
        vasp_data = vasp_data_list[0]
        assert type(vasp_data) is dict
        assert ('vasp_code' in vasp_data) is True
        assert type(vasp_data['vasp_code']) is str
        assert ('vasp_name' in vasp_data) is True
        assert type(vasp_data['vasp_name']) is str
        assert ('vasp_pubkey' in vasp_data) is True
        assert type(vasp_data['vasp_pubkey']) is str

        mock_verify.return_value = False
        with pytest.raises(Exception) as excinfo:
            instance.get_vasp_list()
        assert "get VASP info error: invalid signature." == str(
            excinfo.value)

        """ still return result event if verify_data result is false"""
        mock_verify.return_value = False
        vasp_data_list = instance.get_vasp_list(False)
        assert type(vasp_data_list) is list
        assert len(vasp_data_list) > 0
        vasp_data = vasp_data_list[0]
        assert type(vasp_data) is dict
        assert ('vasp_code' in vasp_data) is True
        assert type(vasp_data['vasp_code']) is str
        assert ('vasp_name' in vasp_data) is True
        assert type(vasp_data['vasp_name']) is str
        assert ('vasp_pubkey' in vasp_data) is True
        assert type(vasp_data['vasp_pubkey']) is str

    def test_get_vasp_public_key(self):
        """ should return correct public key or raise exception if vasp_code is not exist"""
        vasp_code = 'VASPJPJT4'
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        vasp_public_key = instance.get_vasp_public_key(vasp_code)
        assert vasp_public_key == '04670af26edc74b1ae4e4acb6cef65dc0c3914528296aa48a6412f00cf0576d735d99e7cdd9da3daaef6fded244553597be9272d6cd2065a52cc7157264a2a4836'

        vasp_code = '????'
        with pytest.raises(Exception) as excinfo:
            instance.get_vasp_public_key(vasp_code)
        assert "Invalid vasp_code" == str(
            excinfo.value)

    def test_get_status(self):
        """ should contain correct keys"""
        transfer_id = '7a334a64ac5be7f7ad40028af664564d168b2d95b029cf8650a70768409cda64'
        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        status = instance.get_status(transfer_id)
        assert type(status) is dict
        assert ('signature' in status) is True
        assert type(status['signature']) is str
        assert ('transferData' in status) is True
        assert type(status['transferData']) is dict
        transferData = status['transferData']
        assert ('transfer_id' in transferData) is True
        assert type(transferData['transfer_id']) is str
        assert ('private_info' in transferData) is True
        assert type(transferData['private_info']) is str
        assert ('permission_request_data_signature' in transferData) is True
        assert type(transferData['permission_request_data_signature']) is str
        assert ('permission_status' in transferData) is True
        assert type(transferData['permission_status']) is str
        assert ('permission_signature' in transferData) is True
        assert type(transferData['permission_signature']) is str
        transaction = transferData['transaction']
        assert ('beneficiary_vasp_code' in transaction) is True
        assert type(transaction['beneficiary_vasp_code']) is str
        assert ('transaction_currency' in transaction) is True
        assert type(transaction['transaction_currency']) is str
        assert ('originator_vasp_code' in transaction) is True
        assert type(transaction['originator_vasp_code']) is str

    def test_post_permission_request(self):
        """ should contain correct keys or contain err_code if the transfer already has permission status """
        request_data = {
            "private_info": "04f76bf0372c4d4679a172aaaf7fe4746cb83f2a2e5d6a5afcfe6bba72ad4c540d7940853f5fd1f4928c541c39efae81e9165598bad256fab77f6d5c4bd8d135b0553e61bbaeb6d573c71b23d656ed9e4ac37f40106ebd3aab8839c77409a3890b5f056d4e11aaf87c6d29580869ec5f81d20ecaad266ba69e234a2eb627d5c7b95957d82fd1b69172f6bce480f74d9f4ea7d4d38300669c25723e91c5bce83ec8f29aedd4",
            "transaction":
            {
                "originator_vasp_code": "VASPJPJT4",
                "originator_addrs": ["3MNDLKJQW109J3KASM344"],
                "beneficiary_vasp_code": "VASPJPJT3",
                "beneficiary_addrs": ["0x1234567890101010"],
                "transaction_currency": "0x80000000",
                "amount": 0.1234
            },
            "data_dt": "2019-07-29T06:29:00.123Z",
            "signature": "525f09fda51de55fbe6dfb87ba4a3077b7ec4c3eccc0d8714a6e50a09d2f3c6a468b997d44e52d9ae13a968d5c4973eabec612ad189e6e32c2820f065cd29821"
        }
        callback = {
            "callback_url": "http://ec2-3-19-59-48.us-east-2.compute.amazonaws.com:7676/api/v1/originator/transaction/permission",
            "signature": "62bfe28b58d0e53b3b4fb0d246d954a4088d7d236769f394af2b4c230cc8093f27644596e695563ed37d0fe004b0c6c8b91873ef96315d32703a998c5e92e603"
        }

        instance = API(ORIGINATOR_API_KEY, DOMAIN)
        """the transfer already has permission status """
        response = instance.post_permission_request(request_data, callback)
        print('test_post_permission_request response={0}'.format(response))
        assert ('err_code' in response) is True
        assert type(response['err_code']) is str
        assert response['err_code'] == '010217'

    def test_post_permission(self):
        """ should contain correct keys or contain err_code if the transfer already has permission status """
        instance = API(BENEFICIARY_API_KEY, DOMAIN)

        """the transfer already has permission status """
        response = instance.post_permission(
            {
                "transfer_id": "7a334a64ac5be7f7ad40028af664564d168b2d95b029cf8650a70768409cda64",
                "permission_status": "REJECTED",
                "signature": "b26cc88a67d3d5bcd95cc698b886c06e01b4cafe204e5aea2bca3360db6b4f4725529c8fcfd49f3b000bd89aa025fd471b2fd71e6573334a65f55ad1006782ed"
            }
        )
        print('test_post_permission response={0}'.format(response))
        assert ('err_code' in response) is True
        assert type(response['err_code']) is str
        assert response['err_code'] == '010215'

    def test_post_transaction_id(self):
        """ should contain correct keys or contain err_code if the transfer does not exist """
        instance = API(ORIGINATOR_API_KEY, DOMAIN)

        """the transfer does not exist"""
        response = instance.post_transaction_id(
            {
                "transfer_id": "ad468f326ebcc2242c32aa6bf7084c44135a068d939e52c08b6d2e86eb9ef725",
                "txid": "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                "signature": "6e8e259319f22df4dcb1a03cf701baf2d7fbd668fe3250f60ed12bb5c462fb712e9b68069ec0893042188a81a384da1fec5eb06173fadd327318db8430e606eb"
            }
        )
        print('post_transaction_id response={0}'.format(response))
        assert ('err_code' in response) is True
        assert type(response['err_code']) is str
        assert response['err_code'] == '010319'
