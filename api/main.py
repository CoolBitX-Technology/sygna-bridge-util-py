import requests
from config import SYGNA_BRIDGE_CENTRAL_PUBKEY, HTTP_TIMEOUT
from . import check
import crypto.verify
import json


class API:
    def __init__(self, api_key: str, sygna_bridge_domain: str):
        self.api_key = api_key
        self.domain = sygna_bridge_domain

    def get_sb(self, url: str) -> dict:
        """HTTP GET request to Sygna Bridge

        Args:
            url (str)

        Returns:
            dict
        """
        headers = {'api_key': self.api_key}
        response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        return response.json()

    def post_sb(self, url: str, body: dict) -> dict:
        """HTTP Post request to Sygna Bridge

        Args:
            url (str)
            body (dict)

        Returns:
            dict
        """
        headers = {'Content-Type': 'application/json',
                   'api_key': self.api_key}
        response = requests.post(
            url,
            data=json.dumps(body),
            headers=headers,
            timeout=HTTP_TIMEOUT)
        return response.json()

    def get_vasp_list(self, validate: bool = True) -> [dict]:
        """get list of registered VASP associated with public key

         Args:
            validate (bool): validate whether to validate returned vasp list data.

         Returns:
            dict({ vasp_name:str, vasp_code:str, vasp_pubkey:str })

         Raises:
            Exception('Request VASPs failed')
            Exception('get VASP info error: invalid signature')
         """
        url = self.domain+'api/v1/bridge/vasp'
        result = self.get_sb(url)

        if 'vasp_data' not in result:
            raise Exception(
                'Request VASPs failed: {0}'.format(result['message']))

        if not validate:
            return result['vasp_data']

        valid = crypto.verify.verify_data(
            result, SYGNA_BRIDGE_CENTRAL_PUBKEY)
        if not valid:
            raise Exception('get VASP info error: invalid signature.')

        return result['vasp_data']

    def get_vasp_public_key(self, vasp_code: str, validate: bool = True) -> str:
        """A Wrapper function of get_vasp_list to return specific VASP's public key.

         Args:
            vasp_code (str): vasp code
            validate (bool): validate whether to validate returned vasp list data.

         Returns:
            str. uncompressed public key

         Raises:
            Exception('Invalid vasp_code')
         """
        vasps = self.get_vasp_list(validate)
        target_vasp = None
        for _, item in enumerate(vasps):
            if item['vasp_code'] == vasp_code:
                target_vasp = item
                break

        if target_vasp is None:
            raise Exception('Invalid vasp_code')

        return target_vasp['vasp_pubkey']

    def get_status(self, transfer_id: str) -> dict:
        """get detail of particular transaction premission request

         Args:
            transfer_id (str): transfer id

         Returns:
            dict({ transferData:dict(
                {
                    transfter_id: str,
                    private_info: str,
                    transaction: dict(
                        {
                            beneficiary_vasp_code: str,
                            transaction_currency: str,
                            originator_vasp_code: str
                        }
                    ),
                    permission_request_data_signature: str,
                    permission_status: str,
                    permission_signature: str
                }
            ), vasp_code:str, signature:str })
         """
        url = self.domain+'api/v1/bridge/transaction/status?transfer_id='+transfer_id
        return self.get_sb(url)

    def post_permission(self, permission_data: dict) -> dict:
        """Notify Sygna Bridge that you have confirmed specific permission Request from other VASP.
        Should be called by Beneficiary Server

         Args:
            permission_data (dict): {transfer_id:str, permission_status:str, signature:str}

         Returns:
            dict.

         Raises:
            Exception('permission_data invalid error')
         """
        check.check_data_signed(permission_data)
        url = self.domain + 'api/v1/bridge/transaction/permission'
        return self.post_sb(url, permission_data)

    def post_permission_request(self, request_data: dict, callback: dict) -> dict:
        """Should be called by Originator.

         Args: request_data ({private_info:str, transaction:dict, data_dat:str, signature:str}):Private sender info
         encoded by crypto.sygnaEncodePrivateObj callback ({callback_url: string, signature:string})

         Returns:
            {transfer_id: str}

         Raises:
            Exception('request_data/callback invalid error')
         """
        check.check_data_signed(request_data)
        check.check_data_signed(callback)
        url = self.domain + 'api/v1/bridge/transaction/permission-request'
        params = {'data': request_data, 'callback': callback}
        return self.post_sb(url, params)

    def post_transaction_id(self, send_tx_id_dict: dict) -> dict:
        """Send broadcasted transaction id to Sygna Bridge for purpose of storage.

         Args:
            send_tx_id_dict ({transfer_id: str, txid:str, signature:str})

         Returns:
            dict

         Raises:
            Exception('send_tx_id_dict invalid error')
         """
        check.check_data_signed(send_tx_id_dict)
        check.check_specific_key(send_tx_id_dict, 'transfer_id', str)
        check.check_specific_key(send_tx_id_dict, 'txid', str)

        url = self.domain + 'api/v1/bridge/transaction/txid'
        return self.post_sb(url, send_tx_id_dict)
