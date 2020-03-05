import requests
from sygna_bridge_util.config import SYGNA_BRIDGE_CENTRAL_PUBKEY, HTTP_TIMEOUT
import sygna_bridge_util.crypto.verify
import json
from sygna_bridge_util.validator import (
    validate_transfer_id,
    validate_post_permission_schema,
    validate_post_permission_request_schema,
    validate_post_transaction_id_schema
)


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
        url = self.domain + 'api/v1/bridge/vasp'
        result = self.get_sb(url)
        if 'vasp_data' not in result:
            raise ValueError(
                'Request VASPs failed: {0}'.format(result['message']))

        if not validate:
            return result['vasp_data']

        valid = sygna_bridge_util.crypto.verify.verify_data(
            result, SYGNA_BRIDGE_CENTRAL_PUBKEY)
        if not valid:
            raise ValueError('get VASP info error: invalid signature.')

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
            raise ValueError('Invalid vasp_code')

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
        validate_transfer_id(transfer_id)
        url = self.domain + 'api/v1/bridge/transaction/status?transfer_id=' + transfer_id
        return self.get_sb(url)

    def post_permission(self, post_permission_data: dict) -> dict:
        """Notify Sygna Bridge that you have confirmed specific permission Request from other VASP.
        Should be called by Beneficiary Server

         Args:
            post_permission_data (dict): {
                transfer_id:str,
                permission_status:str,
                signature:str,
                Optional expire_date(int)
                Optional reject_code(str) : BVRC001,BVRC002,BVRC003,BVRC004 or BVRC999
                Optional reject_message(str)
            }

         Returns:
            dict.

         Raises:
            Exception('permission_data invalid error')
         """
        validate_post_permission_schema(post_permission_data)
        url = self.domain + 'api/v1/bridge/transaction/permission'
        return self.post_sb(url, post_permission_data)

    def post_permission_request(self, data: dict) -> dict:
        """Should be called by Originator.

         Args: data : dict{
            data(dict): Private sender info encoded by crypto.sygnaEncodePrivateObj{
                private_info: str,
                transaction: dict,
                data_dat: str,
                signature: str,
                Optional expire_date: int
            },
            callback(dict): {
                callback_url: str,
                signature:str
            }
          }


         Returns:
            {transfer_id: str}

         Raises:
            Exception('request_data/callback invalid error')
         """
        validate_post_permission_request_schema(data)
        url = self.domain + 'api/v1/bridge/transaction/permission-request'
        params = {'data': data['data'], 'callback': data['callback']}
        return self.post_sb(url, params)

    def post_transaction_id(self, data: dict) -> dict:
        """Send broadcasted transaction id to Sygna Bridge for purpose of storage.

         Args:
            data ({transfer_id: str, txid:str, signature:str})

         Returns:
            dict

         Raises:
            Exception('send_tx_id_dict invalid error')
         """
        validate_post_transaction_id_schema(data)
        url = self.domain + 'api/v1/bridge/transaction/txid'
        return self.post_sb(url, data)