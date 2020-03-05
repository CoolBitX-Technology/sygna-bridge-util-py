# Python Sygna Bridge Util

This is a Python library to help you build servers/servies within Sygna Bridge Ecosystem. For more detail information about Sygna Bridge, please go through the [Official Sygna Bridge API Document](https://coolbitx.gitlab.io/sygna/bridge/api/#sygna-bridge).

## Installation


```shell
pip install sygna-bridge-util
```

## Crypto

Dealing with encoding, decoding, signing and verifying in Sygna Bridge.

### ECIES Encoding an Decoding

During the communication of VASPs, there are some private information that must be encrypted. We use ECIES(Elliptic Curve Integrated Encryption Scheme) to securely encrypt these private data so that they can only be accessed by the recipient.

```python
sensitive_data = {
    "originator": {
        "name": "Antoine Griezmann",# required and must be in English
        "date_of_birth":"1991-03-21"
    },
    "beneficiary":{
        "name": "Leo Messi"
    }
}

private_info = sygna_bridge_util.crypto.sygna_encrypt_private_data(
    sensitive_data, 
    recipient_public_key
)
decoded_priv_info = sygna_bridge_util.crypto.sygna_decrypt_private_data(
    private_info, 
    recipient_privte_key
)

```

### Sign and Verify

In Sygna Bridge, we use secp256k1 ECDSA over sha256 of utf-8 json string to create signature on every API call. Since you need to provide the identical utf-8 string during verfication, the order of key-value pair you put into the object is important.

The following example is the snippet of originator's signing process of `premissionRequest` API call. If you put the key `transaction` before `private_info` in the object, the verification will fail in the central server.

```python
transaction = {
    "originator_vasp_code":"10000",
    "originator_addrs":["3KvJ1uHPShhEAWyqsBEzhfXyeh1TXKAd7D"],
    "beneficiary_vasp_code":"10001",
    "beneficiary_addrs":["3F4ReDwiMLu8LrAiXwwD2DhH8U9xMrUzUf"],
    "transaction_currency":"0x80000000",
    "amount": 0.973
}

data_dt = "2019-07-29T06:28:00Z"

# using sign_data to get a valid signed object (with signature attached)

data_to_sign = {
    "private_info":private_info,
    "transaction":transaction,
    "data_dt":data_dt
}

sygna_bridge_util.crypto.sign_data(data_to_sign, originator_private_key)

valid = sygna_bridge_util.crypto.verify_data(obj, originator_public_Key)

# or you can use the method that's built for `transfer` request:
signed_data = sygna_bridge_util.crypto.sign_permission_request(
    data_to_sign, 
    originator_private_key
)

valid = sygna_bridge_util.crypto.verify_data(
    signed_data, 
    originator_public_Key
)

```

We provide different methods like `sign_permission_request`, `sign_callback()` to sign different objects(or parameters) we specified in our [api doc](https://coolbitx.gitlab.io/sygna/bridge/api/#custom-objects). You can also find more examples in the following section.

## API

API calls to communicate with Sygna Bridge server.

We use **baisc auth** with all the API calls. To simplify the process, we provide a API class to deal with authentication and post/ get request format.

```python=
sb_server = "https://apis.sygna.io/sb/"
sb_api_instance = sygna_bridge_util.API("api-key", sb_server)
```

After you create the `API` instance, you can use it to make any API call to communicate with Sygna Bridge central server.

### Get VASP Information

```python
# Get List of VASPs associated with public keys.
verify = True # set verify to true to verify the signature attached with api response automatically.
vasps = sb_api_instance.get_vasp_list(verify)

# Or call use get_vasp_public_key() to directly get public key for a specific VASP.
public_key =  sb_api_instance.get_vasp_public_key("10298", verify)
```

### For Originator

There are two API calls from **transaction originator** to Sygna Bridge Server defined in the protocol, which are `post_permission_request` and `post_transaction_id`. 

The full logic of originator would be like the following:

```python
# originator.py

private_sender_info = { 
    "originator": { 
        "name": "Antoine Griezmann",  
        "date_of_birth":"1991-03-21" 
    }, 
    "beneficiary":{
        "name":"Leo Messi"
    } 
}
recipient_public_key = sb_api_instance.get_vasp_public_key("10298")
private_info = sygna_bridge_util.crypto.sygna_encrypt_private_data(
    private_sender_info, 
    recipient_public_key
)

transaction = {
    "originator_vasp_code":"10000",
    "originator_addrs": ["3KvJ1uHPShhEAWyqsBEzhfXyeh1TXKAd7D"],
    "beneficiary_vasp_code":"10298",
    "beneficiary_addrs": ["3CHgkx946yyueucCMiJhyH2Vg5kBBvfSGH"],
    "transaction_currency":"0x80000000",
    "amount": 0.973
}
data_dt = "2019-07-29T07:29:80Z"

data_to_sign = {
    "private_info":private_info,
    "transaction":transaction,
    "data_dt":data_dt
}

transfer_data = sygna_bridge_util.crypto.sign_permission_request(
    data_to_sign, 
    sender_privKey
)

callback_url = "https://81f7d956.ngrok.io/api/v1/originator/transaction/premission"
callback_data = sygna_bridge_util.crypto.sign_callback(
    {
        "callback_url":callback_url
    }, 
    sender_privKey
)

response = sb_api_instance.post_permission_request(
    {
        "data":transfer_data,
        "callback":callback_data
    }
)

# Boradcast your transaction to blockchain after got and api reponse at your api server.
txid = "1a0c9bef489a136f7e05671f7f7fada2b9d96ac9f44598e1bcaa4779ac564dcd"

# Inform Sygna Bridge that a specific transfer is successfully broadcasted to the blockchain.

send_tx_id_data = sygna_bridge_util.crypto.sign_transaction_id(
    {
        "transfer_id":response["transfer_id"], 
        "txid":txid
    }, 
    sender_privKey
)
post_tx_id_response = sb_api_instance.post_transaction_id(send_tx_id_data)

```

### For Beneficiary

There is only one api for Beneficiary VASP to call, which is `post_permission`. After the beneficiary server confirm thet legitemacy of a transfer request, they will sign `{ transfer_id, permission_status }` using `sign_permission()` function, and send the result with signature to Sygna Bridge Central Server.

```Python

permission_status = "ACCEPTED" # or "REJECTED"
permission_data = sygna_bridge_util.crypto.sign_permission(
    {
        "transfer_id":response["transfer_id"],         
        "permission_status":permission_status
    }, 
    beneficiary_private_key
)
finalresult = sb_api_instance.post_permission(permission_data)

```