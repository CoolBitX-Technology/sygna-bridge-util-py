import unittest
from jsonobject import *
from crypto.sign import signMsg, verifyMsg
import json


class Sign_data(JsonObject):
    status = StringProperty()
    privateInfo = StringProperty()
    dataDate = StringProperty()
    txId = StringProperty()
    transferId = StringProperty()
    callbackUrl = StringProperty()


class SignTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.PUBLIC_KEY = "04629dac91cbe671b38b20822f03fe39252a0f93505111c330fbf531af91f3a05e439ec27c4e8ad0b705408bbe9f1e225beeb2b1a33b1b7a23a20040a8c95fca61"
        cls.PRIVATE_KEY = "87c6578c29c9d864ca795d2a095beee1aabef1d6b284df7ec1b5e624045ae3db"

    def testSign(self):
        sign_data = Sign_data(
            status="ACCEPTED",
            privateInfo="048fe63ad1da7a40d4dc2937788bf970ec5e04bdc2f688c4b24ec9dedba5e7f1e2ef5c42e91e997727d917d488e7c28c6bef0bc35d1c76c598f8905948802605dcfc302291ad6a2519f11618ebe8d5d9aa1cbee726bdb277175b771e09f105d90a62c8fe247760c9516406826c43227d1b47cb7cd4135a42576aa26af988a71405028f8ceabae8060ccdff26b88df81a1b1f49fab0a356759bc779c2a292210e7eb7cae9eb774a173a64f80675e45b7bea02e203927e26dd5f5159140235e7c0f06ab1966b2c36c139b6b14ead574a847b1201c4c944eed8cf0724d1081f018d76210e7e3be3d23d4a89739efbd59d20b41b3f12c6efc0a5c6acdc3cf0058fd024e58207384d51547e",
            dataDate="2019-07-29T06:29:00.123Z",
            txId="1a0c9bef489a136f7e05671f7f7fada2b9d96ac9f44598e1bcaa4779ac564dcd",
            transferId="eeac79bb6ad673bfb4444b3bed1191c4b084270445becb7fdc2af7a80bb66aab",
            callbackUrl="http://ec2-3-19-59-48.us-east-2.compute.amazonaws.com:4000/api/v1/originator/transaction/permission"
        )

        sign_data_obj = sign_data.to_json()
        sig = signMsg(sign_data_obj, self.PRIVATE_KEY)
        is_valid = verifyMsg(sign_data_obj, sig, self.PUBLIC_KEY)
        self.assertEqual(is_valid, True)

    def testSignVasp(self):
        signVasp = {
            'vasp_data':
                [{'vasp_code': 'BBBBBBbb333', 'vasp_name': 'CCC', 'is_sb_need_static': False,
                  'vasp_pubkey': '04629dac91cbe671b38b20822f03fe39252a0f93505111c330fbf531af91f3a05e439ec27c4e8ad0b705408bbe9f1e225cccb2b1a33b1b7a23a20040a8c95fca61'},
                 {'vasp_code': 'VASPJPJT4', 'vasp_name': 'VASP4 in Tokyo, Japan',
                  'vasp_pubkey': '04670af26edc74b1ae4e4acb6cef65dc0c3914528296aa48a6412f00cf0576d735d99e7cdd9da3daaef6fded244553597be9272d6cd2065a52cc7157264a2a4836'},
                 {'vasp_code': 'OOOOTWTW98', 'vasp_name': 'OOO', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'}, {'vasp_code': 'VASPUSNY1', 'vasp_name': 'VASP1 in New York, USA',
                                                       'vasp_pubkey': '048709ef46f46c7e89b58987b606dc54eda62f88424517667305d91b3e86b8847f1b44a9659831880a15885ec43a722f76c356ec0ee373a273a0a7900dcd077339'},
                 {'vasp_code': 'FFFFTWTW98', 'vasp_name': 'FFF', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'},
                 {'vasp_code': 'ABCDKRZZ111', 'vasp_name': 'ASDFGHJKL111111', 'is_sb_need_static': True,
                  'vasp_pubkey': '22222222222222222222222'},
                 {'vasp_code': 'VASPTWTP66666', 'vasp_name': 'PAPAPAPAPAPAPAAPA', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'},
                 {'vasp_code': 'CCCCTWTW98', 'vasp_name': 'CCC', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'},
                 {'vasp_code': 'AAAAAAAA798', 'vasp_name': 'AAAA', 'is_sb_need_static': False,
                  'vasp_pubkey': '04629dac91cbe671b38b20822f03fe39252a0f93505111c330fbf531af91f3a05e439ec27c4e8ad0b705408bbe9f1e225beeb2b1a33b1b7a23a20040a8c95fca61'},
                 {'vasp_code': 'KKKKTWTW98', 'vasp_name': 'KKK', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'},
                 {'vasp_code': 'VASPKRZZ888', 'vasp_name': 'Goooooooooooooooooooooooooooooooooogle',
                  'is_sb_need_static': False,
                  'vasp_pubkey': '0x5dc3906c9ee96f8365cf461f109026c2a9bd196cb628f276366bafce93982287'},
                 {'vasp_code': 'XXXXUSXX111', 'vasp_name': 'asdfghjkl', 'is_sb_need_static': False,
                  'vasp_pubkey': '0xf163b7df90d8722ec42124ad380d5099615750214f080e20b46c7e5ee2b9d041'},
                 {'vasp_code': 'VASPUSNY2', 'vasp_name': 'VASP2 in New York, USA',
                  'vasp_pubkey': '04b1f14590a37c5c5fdcdc4f6d606eb383a79d5f6d72c210ec4fab47c2e9a59b4fd1149d8e8fa31ac1a04a9142cda2a479c642fb606eaac14c874fd7426e379f54'},
                 {'vasp_code': 'VASPJPJT3', 'vasp_name': 'VASP3 in Tokyo, Japan',
                  'vasp_pubkey': '04247bc554740852792dee49b8359cb25c74f2335d2c6e2025cd0880a06c8da1d51d461f720046c84da1dab106dfdac0452c92f09de7022a4cef5c4f3f6f3064d5'},
                 {'vasp_code': 'JJJJTWTW98', 'vasp_name': 'JJJ', 'is_sb_need_static': False,
                  'vasp_pubkey': 'AAAAAAAAAAAAAAAA'}],
            'signature': ''
        }
        sig = signMsg(signVasp, self.PRIVATE_KEY)
        """ sig from javascript util  """
        self.assertEqual(sig,
                         '2f1fc5a3ad0bf9e2541627dc91133ec6f82bbe9e7dfa03323623e6ed1ea981634d868001848c0773c5900eb923ca6742d6b4542a82645fa021c8576447af3547')

        is_valid = verifyMsg(signVasp, sig, self.PUBLIC_KEY)
        self.assertEqual(is_valid, True)
