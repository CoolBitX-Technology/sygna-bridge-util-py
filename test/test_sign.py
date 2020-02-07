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
       signVasp = ""

        sig = signMsg(signVasp, self.PRIVATE_KEY)
        self.assertEqual(sig,
                         '2f1fc5a3ad0bf9e2541627dc91133ec6f82bbe9e7dfa03323623e6ed1ea981634d868001848c0773c5900eb923ca6742d6b4542a82645fa021c8576447af3547')

        is_valid = verifyMsg(signVasp, sig, self.PUBLIC_KEY)
        self.assertEqual(is_valid, True)


if __name__ == '__main__':
    unittest.main()
