import unittest
import json
from crypto.ecies import ecies_encrypt, ecies_decrypt


class CryptoTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.recipient_PUBLIC_KEY = "045b409c8c15fd82744ce4f7f86d65f27d605d945d4c4eee0e4e2515a3894b9d157483cc5e49c62c07b46cd59bc980445d9cf987622d66df20c6c3634f6eb05085"
        cls.recipient_PRIVATE_KEY = "bf76d2680f23f6fc28111afe0179b8704c8e203a5faa5112f8aa52721f78fe6a"

    def testEncrypt(self):
        sensitiveData = "{" \
                        "    \"originator\": {" \
                        "        \"name\": \"Antoine Griezmann\"," \
                        "        \"date_of_birth\":\"1991-03-21\"" \
                        "    }," \
                        "    \"beneficiary\":{" \
                        "        \"name\": \"Leo Messi\"" \
                        "    }" \
                        "}"
        sensitiveStr = json.dumps(sensitiveData, separators=(',', ':'))
        enc = ecies_encrypt(sensitiveStr, self.recipient_PUBLIC_KEY)
        dec = ecies_decrypt(enc, self.recipient_PRIVATE_KEY)
        self.assertEqual(sensitiveStr, dec)


    def testDecrypt(self):
        msg = "qwer"
        # Encoded by JavaScript Sygna Bridge Util
        encoded = "045da28c71cc83e81b377891e04700bcd191bf600e44decefaa117c248754ec1fe30ddc9f4c373123b0fb8787d31372e9ec9889d27bfdb1fabc794a1f62b0606ba04859dc4ee6b3ee95fe28f7069d08e16de308440196df2f50eed83af3efb9f74d34c6a42";
        decoded = ecies_decrypt(encoded, self.recipient_PRIVATE_KEY)
        self.assertEqual(msg, decoded)

    if __name__ == '__main__':
        unittest.main()
