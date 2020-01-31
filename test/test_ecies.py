import unittest
import json
from crypto.ecies import ecies_encrypt, ecies_decrypt


class CryptoTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.PUBLIC_KEY = "048709ef46f46c7e89b58987b606dc54eda62f88424517667305d91b3e86b8847f1b44a9659831880a15885ec43a722f76c356ec0ee373a273a0a7900dcd077339"
        cls.PRIVATE_KEY = "948798a4dd6864f18d5c40483aa05bb58ab211a1f9bc455c4065418ee001366a"

    def testEncrypt(self):
        # sensitiveData = "{originator: {name: Antoine Griezmann,date_of_birth:1991-03-21},beneficiary:{name: Leo Messi }}"
        sensitiveData = "{" \
                        "    \"originator\": {" \
                        "        \"name\": \"Antoine Griezmann\"," \
                        "        \"date_of_birth\":\"1991-03-21\"" \
                        "    }," \
                        "    \"beneficiary\":{" \
                        "        \"name\": \"Leo Messi\"" \
                        "    }" \
                        "}"
        sensitiveStr = json.dumps(sensitiveData)
        enc = ecies_encrypt(sensitiveData, self.PUBLIC_KEY)
        print(enc)
        dec = ecies_decrypt(enc, self.PRIVATE_KEY)
        my_json = dec.decode('utf8')
        self.assertEqual(my_json, sensitiveStr)

    if __name__ == '__main__':
        unittest.main()
