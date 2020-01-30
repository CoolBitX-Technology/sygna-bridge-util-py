import unittest
import json
from crypto.ecies import ecies_encrypt, ecies_decrypt

PUBLIC_KEY = "048709ef46f46c7e89b58987b606dc54eda62f88424517667305d91b3e86b8847f1b44a9659831880a15885ec43a722f76c356ec0ee373a273a0a7900dcd077339"
PRIVATE_KEY = "948798a4dd6864f18d5c40483aa05bb58ab211a1f9bc455c4065418ee001366a"

# PUBLIC_KEY = "036410211aae9f73e8ba94674fbf53f9d83f6898ec6b32ea2cb39e9a8dbc6355c4";
# PRIVATE_KEY = "eb8473f97dedf6139e88f9bd7b6116cd03c847e236f0532b7c2f8b13efbf8f32"


class CryptoTest(unittest.TestCase):

    def test_something(self):
        self.assertEqual(True, False)

    def testEncrypt(self):
        sensitiveData = "{originator: {name: Antoine Griezmann,date_of_birth:1991-03-21},beneficiary:{name: Leo Messi }}"
        sensitiveStr = json.dumps(sensitiveData)
        enc = ecies_encrypt(sensitiveData, PUBLIC_KEY)
        dec = ecies_decrypt(enc, PRIVATE_KEY)
        my_json = dec.decode('utf8')
        self.assertEqual(my_json, sensitiveStr)

    def testSign(self):
        privateInfo = "0405a39f02fb74cb0a748ff70adf0e4b7a8910befbaa536682fd3e4d1feed551c4e5d27bf85e03836bbb975e83e620529139d31644cee17f60f089b5b44a89513c336e262dd2a686e6460339ec3a8eacbdeda77bbb7d18bec45bb4288bd959dae803176ddf535b634e6ea9367fffb5f811a10c540a4eacbd8ceb9a4b5631a1b64dfa7ac9c4f52dff09f14d18652e9eb30b0b4e56a145c6d912a89c5442a0673b83728cf6cbc527e3004eeaf609573edb2f2844c1ec68a1cf97917a9213ce695eb3624a32f7";


if __name__ == '__main__':
    unittest.main()
