import ecdsa
import json
from hashlib import sha256, sha1

if __name__ == '__main__':
    # message = 'message'
    # message_b = message.encode(encoding='utf-8')
    # public_key = '98cedbb266d9fc38e41a169362708e0509e06b3040a5dfff6e08196f8d9e49cebfb4f4cb12aa7ac34b19f3b29a17f4e5464873f151fd699c2524e0b7843eb383'
    # sig = '740894121e1c7f33b174153a7349f6899d0a1d2730e9cc59f674921d8aef73532f63edb9c5dba4877074a937448a37c5c485e0d53419297967e95e9b1bef630d'
    #
    # vk = ecdsa.VerifyingKey.from_string(bytearray.fromhex(public_key), curve=ecdsa.SECP256k1)
    # print(vk.verify(bytearray.fromhex(sig), message_b)) # True

    message = {
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
             {'vasp_code': 'VASPTWTP66666', 'vasp_name': 'PAPAPAPAPAPAPAAPA', 'is_sb_need_static': True,
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

    message_str = json.dumps(message)
    print(f'message_str = {message_str}')
    message_str_b = message_str.encode(encoding='utf-8')

    # SECP256k1 is the Bitcoin elliptic curve
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha256)
    sig = sk.sign_deterministic(message_str_b)
    print('sig', sig.hex())
    vk = sk.get_verifying_key()
    public_key = vk.to_string().hex()
    print('vk', public_key)
    isValid = vk.verify(sig, message_str_b, hashfunc=sha1)
    print(isValid)
    # sig = 'eecf11ab95cfb03237cf8e27d1c654df19b367b1b120a8a167aadf417500c64cbe600e9f17f3b80834ea24bb48196b6a09b7b786b17237d6ee57be32d3832b21'
    # public_key = '44049f6dbcf630c3184c7fba083dda0870a363f8e80ab4c5c639f72f7be3d5a90138fcaa54ec038ede6a7e67780cd382f938478ff2129e5be13270fd12ba8e7e'

    # vk = ecdsa.VerifyingKey.from_string(bytearray.fromhex(public_key), curve=ecdsa.SECP256k1, hashfunc=sha256)
    # print(vk.verify(sig, message_str_b)) # True
