from unittest import TestCase
from gmutil import sm3_hash, SM4, sm4_decrypt_block, sm4_encrypt_block
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT


class GBTCheck(TestCase):
    def test_sm3(self):
        sample_1 = bytes.fromhex('616263')
        result_1 = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
        self.assertEqual(sm3_hash(sample_1), result_1)

        sample_2 = bytes.fromhex('61626364' * 16)
        result_2 = bytes.fromhex('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
        self.assertEqual(sm3_hash(sample_2), result_2)

    def test_sm4(self):
        # GB/T 32097-2016 A.1
        message = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
        secrets = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
        cipher_text = sm4_encrypt_block(message, secrets)

        self.assertEqual(cipher_text, bytes.fromhex('681EDF34 D206965E 86B3E94F 536E4246'))

        restored = sm4_decrypt_block(cipher_text, secrets)
        self.assertEqual(message, restored)

        # GB/T 32097-2016 A.2
        sm4 = SM4(secrets)
        cipher_text = message
        for _ in range(1000000):
            cipher_text = sm4.encrypt_block(cipher_text)
            if _ % 10000 == 0:
                print(_)
        self.assertEqual(cipher_text, bytes.fromhex('595298C7 C6FD271F 0402F804 C33D3F66'))

    def test_sm4_bug(self):
        key = b'\x00' * 16
        message = b'\x00' * 15 + b'\x01'

        crypt_sm4 = CryptSM4()
        crypt_sm4.set_key(key, SM4_ENCRYPT)
        e = crypt_sm4.crypt_ecb(message)
        print(e.hex(' '))

        s = sm4_encrypt_block(message, key)
        print(s.hex(' '))



