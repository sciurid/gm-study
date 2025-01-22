from unittest import TestCase
from gmutil import sm3_hash, SM4, sm4_decrypt_block, sm4_encrypt_block, p_add
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT
from gmutil.padding import pkcs7_padding, length_prefixed_padding, bit_based_padding


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


    def test_padding(self):
        sample_0 = b''
        sample_1 = bytes.fromhex('00112233445566778899')
        sample_2 = bytes.fromhex('00112233445566778899aabbccddeeff')

        padding_10 = bytes.fromhex('10' * 16)
        padding_11 = bytes.fromhex('00112233445566778899060606060606')
        padding_12 = bytes.fromhex('00112233445566778899aabbccddeeff10101010101010101010101010101010')

        self.assertEqual(pkcs7_padding(sample_0, 128), padding_10)
        self.assertEqual(pkcs7_padding(sample_1, 128), padding_11)
        self.assertEqual(pkcs7_padding(sample_2, 128), padding_12)

        padding_20 = bytes.fromhex('80000000000000000000000000000000')
        padding_21 = bytes.fromhex('00112233445566778899800000000000')
        padding_22 = bytes.fromhex('00112233445566778899aabbccddeeff80000000000000000000000000000000')

        self.assertEqual(bit_based_padding(sample_0, 128), padding_20)
        self.assertEqual(bit_based_padding(sample_1, 128), padding_21)
        self.assertEqual(bit_based_padding(sample_2, 128), padding_22)

        padding_30 = bytes.fromhex('00' * 32)
        padding_31 = bytes.fromhex('0000000000000000000000000000005000112233445566778899000000000000')
        padding_32 = bytes.fromhex('0000000000000000000000000000008000112233445566778899aabbccddeeff'
                                   '00000000000000000000000000000000')

        self.assertEqual(length_prefixed_padding(sample_0, 128), padding_30)
        self.assertEqual(length_prefixed_padding(sample_1, 128), padding_31)
        self.assertEqual(length_prefixed_padding(sample_2, 128), padding_32)




