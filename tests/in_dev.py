from unittest import TestCase

from gmutil.calculation import *
from gmutil.sm4 import *

class InDevelopmentTestCase(TestCase):
    def test_dev_xts(self):
        key_1 = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
        key_2 = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        tw = bytes.fromhex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')

        ek_tw_1 = sm4_encrypt_block(message=tw, secret_key=key_2)
        print(ek_tw_1.hex())
        p_1 = bytes.fromhex('6BC1BEE22E409F96E93D7E117393172A')

        input_1 = xor_on_bytes(p_1, ek_tw_1)
        print(input_1.hex())   # 数据加密分组密码输入分组
        output_1 = sm4_encrypt_block(input_1, secret_key=key_1)
        print(output_1.hex())  # 数据加密分组密码输出分组
        c_1 = xor_on_bytes(output_1, ek_tw_1)
        print(c_1.hex())

        print()

        p_2 = bytes.fromhex('AE2D8A571E03AC9C9EB76FAC45AF8E51')
        # 0b11100001 << 120
        ek_tw_2 = (mul_gf_2_128(int.from_bytes(ek_tw_1, byteorder='big', signed=False), 1 << 126, False)
                   .to_bytes(16, byteorder='big', signed=False))
        print(ek_tw_2.hex())

        input_2 = xor_on_bytes(p_2, ek_tw_2)
        print(input_2.hex())  # 数据加密分组密码输入分组
        output_2 = sm4_encrypt_block(input_2, secret_key=key_1)
        print(output_2.hex())  # 数据加密分组密码输出分组
        c_2 = xor_on_bytes(output_2, ek_tw_2)
        print(c_2.hex())

        print()

        p_3 = bytes.fromhex('30C81C46A35CE411E5FBC1191A0A52EF')
        # 0b11100001 << 120
        ek_tw_3 = (mul_gf_2_128(int.from_bytes(ek_tw_2, byteorder='big', signed=False), 1 << 126, False)
                   .to_bytes(16, byteorder='big', signed=False))
        print(ek_tw_3.hex())

        input_3 = xor_on_bytes(p_3, ek_tw_3)
        print(input_3.hex())  # 数据加密分组密码输入分组
        output_3 = sm4_encrypt_block(input_3, secret_key=key_1)
        print(output_3.hex())  # 数据加密分组密码输出分组
        c_3 = xor_on_bytes(output_3, ek_tw_3)
        print(c_3.hex())

        print()
        tc1 = bytes.fromhex('EA634CBAA69DC60CC54F5E25855CA646')
        c1 = sm4_decrypt_block(tc1, secret_key=key_1)
        tc2 = bytes.fromhex('2f3a089f84eed57b1091d6fe70fd4c6e')
        c2 = sm4_decrypt_block(tc2, secret_key=key_1)
        print(c1.hex())
        print(c2.hex())
        assert c1 == c2


        ti = bytes.fromhex('68129ef66eba455945f0a7c6740527cc')
        print(sm4_encrypt_block(ti, secret_key=key_1).hex())







