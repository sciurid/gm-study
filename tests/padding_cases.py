from unittest import TestCase
from gmutil import *
import logging

logging.basicConfig(level=logging.DEBUG)


class PaddingCases(TestCase):
    def test_padding(self):
        sample_0 = b''
        sample_1 = bytes.fromhex('00112233445566778899')
        sample_2 = bytes.fromhex('00112233445566778899aabbccddeeff')

        padding_10 = bytes.fromhex('10' * 16)
        padding_11 = bytes.fromhex('00112233445566778899060606060606')
        padding_12 = bytes.fromhex('00112233445566778899aabbccddeeff10101010101010101010101010101010')

        self.assertEqual(pkcs7_pad(sample_0, 128), padding_10)
        self.assertEqual(pkcs7_unpad(padding_10, 128), sample_0)
        self.assertEqual(pkcs7_pad(sample_1, 128), padding_11)
        self.assertEqual(pkcs7_unpad(padding_11, 128), sample_1)
        self.assertEqual(pkcs7_pad(sample_2, 128), padding_12)
        self.assertEqual(pkcs7_unpad(padding_12, 128), sample_2)

        padding_20 = bytes.fromhex('80000000000000000000000000000000')
        padding_21 = bytes.fromhex('00112233445566778899800000000000')
        padding_22 = bytes.fromhex('00112233445566778899aabbccddeeff'
                                   '80000000000000000000000000000000')

        self.assertEqual(one_and_zeros_pad(sample_0, 128), padding_20)
        self.assertEqual(one_and_zeros_unpad(padding_20, 128), sample_0)
        self.assertEqual(one_and_zeros_pad(sample_1, 128), padding_21)
        self.assertEqual(one_and_zeros_unpad(padding_21, 128), sample_1)
        self.assertEqual(one_and_zeros_pad(sample_2, 128), padding_22)
        self.assertEqual(one_and_zeros_unpad(padding_22, 128), sample_2)

        padding_30 = bytes.fromhex('00' * 32)
        padding_31 = bytes.fromhex('0000000000000000000000000000005000112233445566778899000000000000')
        padding_32 = bytes.fromhex('0000000000000000000000000000008000112233445566778899aabbccddeeff')

        self.assertEqual(length_prefixed_pad(sample_0, 128), padding_30)
        self.assertEqual(length_prefixed_pad(sample_1, 128), padding_31)
        self.assertEqual(length_prefixed_pad(sample_2, 128), padding_32)





