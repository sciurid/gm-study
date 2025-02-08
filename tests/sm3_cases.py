import unittest

from gmutil import *

class SM3TestCase(unittest.TestCase):
    def test_sm3(self):
        sample_1 = bytes.fromhex('616263')
        result_1 = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
        self.assertEqual(sm3_hash(sample_1), result_1)

        sample_2 = bytes.fromhex('61626364' * 16)
        result_2 = bytes.fromhex('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
        self.assertEqual(sm3_hash(sample_2), result_2)

    def test_sm3_digest(self):
        sm3obj = SM3Hash()
        sample_1 = bytes.fromhex('616263')
        sm3obj.update(sample_1)
        result_1 = bytes.fromhex('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
        self.assertEqual(sm3obj.digest(), result_1)

        sm3obj = SM3Hash()
        sample_2 = bytes.fromhex('61626364' * 16)
        sm3obj.update(sample_2)
        result_2 = bytes.fromhex('debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')
        self.assertEqual(sm3obj.digest(), result_2)