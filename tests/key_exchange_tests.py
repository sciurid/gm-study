import unittest

from gmutil import *


class KeyExchangeTests(unittest.TestCase):
    def test_key_exchange(self):
        user_a = SM2KeyExchange(uid='user-a@tsinghua.edu.cn'.encode())
        user_b = SM2KeyExchange(uid='user-b@tsinghua.edu.cn'.encode())

        k_byte_len = 16
        key_b = user_b.receive(user_a.public_key, user_a.point_r, user_a.uid, k_byte_len, False)
        key_a = user_a.receive(user_b.public_key, user_b.point_r, user_b.uid, k_byte_len, True)

        print("Key A:", key_a.hex())
        print("Key B:", key_b.hex())
        self.assertEqual(key_a, key_b)


