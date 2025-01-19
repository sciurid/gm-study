import unittest

from gmutil import *
import sys

class KeyExchangeTests(unittest.TestCase):
    def test_simple_key_exchange(self):
        user_a = SM2KeyExchange(uid='user-a'.encode())
        user_b = SM2KeyExchange(uid='user-b'.encode())

        key_a = user_a.calculate_key(True, *user_b.send())
        key_b = user_b.calculate_key(False, *user_a.send())

        print("Key A:", key_a.hex())
        print("Key B:", key_b.hex())
        self.assertEqual(key_a, key_b)


    def test_verified_key_exchange(self):
        user_a = SM2KeyExchangePartyA(uid='user-a'.encode())
        user_b = SM2KeyExchangePartyB(uid='user-b'.encode())

        user_b.receive_1(*user_a.send_1())
        user_a.receive_2(*user_b.send_2())
        user_b.receive_3(*user_a.send_3())

        print("Key A:", user_a.exchanged_key.hex())
        print("Key B:", user_b.exchanged_key.hex())

        self.assertEqual(user_a.exchanged_key, user_b.exchanged_key)
