import unittest
from gmutil import *

class SM2TestCase(unittest.TestCase):
    def test_signature(self, message = 'A fox jumps over the lazy dog.'):
        print("Message:", message.encode().hex())

        prikey = SM2PrivateKey()
        print("Private Key:", prikey.to_bytes().hex())
        signature = prikey.sign(message.encode())
        print("Signature:", signature.hex().upper())

        pubkey = prikey.get_public_key()
        print("Public Key:", pubkey)
        self.assertTrue(pubkey.verify(message.encode(), signature))

    def test_encryption(self, message = 'A fox jumps over the lazy dog.'):
        print("Message:", message.encode('ascii').hex())

        start_time = datetime.now()
        for _ in range(100):
            prikey = SM2PrivateKey()
            print("Private Key:", prikey.to_bytes().hex())
            pubkey = prikey.get_public_key()
            print("Public Key:", pubkey)

            cipher_text = pubkey.encrypt(message.encode())
            print("Cipher Text:", cipher_text.hex().upper())

            recovered = prikey.decrypt(cipher_text)
            print("Recovered:", recovered.hex().upper())
            print("Message:", recovered.decode('ascii'))

            self.assertEqual(message, recovered.decode('ascii'))
        end_time = datetime.now()
        t1 = end_time - start_time

        start_time = datetime.now()
        for _ in range(100):
            cipher_text = pubkey.encrypt(message.encode())
            print("Cipher Text:", cipher_text.hex().upper())

            recovered = prikey.decrypt(cipher_text)
            print("Recovered:", recovered.hex().upper())
            print("Message:", recovered.decode('ascii'))
            self.assertEqual(message, recovered.decode('ascii'))
        end_time = datetime.now()
        t2 = end_time - start_time
        print(t1, t2)

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



