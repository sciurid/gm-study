from unittest import TestCase
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import secrets
from gmutil import gcm_encrypt, gcm_decrypt, sm4_encrypt_block

def aes_encrypt(key, message):
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()


class GCMTests(TestCase):
    def test_gcm_aes(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'aes-gcm-test-vectors.json'), 'r') as f:
            test_vectors = json.load(f)
        for test_vector in test_vectors:
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])
            c, t = gcm_encrypt(aes_encrypt, key, p, iv, aad)

            self.assertEqual(c, bytes.fromhex(test_vector['C']))
            self.assertEqual(t, bytes.fromhex(test_vector['T']))
            print(c.hex(), t.hex())
            r = gcm_decrypt(aes_encrypt, key, iv, aad, c, t)
            self.assertEqual(r, p)

            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(iv, p, aad)
            print(ct.hex())
            self.assertEqual(c + t, ct)

    def test_pyca_aesgcm(self):
        for _ in range(100):
            key = secrets.randbits(128).to_bytes(length=16, byteorder='big', signed=False)
            iv = secrets.randbits(128).to_bytes(length=16, byteorder='big', signed=False)
            message = 'A fox jumps over a lazy dog.'.encode()
            aad = 'Hello world!'.encode()

            c, t = gcm_encrypt(aes_encrypt, key, message, iv, aad)
            print(c.hex(), t.hex())

            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(iv, message, aad)
            print(ct.hex())
            self.assertEqual(c + t, ct)

    def test_sm4_gcm(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sm4-gcm-test-vectors.json'), 'r') as f:
            test_vectors = json.load(f)

        for test_vector in test_vectors:
            print('=' * 24)
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])
            print('ENC', '-' * 20)
            c, t = gcm_encrypt(sm4_encrypt_block, key, p, iv, aad)
            self.assertEqual(c, bytes.fromhex(test_vector['C']))
            self.assertEqual(t, bytes.fromhex(test_vector['T']))
            print(c.hex(), t.hex())
            print('DEC', '-' * 20)
            r = gcm_decrypt(sm4_encrypt_block, key, iv, aad, c, t)
            self.assertEqual(r, p)
            print()










