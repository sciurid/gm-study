from typing import Union
from unittest import TestCase
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json
import secrets
from gmutil import gcm_encrypt, gcm_decrypt, SM4, GCM, BlockCipherAlgorithm


def cipher_aes(key):
    def _cipher(message):
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(message) + encryptor.finalize()
    return _cipher


class AESAlgorithm(BlockCipherAlgorithm):

    def __init__(self, key: bytes):
        super().__init__(128)
        self._cipher = Cipher(algorithms.AES128(key), modes.ECB())

    @property
    def block_size(self) -> int:
        return 128

    def encrypt_block(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        encryptor = self._cipher.encryptor()
        return encryptor.update(in_octets) + encryptor.finalize()

    def decrypt_block(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        decryptor = self._cipher.decryptor()
        return decryptor.update(in_octets) + decryptor.finalize()


class GCMTests(TestCase):
    def test_gcm_aes(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'aes-gcm-test-vectors.json'), 'r') as f:
            test_vectors = json.load(f)
        for test_vector in test_vectors:
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])
            c, t = gcm_encrypt(cipher_aes(key), p, iv, aad)

            self.assertEqual(c, bytes.fromhex(test_vector['C']))
            self.assertEqual(t, bytes.fromhex(test_vector['T']))
            print(c.hex(), t.hex())
            r = gcm_decrypt(cipher_aes(key), iv, aad, c, t)
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

            c, t = gcm_encrypt(cipher_aes(key), message, iv, aad)
            print(c.hex(), t.hex())

            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(iv, message, aad)
            print(ct.hex())
            self.assertEqual(c + t, ct)

            gcm = GCM(AESAlgorithm(key), iv, aad)
            enc = gcm.encryptor()
            ct_ = enc.update(message) + enc.finalize()
            self.assertEqual(ct, ct_)

            dec = gcm.decryptor()
            r = dec.update(ct_) + dec.finalize()
            self.assertEqual(message, r)

    def test_sm4_gcm(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sm4-gcm-test-vectors.json'), 'r') as f:
            test_vectors = json.load(f)

        for test_vector in test_vectors:
            print('=' * 24)
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])

            sm4 = SM4(key)

            print('ENC', '-' * 20)
            c, t = gcm_encrypt(sm4.encrypt_block, p, iv, aad)
            self.assertEqual(c, bytes.fromhex(test_vector['C']))
            self.assertEqual(t, bytes.fromhex(test_vector['T']))
            print(c.hex(), t.hex())
            print('DEC', '-' * 20)
            r = gcm_decrypt(sm4.encrypt_block, iv, aad, c, t)
            self.assertEqual(r, p)
            print()


    def test_sm4_gcm_mode(self):
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sm4-gcm-test-vectors.json'), 'r') as f:
            test_vectors = json.load(f)

        for test_vector in test_vectors:
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])
            c = bytes.fromhex(test_vector['C'])
            t = bytes.fromhex(test_vector['T'])

            gcm = GCM(SM4(key), iv, aad)
            enc = gcm.encryptor()
            ct = enc.update(p) + enc.finalize()
            self.assertEqual(c + t, ct)

            dec = gcm.decryptor()
            r = dec.update(ct) + dec.finalize()
            self.assertEqual(p, r)












