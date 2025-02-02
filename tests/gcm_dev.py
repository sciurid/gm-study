from unittest import TestCase

import pylab as p

from gmutil import uint128_to_bytes, bytes_to_uint128, ZEROS_128, ghash, uint_incr
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from typing import Tuple, Optional


def gctr(ciph, key, icb, message) -> bytes:
    lm = len(message)
    if lm == 0:
        return b''
    n = ((lm - 1) // 16) + 1

    message = message if isinstance(message, memoryview) else memoryview(message)

    cb = bytearray(icb)
    begin = 0
    end = 16
    buffer = bytearray()
    for _ in range(n - 1):
        print("CB:", cb.hex())
        ek_cb = ciph(key, cb)
        print("EK_CB:", ek_cb.hex())
        block = uint128_to_bytes(bytes_to_uint128(ek_cb) ^ bytes_to_uint128(message[begin:end]))
        print("CIPHER_BLOCK:", block.hex())
        buffer.extend(block)
        begin = end
        end = begin + 16
        uint_incr(cb)

    padding = end - lm
    last = bytearray(message[begin:])
    last.extend(b'\x00' * padding)
    print("CB:", cb.hex())
    ek_cb = ciph(key, cb)
    print("EK_CB:", ek_cb.hex())
    block = uint128_to_bytes(bytes_to_uint128(ek_cb) ^ bytes_to_uint128(last))[0: lm-begin]
    print("CIPHER_BLOCK:", block.hex())
    buffer.extend(block)

    return bytes(buffer)


def gcm_j0(h, iv):
    if (liv := len(iv)) == 12:
        return iv + b'\x00\x00\x00\x01'
    else:
        return uint128_to_bytes(ghash(key_h=h, w=b'', z=iv))


def gcm_encrypt(ciph, key, message, iv, auth_data) -> Tuple[bytes, bytes]:
    key_h = ciph(key, ZEROS_128)
    print('H:', key_h.hex())
    j0 = gcm_j0(key_h, iv)
    icb = bytearray(j0)
    print("ICB:", icb.hex())
    uint_incr(icb)
    c = gctr(ciph, key, icb, message)
    s = uint128_to_bytes(ghash(key_h, auth_data, c))
    print("GHASH(H,A,C):", s.hex())
    t = gctr(ciph, key, j0, s)
    print("C:", c.hex())
    print("T:", t.hex())
    return c, t


def gcm_decrypt(ciph, key, iv, auth_data, cipher_text, auth_tag) -> Optional[bytes]:
    key_h = ciph(key, ZEROS_128)
    print('H:', key_h.hex())
    j0 = gcm_j0(key_h, iv)
    icb = bytearray(j0)
    print("ICB:", icb.hex())
    uint_incr(icb)
    p = gctr(ciph, key, icb, cipher_text)
    print("P:", p.hex())

    s = uint128_to_bytes(ghash(key_h, auth_data, cipher_text))
    t = gctr(ciph, key, j0, s)
    if auth_tag == t:
        return p
    else:
        return None



TEST_VECTORS = (
    {
        'K': '00000000000000000000000000000000',
        'P': '',
        'IV': '000000000000000000000000',
        'A': '',
        'C': '',
        'T': '58e2fccefa7e3061367f1d57a4e7455a'
    },
    {
        'K': '00000000000000000000000000000000',
        'P': '00000000000000000000000000000000',
        'IV': '000000000000000000000000',
        'A': '',
        'C': '0388dace60b6a392f328c2b971b2fe78',
        'T': 'ab6e47d42cec13bdf53a67b21257bddf'
    },
    {
        'K': 'feffe9928665731c6d6a8f9467308308',
        'P': 'd9313225f88406e5a55909c5aff5269a'
             '86a7a9531534f7da2e4c303d8a318a72'
             '1c3c0c95956809532fcf0e2449a6b525'
             'b16aedf5aa0de657ba637b391aafd255',
        'IV': 'cafebabefacedbaddecaf888',
        'A': '',
        'C': '42831ec2217774244b7221b784d0d49c'
             'e3aa212f2c02a4e035c17e2329aca12e'
             '21d514b25466931c7d8f6a5aac84aa05'
             '1ba30b396a0aac973d58e091473f5985',
        'T': '4d5c2af327cd64a62cf35abd2ba6fab4'
    },
    {
        'K': 'feffe9928665731c6d6a8f9467308308',
        'P': 'd9313225f88406e5a55909c5aff5269a'
             '86a7a9531534f7da2e4c303d8a318a72'
             '1c3c0c95956809532fcf0e2449a6b525'
             'b16aedf5aa0de657ba637b39',
        'IV': 'cafebabefacedbaddecaf888',
        'A': 'feedfacedeadbeeffeedfacedeadbeef'
             'abaddad2',
        'C': '42831ec2217774244b7221b784d0d49c'
             'e3aa212f2c02a4e035c17e2329aca12e'
             '21d514b25466931c7d8f6a5aac84aa05'
             '1ba30b396a0aac973d58e091',
        'T': '5bc94fbc3221a5db94fae95ae7121a47'
    },
)


def aes_encrypt(key, message):
    cipher = Cipher(algorithms.AES128(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(message) + encryptor.finalize()

class GCMTests(TestCase):
    def test_gcm_encrypt(self):
        for test_vector in TEST_VECTORS:
            print('=' * 24)
            key = bytes.fromhex(test_vector['K'])
            p = bytes.fromhex(test_vector['P'])
            iv = bytes.fromhex(test_vector['IV'])
            aad = bytes.fromhex(test_vector['A'])
            print('ENC', '-' * 20)
            c, t = gcm_encrypt(aes_encrypt, key, p, iv, aad)
            self.assertEqual(c, bytes.fromhex(test_vector['C']))
            self.assertEqual(t, bytes.fromhex(test_vector['T']))
            print(c.hex(), t.hex())
            print('DEC', '-' * 20)
            r = gcm_decrypt(aes_encrypt, key, iv, aad, c, t)
            self.assertEqual(r, p)
            print()

            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(iv, p, aad)
            print(ct.hex())

    def test_pyca_aesgcm(self):
        key = uint128_to_bytes(secrets.randbits(128))
        iv = secrets.randbits(128).to_bytes(length=16, byteorder='big', signed=False)
        message = 'A fox jumps over a lazy dog.'.encode()
        aad = 'Hello world!'.encode()

        c, t = gcm_encrypt(aes_encrypt, key, message, iv, aad)
        print(c.hex(), t.hex())

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(iv, message, aad)
        print(ct.hex())









