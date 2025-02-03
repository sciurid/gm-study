import secrets
import unittest
import logging

from gmutil.mode import *
from gmutil.sm4 import sm4_encrypt_block, sm4_decrypt_block, SM4, SM4Encryptor, SM4Decryptor
from os.path import join, abspath, pardir

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)


class SM4TestCase(unittest.TestCase):
    SECRET_KEY = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
    IV = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    MESSAGE = bytes.fromhex('6BC1BEE22E409F96E93D7E117393172A'
                            'AE2D8A571E03AC9C9EB76FAC45AF8E51'
                            '30C81C46A35CE411E5FBC1191A0A52EF'
                            'F69F2445DF4F9B17AD2B417BE66C3710')

    def test_sm4_block(self):
        # GB/T 32097-2016 A.1
        message = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
        secret_key = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
        cipher_text = sm4_encrypt_block(secret_key, message)

        self.assertEqual(cipher_text, bytes.fromhex('681EDF34 D206965E 86B3E94F 536E4246'))

        restored = sm4_decrypt_block(secret_key, cipher_text)
        self.assertEqual(message, restored)

        # GB/T 32097-2016 A.2
        # sm4 = SM4(secret_key)
        # cipher_text = message
        # for _ in range(1000000):
        #     cipher_text = sm4.encrypt_block(cipher_text)
        #     if _ % 10000 == 0:
        #         print(_)
        # self.assertEqual(cipher_text, bytes.fromhex('595298C7 C6FD271F 0402F804 C33D3F66'))

    def test_sm4_ecb(self):
        ecb = ECB(SM4(SM4TestCase.SECRET_KEY))
        ecb_assertion = ('a51411ff04a711443891fce7ab842a29',
                         'd5b50f46a9a730a0f590ffa776d99855',
                         'c9a86a4d71447f4e873ada4f388af9b9',
                         '2b25557b50514d155939e6ec940ad90e')

        logger.debug('=' * 20 + 'ECB ENCRYPTION' + '=' * 20)
        cipher_text = bytearray()
        enc = ecb.encryptor()

        for i in range(4):
            cipher_block = enc.update(SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            self.assertEqual(cipher_block, bytes.fromhex(ecb_assertion[i]))
            cipher_text.extend(cipher_block)
            print(cipher_block.hex())
        cipher_block = enc.finalize()
        self.assertEqual(cipher_block, b'')
        cipher_text.extend(cipher_block)
        print(cipher_block.hex())

        logger.debug('=' * 20 + 'ECB DECRYPTION' + '=' * 20)
        dec = ecb.decryptor()
        restored = bytearray()
        for i in range(4):
            restored_block = dec.update(cipher_text[i * 16: (i + 1) * 16])
            self.assertEqual(restored_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            restored.extend(restored_block)
            print(restored_block.hex())
        restored_block = dec.finalize()
        restored.extend(restored_block)
        print(restored_block.hex())

    def test_sm4_cbc(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        cbc = CBC(sm4, SM4TestCase.IV)

        cbc_assertion = ('AC529AF989A62FCE9CDDC5FFB84125CA',
                         'B168DD69DB3C0EEA1AB16DE6AEA43C59',
                         '2C15567BFF8F707486C202C7BE59101F',
                         '74A629B350CD7E11BE99998AF5206D6C')

        logger.debug('=' * 20 + 'CBC ENCRYPTION' + '=' * 20)
        enc = cbc.encryptor()
        cipher_text = bytearray()
        for i in range(4):
            in_block = SM4TestCase.MESSAGE[i * 16: (i + 1) * 16]
            logger.debug('Plain:  {}'.format(in_block.hex()))
            cipher_block = enc.update(in_block)
            cipher_text.extend(cipher_block)
            logger.debug('Cipher: {}'.format(cipher_block.hex()))
            self.assertEqual(bytes.fromhex(cbc_assertion[i]), cipher_block)
        cipher_block = enc.finalize()
        self.assertEqual(b'', cipher_block)
        print(cipher_block.hex())
        cipher_text.extend(cipher_block)

        logger.debug('=' * 20 + 'CBC DECRYPTION' + '=' * 20)
        dec = cbc.decryptor()
        restored = bytearray()
        for i in range(4):
            restore_block = dec.update(cipher_text[i * 16: (i + 1) * 16])
            self.assertEqual(restore_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            logger.debug('Restored:{}'.format(restore_block.hex()))
            restored.extend(restore_block)
        restore_block = dec.finalize()
        self.assertEqual(b'', restore_block)
        restored.extend(restore_block)
        self.assertEqual(SM4TestCase.MESSAGE, restored)

    IV_COUNTER = bytes.fromhex('F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF')

    def test_sm4_ctr(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        ctr = CTR(SM4TestCase.IV_COUNTER, sm4)


        enc_assertion = ('14AE4A72B97A93CE1216CCD998E371C1',
                         '60F7EF8B6344BD6DA1992505E5FC219B',
                         '0BF057F86C5D75103C0F46519C7FB2E7',
                         '292805035ADB9A90ECEF145359D7CF0E')

        logger.debug('=' * 20 + 'CTR ENCRYPTION' + '=' * 20)
        enc = ctr.encryptor()
        cipher_text = bytearray()
        for i in range(4):
            cipher_block = enc.update(SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            cipher_text.extend(cipher_block)
            self.assertEqual(cipher_block, bytes.fromhex(enc_assertion[i]))
        cipher_block = enc.finalize()
        cipher_text.extend(cipher_block)
        self.assertEqual(b'', cipher_block)

        logger.debug('=' * 20 + 'CTR DECRYPTION' + '=' * 20)
        dec = ctr.decryptor()
        restored = bytearray()
        for i in range(4):
            restored_block = dec.update(cipher_text[i * 16: (i + 1) * 16])
            restored.extend(restored_block)
            self.assertEqual(restored_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
        restored_block = dec.finalize()
        restored.extend(restored_block)
        self.assertEqual(b'', restored_block)

        self.assertEqual(SM4TestCase.MESSAGE, restored)

    def test_sm4_cfb8(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)

        message = bytes.fromhex('6b c1 be e2 2e 40 9f 96')
        enc_assertion = bytes.fromhex('bc 98 b6 9c 0b 3a c8 7b')

        cfb = CFB(SM4TestCase.IV, sm4, 1)

        logger.debug('=' * 20 + 'CFB8 ENCRYPTION' + '=' * 20)
        enc = cfb.encryptor()
        cipher_text = bytearray()
        for i in range(len(message)):
            cipher_block = enc.update(message[i:i+1])
            cipher_text.extend(cipher_block)
            self.assertEqual(cipher_block, enc_assertion[i:i+1])
        cipher_block = enc.finalize()
        cipher_text.extend(cipher_block)
        self.assertEqual(b'', cipher_block)
        print(cipher_text.hex())

        dec = cfb.decryptor()
        restored = bytearray()
        logger.debug('=' * 20 + 'CFB8 DECRYPTION' + '=' * 20)
        for i in range(len(message)):
            restored_block = dec.update(cipher_text[i:i+1])
            restored.extend(restored_block)
            self.assertEqual(restored_block, message[i:i+1])
        restored_block = dec.finalize()
        restored.extend(restored_block)
        self.assertEqual(b'', restored_block)
        print(restored.hex())

        self.assertEqual(restored, message)

    def test_sm4_ofb128(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        ofb = OFB(SM4TestCase.IV, sm4, 16)

        enc_assertion = ('bc710d762d070b26361da82b54565e46',
                         '07a0c62834740ad3240d239125e11621',
                         'd476b21cc9f04951f0741d2ef9e09498',
                         '1584fc142bf13aa626b82f9d7d076cce')

        logger.debug('=' * 20 + 'OFB128 ENCRYPTION' + '=' * 20)
        enc = ofb.encryptor()
        cipher_text = bytearray()
        for i in range(4):
            cipher_block = enc.update(SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            cipher_text.extend(cipher_block)
            # print(cipher_block.hex())
            self.assertEqual(cipher_block, bytes.fromhex(enc_assertion[i]))
        cipher_block = enc.finalize()
        cipher_text.extend(cipher_block)
        self.assertEqual(b'', cipher_block)
        print(cipher_text.hex())

        logger.debug('=' * 20 + 'CTR DECRYPTION' + '=' * 20)
        dec = ofb.decryptor()
        restored = bytearray()
        for i in range(4):
            restored_block = dec.update(cipher_text[i * 16: (i + 1) * 16])
            restored.extend(restored_block)
            self.assertEqual(restored_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
        restored_block = dec.finalize()
        restored.extend(restored_block)
        self.assertEqual(b'', restored_block)
        print(restored.hex())
        self.assertEqual(SM4TestCase.MESSAGE, restored)

    def test_sm4_xts(self):
        secret_key = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
        tweak_key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        tweak = bytes.fromhex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')
        message = bytes.fromhex('6BC1BEE22E409F96E93D7E117393172A'
                                'AE2D8A571E03AC9C9EB76FAC45AF8E51'
                                '30C81C46A35CE411E5FBC1191A0A52EF'
                                'F69F2445DF4F9B17')

        xts = XTS(SM4(secret_key), tweak, SM4(tweak_key))

        logger.debug('=' * 20 + 'XTS ENCRYPTION' + '=' * 20)
        enc = xts.encryptor()
        cipher_text = enc.update(message) + enc.finalize()
        print(cipher_text.hex())

        logger.debug('=' * 20 + 'XTS DECRYPTION' + '=' * 20)
        dec = xts.decryptor()
        restored = dec.update(cipher_text) + dec.finalize()
        print(restored.hex())

        self.assertEqual(message.hex(), restored.hex())

    def test_sm4_simple_case(self):
        plain_text = '飞流直下三千尺，疑似银河落九天。'.encode('utf-8')
        secret_key = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)
        iv = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)

        encryptor = SM4Encryptor(secret_key, 'CBC', 'PKCS7', iv=iv)
        cipher_text = encryptor.update(plain_text) + encryptor.finalize()
        print(cipher_text.hex())

        decryptor = SM4Decryptor(secret_key, 'CBC', 'PKCS7', iv=iv)
        restored = decryptor.update(cipher_text) + decryptor.finalize()
        print(restored.decode('utf-8'))

    def do_test_text(self, data, secret_key, iv_tweak, tweak_key, mode_name, padding_name):
        logger.debug('=' * 20 + f"SM4 {mode_name} {padding_name}" + '=' * 20)
        tweak_algorithm = SM4(tweak_key)
        encryptor = SM4Encryptor(secret_key, mode_name, padding_name,
                                 iv=iv_tweak, tweak=iv_tweak, tweak_algorithm=tweak_algorithm)
        decryptor = SM4Decryptor(secret_key, mode_name, padding_name,
                                 iv=iv_tweak, tweak=iv_tweak, tweak_algorithm=tweak_algorithm)
        logger.debug('Secret   :' + secret_key.hex())
        cipher_text = encryptor.update(data) + encryptor.finalize()
        logger.debug('Encrypted:' + cipher_text.hex())

        restored = decryptor.update(cipher_text) + decryptor.finalize()
        print(restored.decode('utf-8'))
        self.assertEqual(data, restored)

    def test_text(self):
        with open(join(abspath(join(__file__, pardir)), 'DFB.txt'), 'rb') as f:
            data = f.read()

        secret_key = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)
        tweak_key = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)
        iv_tweak = secrets.randbits(SM4.BLOCK_SIZE).to_bytes(16, byteorder='big', signed=False)

        for mode in ('ECB', 'CBC', 'CFB8', 'CFB128', 'OFB8', 'OFB128', 'CTR', 'XTS', 'GCM'):
            for padding in ('PKCS7', 'ISO9797M2'):
                self.do_test_text(data, secret_key, iv_tweak, tweak_key, mode, padding)
