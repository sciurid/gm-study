import unittest
import logging

from THUCard.realtime_verify import SECRET_KEY
from gmutil.mode import ECB, CBC, CTR
from gmutil.sm4 import sm4_encrypt_block, sm4_decrypt_block, SM4

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
        secrets = bytes.fromhex('01234567 89ABCDEF FEDCBA98 76543210')
        cipher_text = sm4_encrypt_block(message, secrets)

        self.assertEqual(cipher_text, bytes.fromhex('681EDF34 D206965E 86B3E94F 536E4246'))

        restored = sm4_decrypt_block(cipher_text, secrets)
        self.assertEqual(message, restored)

        # GB/T 32097-2016 A.2
        sm4 = SM4(secrets)
        cipher_text = message
        for _ in range(1000000):
            cipher_text = sm4.encrypt_block(cipher_text)
            if _ % 10000 == 0:
                print(_)
        self.assertEqual(cipher_text, bytes.fromhex('595298C7 C6FD271F 0402F804 C33D3F66'))

    def test_sm4_ecb(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        ecb = ECB(sm4.encrypt_block, 128)

        ecb_assertion = ('a51411ff04a711443891fce7ab842a29',
                         'd5b50f46a9a730a0f590ffa776d99855',
                         'c9a86a4d71447f4e873ada4f388af9b9',
                         '2b25557b50514d155939e6ec940ad90e')

        logger.debug('=' * 20 + 'ECB ENCRYPTION' + '=' * 20)
        cipher_text = bytearray()
        for i in range(4):
            cipher_block = ecb.update(SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            self.assertEqual(cipher_block, bytes.fromhex(ecb_assertion[i]))
            cipher_text.extend(cipher_block)
            print(cipher_block.hex())
        cipher_block = ecb.finalize()
        self.assertEqual(cipher_block, b'')
        cipher_text.extend(cipher_block)
        print(cipher_block.hex())

        logger.debug('=' * 20 + 'ECB DECRYPTION' + '=' * 20)
        ecb = ECB(sm4.decrypt_block, 128)
        restored = bytearray()
        for i in range(4):
            restore_block = ecb.update(cipher_text[i * 16: (i + 1) * 16])
            self.assertEqual(restore_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            restored.extend(restore_block)
            print(restore_block.hex())

    def test_sm4_cbc(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        cbc = CBC(sm4.encrypt_block, 128, iv=SM4TestCase.IV, is_encrypt=True)

        logger.debug('=' * 20 + 'CBC ENCRYPTION' + '=' * 20)

        cbc_assertion = ('AC529AF989A62FCE9CDDC5FFB84125CA',
                         'B168DD69DB3C0EEA1AB16DE6AEA43C59',
                         '2C15567BFF8F707486C202C7BE59101F',
                         '74A629B350CD7E11BE99998AF5206D6C')

        cipher_text = bytearray()
        for i in range(4):
            in_block = SM4TestCase.MESSAGE[i * 16: (i + 1) * 16]
            logger.debug('Plain:  {}'.format(in_block.hex()))
            cipher_block = cbc.update(in_block)
            cipher_text.extend(cipher_block)
            logger.debug('Cipher: {}'.format(cipher_block.hex()))
            self.assertEqual(bytes.fromhex(cbc_assertion[i]), cipher_block)
        cipher_block = cbc.finalize()
        self.assertEqual(b'', cipher_block)
        print(cipher_block.hex())
        cipher_text.extend(cipher_block)

        logger.debug('=' * 20 + 'CBC DECRYPTION' + '=' * 20)
        cbc = CBC(sm4.decrypt_block, 128, iv=SM4TestCase.IV, is_encrypt=False)
        restored = bytearray()
        for i in range(4):
            restore_block = cbc.update(cipher_text[i * 16: (i + 1) * 16])
            self.assertEqual(restore_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            logger.debug('Restored:{}'.format(restore_block.hex()))
            restored.extend(restore_block)
        restore_block = cbc.finalize()
        self.assertEqual(b'', restore_block)
        restored.extend(restore_block)
        self.assertEqual(SM4TestCase.MESSAGE, restored)

    IV_COUNTER = bytes.fromhex('F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF')

    def test_sm4_ctr(self):
        sm4 = SM4(SM4TestCase.SECRET_KEY)
        ctr = CTR(sm4.encrypt_block, 128, iv=SM4TestCase.IV_COUNTER)

        logger.debug('=' * 20 + 'CTR ENCRYPTION' + '=' * 20)
        enc_assertion = ('14AE4A72B97A93CE1216CCD998E371C1',
                         '60F7EF8B6344BD6DA1992505E5FC219B',
                         '0BF057F86C5D75103C0F46519C7FB2E7',
                         '292805035ADB9A90ECEF145359D7CF0E')
        cipher_text = bytearray()
        for i in range(4):
            cipher_block = ctr.update(SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
            cipher_text.extend(cipher_block)
            self.assertEqual(cipher_block, bytes.fromhex(enc_assertion[i]))
        cipher_block = ctr.finalize()
        cipher_text.extend(cipher_block)
        self.assertEqual(b'', cipher_block)

        logger.debug('=' * 20 + 'CTR DECRYPTION' + '=' * 20)
        ctr = CTR(sm4.encrypt_block, 128, iv=SM4TestCase.IV_COUNTER)
        restored = bytearray()
        for i in range(4):
            restored_block = ctr.update(cipher_text[i * 16: (i + 1) * 16])
            restored.extend(restored_block)
            self.assertEqual(restored_block, SM4TestCase.MESSAGE[i * 16: (i + 1) * 16])
        restored_block = ctr.finalize()
        restored.extend(restored_block)
        self.assertEqual(b'', restored_block)

        self.assertEqual(SM4TestCase.MESSAGE, restored)


    def test_encrypt_text(self):
        with open('DFB.txt', 'rb') as f:
            cipher = SM4(secret_key=SECRET_KEY)
            while data := r.read():
                cipher.encrypt()

        