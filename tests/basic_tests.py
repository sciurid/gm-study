from unittest import TestCase, skip
from cryptography.hazmat.primitives.hashes import Hash, SM3
from gmutil import *
import logging

logging.basicConfig(level=logging.DEBUG)

def primes(n):
    out = list()
    sieve = [True] * (n+1)
    for p in range(2, n+1):
        if sieve[p]:
            out.append(p)
            for i in range(p, n+1, p):
                sieve[i] = False
    return out


class FundamentalTests(TestCase):
    def test_pow_mod(self):
        n = 127
        for k in range(1000):
            res = p_pow(n, k)
            cmp = n ** k % ECC_P
            self.assertEqual(res, cmp)

    def test_square_root_mod_prime(self):
        for p in primes(100)[1:]:
            for n in range(0, p):
                q = square_root_mod_prime(p, n)
                if q is not None:
                    print(p, n, q, q ** 2 % p - n)
                    self.assertEqual(q ** 2 % p,  n)
                else:
                    for i in range(p):
                        self.assertNotEqual(i ** 2 % p, n)

    def test_ex_gcd(self):
        n = p_mul(2, ECC_Y)
        p = ECC_P
        i = inverse_mod_prime(p, n)
        print(i)
        self.assertEqual((n * i) % p, 1)

    def test_point_operators(self):
        g = SM2Point(ECC_X, ECC_Y)
        print(g)

        s = g + g
        print(s)
        self.assertTrue(on_curve(s._x, s._y))

        t = s + g
        print(t)
        self.assertTrue(on_curve(t._x, t._y))

        r = g * 3
        print(r)
        self.assertTrue(on_curve(r._x, r._y))
        self.assertEqual(t, r)

        for _ in range(10):
            n = secrets.randbelow(ECC_N)
            print(n)
            p = g * n
            print(p)
            self.assertTrue(on_curve(p._x, p._y))

    def test_signature(self, message = 'A fox jumps over the lazy dog.'):
        prikey = SM2PrivateKey()
        pubkey = prikey.get_public_key()

        print(message.encode().hex())

        print(pubkey.point.x_octets.hex(), pubkey.point.y_octets.hex())
        signature = prikey.sign(message.encode())
        print(signature.hex().upper())

        self.assertTrue(pubkey.verify(message.encode(), signature))

    def test_encryption(self, message = 'A fox jumps over the lazy dog.'):
        # 加密
        prikey = SM2PrivateKey()
        pubkey = prikey.get_public_key()

        print(prikey)
        print(pubkey)
        c = pubkey.encrypt(message.encode())
        print(c.hex().upper())

        recovered = prikey.decrypt(c)
        self.assertEqual(message.encode(), recovered)









