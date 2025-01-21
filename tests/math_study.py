from unittest import TestCase



class PolynomialOperation(TestCase):
    # {GF(2^8)的本原多项式m(x)=x^8+x^4+x^3+x+1

    def multiply_mod(self, a: int, b: int) -> int:
        intermediates = [a]
        _last = a
        for i in range(7):
            if _last & 0x80 == 0:
                _next = (_last << 1) & 0xff
            else:
                _next = (_last << 1) & 0xff ^ 0x1b
            intermediates.append(_next)
            _last = _next

        # print("Intermediates:", [f'{i:08b}' for i in intermediates])
        res = 0
        for i in range(8):
            if b & 0x01 != 0:
                res ^= intermediates[i]
            b >>= 1
        return res

    def test_sample_p94(self):
        a = 0x57
        b = 0x83

        print('{:08b}'.format(self.multiply_mod(a, b)))
        self.assertEqual(self.multiply_mod(a, b), 0b11000001)


    def test_find_generator(self):
        def _pow(x, n):
            pows = [1, x]
            for i in range(2, n + 1):
                j = i
                s = 1
                for b in range(8):
                    if j & 0x01 != 0:
                        p = 1 << b
                        if p == len(pows):  # 指数为2的幂的值
                            k = pows[p >> 1]
                            s = self.multiply_mod(k, k)
                        else:
                            bit_value = pows[p]
                            s = self.multiply_mod(s, bit_value)
                    j >>= 1
                pows.append(s)
            return pows

        def _ploynomial(x):
            pows = _pow(x, 8)
            print(pows)
            return pows[8] ^ pows[4] ^ pows[3] ^ pows[1] ^ pows[0]

        print(self.multiply_mod(250, 2))

        x = 2
        s = 1
        field = {s}
        for i in range(255):
            s = self.multiply_mod(s, x)
            print(s)

            if s in field:
                print(sorted(list(field)))
                print(s, len(field))
                break
            field.add(s)




