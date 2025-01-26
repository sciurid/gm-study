from typing import Callable, Union, Optional
from .calculation import xor_on_bytes, mul_gf_2_128
from .commons import Codec
import logging

logger = logging.getLogger(__name__)


class ECB(Codec):
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int):
        super().__init__()
        self._function = function
        self._block_size = block_size
        self._block_byte_len = self._block_size // 8
        self._buffer = bytearray()

    def _process_buffer(self) -> bytearray:
        out_octets = bytearray()
        buffer_len = len(self._buffer)
        if buffer_len >= self._block_byte_len:
            in_octets = memoryview(self._buffer)
            i = 0
            while i + self._block_byte_len <= buffer_len:
                out_octets.extend(self._function(in_octets[i:i + self._block_byte_len]))
                i += self._block_byte_len
            self._buffer = self._buffer[i * self._block_byte_len:]
        return out_octets

    def update(self, in_octets: bytes) -> bytes:
        self._buffer.extend(in_octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        out_octets = self._process_buffer()  # 以防万一
        if len(self._buffer) != 0:
            raise ValueError('数据长度不是分组长度的整数倍，需要填充/'
                             'Length of data is not a multiple of block size, so padding is required')
        return bytes(out_octets)


class CBC(Codec):
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 iv: Union[bytes, bytearray, memoryview], is_encrypt: bool):
        super().__init__()
        self._function = function

        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')
        if len(iv) * 8 != block_size:
            raise ValueError('初始向量IV必须为分组长度/Initial vector should be of block size.')

        self._block_size = block_size
        self._block_byte_len = self._block_size // 8

        self._iv = iv
        self._is_encrypt = is_encrypt

        self._buffer = bytearray()
        self._last_cipher_block = iv

    def _process_buffer(self) -> bytearray:
        out_octets = bytearray()
        buffer_len = len(self._buffer)
        if buffer_len >= self._block_byte_len:
            in_octets = memoryview(self._buffer)
            i = 0
            while i + self._block_byte_len <= buffer_len:
                if self._is_encrypt:
                    block_input = xor_on_bytes(self._last_cipher_block, in_octets[i:i + self._block_byte_len])
                    self._last_cipher_block = (self._function(block_input))
                    out_octets.extend(self._last_cipher_block)
                else:
                    block_output = self._function(in_octets[i:i + self._block_byte_len])
                    block_output = xor_on_bytes(block_output, self._last_cipher_block)
                    self._last_cipher_block = in_octets[i:i + self._block_byte_len]
                    out_octets.extend(block_output)
                i += self._block_byte_len
            self._buffer = self._buffer[i * self._block_byte_len:]
        return out_octets

    def update(self, in_octets: bytes) -> bytes:
        self._buffer.extend(in_octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        out_octets = self._process_buffer()  # 以防万一
        if len(self._buffer) != 0:
            raise ValueError('数据长度不是分组长度的整数倍，需要填充/'
                             'Length of data is not a multiple of block size, so padding is required')
        return bytes(out_octets)


class CTR(Codec):
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 iv: Union[bytes, bytearray, memoryview]):
        super().__init__()
        self._function = function

        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8.')
        if len(iv) * 8 != block_size:
            raise ValueError('初始向量IV必须为分组长度/Initial vector should be of block size.')

        self._block_size = block_size
        self._block_byte_len = self._block_size // 8

        self._iv = iv

        self._buffer = bytearray()
        self._last_counter = iv
        self._block_mask = (1 << block_size) - 1

    def _counter_mask(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        assert len(in_octets) <= self._block_byte_len
        # logger.debug('-' * 20 + 'BLOCK' + '-' * 20)
        # logger.debug('Plain:  {}'.format(in_octets.hex()))
        # logger.debug('Counter:{}'.format(self._last_counter.hex()))
        mask = self._function(self._last_counter)
        # logger.debug('Mask:   {}'.format(mask.hex()))
        out_octet = xor_on_bytes(in_octets, mask[0:len(in_octets)])
        # logger.debug('Cipher: {}'.format(out_octet.hex()))

        self._last_counter = (((int.from_bytes(self._last_counter, byteorder='big', signed=False) + 1)
                               & self._block_mask)
                              .to_bytes(self._block_byte_len, byteorder='big', signed=False))
        return out_octet

    def _process_buffer(self) -> bytearray:
        out_octets = bytearray()
        buffer_len = len(self._buffer)
        if buffer_len >= self._block_byte_len:
            in_octets = memoryview(self._buffer)
            m = 0
            while m <= buffer_len:
                n = m + self._block_byte_len
                out_octets.extend(self._counter_mask(in_octets[m:n]))
                m = n
            self._buffer = self._buffer[m:]
        return out_octets

    def update(self, in_octets: bytes) -> bytes:
        self._buffer.extend(in_octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        out_octets = self._process_buffer()  # 以防万一
        if len(self._buffer) != 0:
            out_octets.extend(self._counter_mask(self._buffer))
        return bytes(out_octets)


class CFB(Codec):
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 iv: Union[bytes, bytearray, memoryview], is_encrypt: bool,
                 output_block_byte_len: Optional[int] = None, val_k_byte_len: Optional[int] = None):
        self._function = function

        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8.')
        if len(iv) * 8 < block_size:
            raise ValueError('初始向量IV必须不小于分组长度/Initial vector should be of block size.')

        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._iv = iv
        self._iv_byte_len = len(self._iv)
        self._is_encrypt = is_encrypt

        self._output_block_byte_len = output_block_byte_len if output_block_byte_len else self._block_byte_len
        self._val_k_byte_len = val_k_byte_len if val_k_byte_len else self._output_block_byte_len
        self._buffer = bytearray()
        self._fb = bytearray(iv)

    def _process_buffer(self):
        out_octets = bytearray()
        in_octets = memoryview(self._buffer)
        buffer_len = len(self._buffer)
        m = 0
        while m < buffer_len:
            val_x = memoryview(self._fb)[0:self._block_byte_len]
            val_y = memoryview(self._function(val_x))[0:self._output_block_byte_len]

            if self._is_encrypt:
                n = m + self._output_block_byte_len
                val_c = xor_on_bytes(val_y, in_octets[m:n])
                m = n
                out_octets.extend(val_c)
            else:
                n = m + self._output_block_byte_len
                val_c = memoryview(self._buffer)[m:n]
                m = n
                out_octets.extend(xor_on_bytes(val_y, val_c))

            self._fb.extend(b'\xff' * (self._val_k_byte_len - self._output_block_byte_len))
            self._fb.extend(val_c)
            self._fb = self._fb[-self._iv_byte_len:]

        in_octets.release()
        self._buffer = self._buffer[m:]
        return out_octets

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        buffer_len = len(self._buffer)
        if buffer_len % self._output_block_byte_len != 0:
            self._buffer.extend(b'\x00' * (self._output_block_byte_len - buffer_len))
        out_octets = self._process_buffer()
        return bytes(out_octets[0:buffer_len])


class OFB(Codec):
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 iv: Union[bytes, bytearray, memoryview], is_encrypt: bool, output_byte_len: Optional[int] = None):

        self._function = function
        self._block_size = block_size
        self._block_byte_len = self._block_size // 8

        self._output_block_byte_len = output_byte_len if output_byte_len else self._block_byte_len
        self._iv = iv
        self._fb = iv
        self._buffer = bytearray()

    def _process_buffer(self):
        out_octets = bytearray()
        in_octets = memoryview(self._buffer)
        buffer_len = len(self._buffer)
        m = 0
        while m < buffer_len:
            val_y = self._function(self._fb)
            n = m + self._output_block_byte_len
            out_octets.extend(xor_on_bytes(memoryview(val_y)[0:self._output_block_byte_len], in_octets[m:n]))
            m = n
            self._fb = val_y

        in_octets.release()
        self._buffer = self._buffer[m:]
        return out_octets

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        buffer_len = len(self._buffer)
        if buffer_len % self._output_block_byte_len != 0:
            self._buffer.extend(b'\x00' * (self._output_block_byte_len - buffer_len))
        out_octets = self._process_buffer()
        return bytes(out_octets[0:buffer_len])


class XTS:
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 tweak_enc_func: Callable[[Union[bytes, bytearray, memoryview]], bytes],
                 tweak: Union[bytes, bytearray, memoryview], is_encrypt: bool):
        self._tweak_enc_func = tweak_enc_func
        self._function = function

        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8.')
        self._block_size = block_size
        self._block_byte_len = self._block_size // 8

        self._tweak = tweak
        self._step_mask = tweak_enc_func(self._tweak)
        self._is_encrypt = is_encrypt

        self._buffer = bytearray()

    POLYNOMIAL_ALPHA: int = 1 << 126

    @staticmethod
    def _next_step_mask(polynomial_mask: bytes):
        return mul_gf_2_128(int.from_bytes(polynomial_mask, byteorder='big', signed=False),
                            XTS.POLYNOMIAL_ALPHA).to_bytes(length=16, byteorder='big', signed=False)

    def _process_block(self, in_block: Union[bytes, bytearray, memoryview]) -> bytes:
        print('In block :', in_block.hex())
        print('Mask     :', self._step_mask.hex())
        enc_in = xor_on_bytes(self._step_mask, in_block)
        print('Encrypt I:', enc_in.hex())
        enc_out = self._function(enc_in)
        print('Encrypt O:', enc_out.hex())
        out_block = xor_on_bytes(self._step_mask, enc_out)
        print('Out block:', out_block.hex())
        print()

        return bytes(out_block)

    def _process_buffer(self):
        out_octets = bytearray()
        in_octets = memoryview(self._buffer)
        buffer_len = len(self._buffer)
        m = 0
        while m < buffer_len - 2 * self._block_byte_len:  # 至少保留两个分组
            n = m + self._block_byte_len
            out_octets.extend(self._process_block(in_octets[m:n]))
            self._step_mask = XTS._next_step_mask(self._step_mask)
            m = n
        self._buffer = self._buffer[m:]
        return out_octets

    def update(self, octets: Union[bytes, bytearray, memoryview]) -> bytes:
        self._buffer.extend(octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        out_octets = self._process_buffer()
        buffer_len = len(self._buffer)
        in_octets = memoryview(self._buffer)
        if buffer_len < self._block_byte_len:
            raise ValueError('数据长度不足一个分组，需要补齐/Data is shorter than one block, so padding is required.')

        if buffer_len == 2 * self._block_byte_len:
            out_octets.extend(self._process_block(in_octets[0:self._block_byte_len]))
            out_octets.extend(self._process_block(in_octets[self._block_byte_len:]))
        else:
            d = buffer_len - self._block_byte_len
            n_d = self._block_byte_len - d
            if self._is_encrypt:
                c_ql = self._process_block(in_octets[0:self._block_byte_len])
                self._step_mask = XTS._next_step_mask(self._step_mask)
                ex = bytearray(in_octets[self._block_byte_len:])
                ex.extend(c_ql[-n_d:])
                c_q = self._process_block(ex)

                out_octets.extend(c_q)
                print(c_q.hex())
                out_octets.extend(c_ql[0:d])
                print(c_ql[0:d].hex())
            else:
                mask_ql = self._step_mask
                self._step_mask = XTS._next_step_mask(self._step_mask)
                p_q = self._process_block(in_octets[0:self._block_byte_len])
                ex = bytearray(in_octets[self._block_byte_len:])
                ex.extend(p_q[-n_d:])
                self._step_mask = mask_ql
                p_ql = self._process_block(ex)
                out_octets.extend(p_ql)
                out_octets.extend(p_q[0:d])
        return bytes(out_octets)

