from typing import Callable, Union, Optional
from .calculation import xor_on_bytes
import logging

logger = logging.getLogger(__name__)


class Mode:
    def __init__(self) -> None:
        pass

    def update(self, in_octets: Union[bytes, bytearray, memoryview]) -> bytes:
        raise NotImplementedError()

    def finalize(self) -> bytes:
        raise NotImplementedError()


class ECB(Mode):
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


class CBC(Mode):
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


class CTR(Mode):
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
            i = 0
            while i + self._block_byte_len <= buffer_len:
                out_octets.extend(self._counter_mask(in_octets[i:i + self._block_byte_len]))
                i += self._block_byte_len
            self._buffer = self._buffer[i * self._block_byte_len:]
        return out_octets

    def update(self, in_octets: bytes) -> bytes:
        self._buffer.extend(in_octets)
        return bytes(self._process_buffer())

    def finalize(self) -> bytes:
        out_octets = self._process_buffer()  # 以防万一
        if len(self._buffer) != 0:
            out_octets.extend(self._counter_mask(self._buffer))
        return bytes(out_octets)

