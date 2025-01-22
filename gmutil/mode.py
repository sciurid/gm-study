from typing import Callable, Union, Optional


class ECB:
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int):
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


class CBC:
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes], block_size: int,
                 iv: Union[bytes, bytearray, memoryview], is_encrypt: bool):
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
                    block_input = (int.from_bytes(self._last_cipher_block, byteorder='big', signed=False)
                                   ^ int.from_bytes(in_octets[i:i + self._block_byte_len], byteorder='big', signed=False))
                    self._last_cipher_block = (
                        self._function(block_input.to_bytes(length=self._block_byte_len, byteorder='big', signed=False)))
                    out_octets.extend(self._last_cipher_block)
                else:
                    block_output = self._function(in_octets[i:i + self._block_byte_len])
                    block_output = (int.from_bytes(block_output, byteorder='big', signed=False)
                                    ^ int.from_bytes(self._last_cipher_block, byteorder='big', signed=False))
                    self._last_cipher_block = in_octets[i:i + self._block_byte_len]
                    out_octets.extend(block_output.to_bytes(length=self._block_byte_len, byteorder='big', signed=False))
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






