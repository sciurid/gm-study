from typing import Callable, Union, Optional


class ECB:
    def __init__(self, function: Callable[[Union[bytes, bytearray, memoryview]], bytes],
                 block_size: int, padding: Optional[Callable[[Union[bytes, bytearray, memoryview], int], bytes]]):
        self._function = function
        self._block_size = block_size
        self._block_byte_len = self._block_size // 8
        self._padding = padding
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
        if self._padding is None:
            if len(self._buffer) != 0:
                raise ValueError('数据长度不是分组长度的整数倍，需要指明填充方法/'
                                 'Length of data is not a multiple of block size, so padding is required')
        else:
            last_block = self._padding(memoryview(out_octets), self._block_size)
            out_octets.extend(self._function(last_block))
        return bytes(out_octets)









