from typing import Union


class SuffixPadding:
    def __init__(self, block_size: int, mode_padding: bool = True):
        pass

    def update(self, in_octets: Union[bytes, bytearray, memoryview]):
        raise NotImplementedError()

    def finalize(self):
        raise NotImplementedError()


class PKCS7Padding(SuffixPadding):
    """
    PKCS#7填充方法，与GB/T 17964-2021的C.2相同。
    """
    def __init__(self, block_size: int, mode_padding: bool = True):
        super().__init__(block_size=block_size)
        if not (0 < block_size < 2048):
            raise ValueError('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def update(self, in_octets: Union[bytes, bytearray, memoryview]):
        self._buffer.extend(in_octets)
        buffer_len = len(self._buffer)
        if buffer_len == 0:
            return b''

        if self._mode_padding:
            out_len = (buffer_len // self._block_byte_len) * self._block_byte_len
            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets
        else:
            out_len = ((buffer_len - 1) // self._block_byte_len - 1) * self._block_byte_len
            if out_len <= 0:
                return b''

            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets

    def finalize(self):
        if self._mode_padding:
            buffer_len = len(self._buffer)
            padding_byte_len = self._block_byte_len - buffer_len % self._block_byte_len
            self._buffer.extend([padding_byte_len] * padding_byte_len)
            out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            if len(self._buffer) % self._block_byte_len != 0:
                raise ValueError("经过填充的数据长度不是分组长度的整数倍"
                                 "/Length of padded data is not a multiple of block size")
            padding_len = self._buffer[-1]
            for i in range(-padding_len, 0):
                if self._buffer[i] != padding_len:
                    raise ValueError("填充数据格式错误/Padded data is mal-formatted.")
            return self._buffer[0:-padding_len]


def pkcs7_pad(data: Union[bytes, bytearray, memoryview], block_size: int) -> Union[bytes, bytearray]:
    padding = PKCS7Padding(128, True)
    out_octets = bytearray()
    out_octets.extend(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


def pkcs7_unpad(data: Union[bytes, bytearray, memoryview], block_size: int) -> Union[bytes, bytearray]:
    padding = PKCS7Padding(128, False)
    out_octets = bytearray()
    out_octets.extend(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


class BitBasedPadding(SuffixPadding):
    """

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法2，与PKCS#7填充方法，与GB/T 17964-2021的C.3相同。
    """
    def __init__(self, block_size: int, mode_padding: bool = True):
        super().__init__(block_size=block_size)
        if not (0 < block_size < 2048):
            raise ValueError('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
        if block_size % 8 != 0:
            raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')
        self._block_size = block_size
        self._block_byte_len = block_size // 8
        self._buffer = bytearray()
        self._mode_padding = mode_padding

    def update(self, in_octets: Union[bytes, bytearray, memoryview]):
        self._buffer.extend(in_octets)
        buffer_len = len(self._buffer)
        if buffer_len == 0:
            return b''

        if self._mode_padding:
            out_len = (buffer_len // self._block_byte_len) * self._block_byte_len
            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets
        else:
            out_len = ((buffer_len - 1) // self._block_byte_len) * self._block_byte_len
            if out_len <= 0:
                return b''

            out_octets = bytes(self._buffer[:out_len])
            self._buffer = self._buffer[out_len:]
            return out_octets

    def finalize(self):
        if self._mode_padding:
            self._buffer.append(0x80)
            buffer_len = len(self._buffer)
            padding_byte_len = self._block_byte_len - buffer_len % self._block_byte_len
            self._buffer.extend([0] * padding_byte_len)
            out_octets = bytes(self._buffer)
            self._buffer = None
            return bytes(out_octets)
        else:
            buffer_len = len(self._buffer)
            if buffer_len % self._block_byte_len != 0:
                raise ValueError("经过填充的数据长度不是分组长度的整数倍"
                                 "/Length of padded data is not a multiple of block size")
            for i in range(-1, -buffer_len-1, -1):
                if self._buffer[i] == 0x80:
                    return bytes(self._buffer[:i])
            else:
                raise ValueError("填充数据格式错误/Padded data is mal-formatted.")


def bit_based_pad(data: Union[bytes, bytearray, memoryview], block_size: int) -> Union[bytes, bytearray]:
    padding = BitBasedPadding(128, True)
    out_octets = bytearray()
    out_octets.extend(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


def bit_based_unpad(data: Union[bytes, bytearray, memoryview], block_size: int) -> Union[bytes, bytearray]:
    padding = BitBasedPadding(128, False)
    out_octets = bytearray()
    out_octets.extend(padding.update(data))
    out_octets.extend(padding.finalize())
    return out_octets


def length_prefixed_padding(data: Union[bytes, bytearray], block_size: int, unused_bit_num:int = 0) -> Union[bytes, bytearray]:
    """

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法3。与GB/T 17964-2021的C.3描述相同，但示例有差别（猜想是GB/T 17964的错讹）。
    适用于预先知道长度的非整数比特的情况，比如ASN.1的BITSTRING类型。
    """
    if not (0 <= unused_bit_num < 8):
        raise ValueError('未用比特数应当为0至7/Unused bit number should between 0 and 7 (inclusive)')
    if block_size <= 0:
        raise ValueError('分组大小必须大于0//Block size should be positive.')
    if (len(data) * 8) >= (1 << block_size):
        raise ValueError('数据长度超出分组大小限制/Length of data exceeds the block size.')
    if len(data) > 0 and data[-1] & ((1 << unused_bit_num) - 1) != 0:
        raise ValueError('未用比特的值必须均为0/The unused bit number should all be 0.')

    block_byte_len = block_size // 8
    prefix = (len(data) * 8 - unused_bit_num).to_bytes(block_byte_len, byteorder='big', signed=False)

    suffix = b'\x00' * (block_byte_len - (len(data) % block_byte_len))

    result = bytearray()
    result.extend(prefix)
    result.extend(data)
    result.extend(suffix)
    return result

