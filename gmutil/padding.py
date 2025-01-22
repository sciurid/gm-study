from typing import Union

def pkcs7_padding(data: Union[bytes, bytearray], block_size: int) -> Union[bytes, bytearray]:
    """
    PKCS#7填充方法，与GB/T 17964-2021的C.2相同。
    """
    if not (0 < block_size < 2048):
        raise ValueError('分组大小必须大于0小于2048/Block size should be between 0 and 2048 exclusive')
    if block_size % 8 != 0:
        raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')

    block_byte_len = block_size // 8
    padding_bytes = block_byte_len - len(data) % block_byte_len

    result = bytearray(data) if isinstance(data, bytes) else data
    padding = int.to_bytes(padding_bytes, byteorder='big', signed=False) * padding_bytes
    result.extend(padding)

    return result


def bit_based_padding(data: Union[bytes, bytearray], block_size: int) -> Union[bytes, bytearray]:
    """

    GB/T 15852.1-2020 (ISO/IEC 9797-1）中规定的填充方法2，与PKCS#7填充方法，与GB/T 17964-2021的C.3相同。
    """
    if not (0 < block_size < 2048):
        raise ValueError('分组大小必须大于0小于2048/Block size should between 0 and 2048 exclusive')
    if block_size % 8 != 0:
        raise ValueError('分组大小必须为8的倍数/Block size should be a multiple of 8')

    block_byte_len = block_size // 8
    zero_byte_len = block_byte_len - (len(data) % block_byte_len) - 1
    padding = b'\x80' + b'\x00' * zero_byte_len

    result = bytearray(data) if isinstance(data, bytes) else data
    result.extend(padding)
    return result


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

