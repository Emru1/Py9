import struct


STR_LEN = 2


def encode_string(string: str) -> bytes:
    data = string.encode()
    buff = struct.pack('<H', len(data)) + data

    return buff
