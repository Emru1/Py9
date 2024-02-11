import struct


class Qid:
    def __init__(
            self,
            _type: int,
            version: int,
            path: int,
    ) -> None:
        self._type: int = _type
        self.version: int = version
        self.path: int = path

    @classmethod
    def from_bytes(cls, qid: bytes):
        _type: int = struct.unpack('<B', qid[0:1])[0]
        version: int = struct.unpack('<I', qid[1:5])[0]
        path: int = struct.unpack('<Q', qid[5:13])[0]

        return cls(_type, version, path)

    def to_bytes(self) -> bytes:
        buff = b''

        buff += struct.pack('<B', self._type)
        buff += struct.pack('<I', self.version)
        buff += struct.pack('<Q', self.path)

        return buff

    def __iter__(self) -> dict:
        yield 'type', self._type
        yield 'version', self.version
        yield 'path', self.path

    def __str__(self) -> str:
        return str(dict(self))
