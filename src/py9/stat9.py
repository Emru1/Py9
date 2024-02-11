import struct

from qid import Qid

from utils import (
    encode_string,
    STR_LEN,
)


class Stat:
    def __init__(
            self,
            size: int,
            _type: int,
            dev: int,
            qid: int,
            mode: int,
            atime: int,
            mtime: int,
            length: int,
            name: str,
            uid: str,
            gid: str,
            muid: str,
    ):
        self.size: int = size
        self._type: int = _type
        self.dev: int = dev
        self.qid: Qid = qid
        self.mode: int = mode
        self.atime: int = atime
        self.mtime: int = mtime
        self.length: int = length
        self.name: str = name
        self.uid: str = uid
        self.gid: str = gid
        self.muid: str = muid

    @classmethod
    def from_bytes(cls, stat: bytes):
        try:
            size: int = struct.unpack('<H', stat[0:2])[0]
            _type: int = struct.unpack('<H', stat[2:4])[0]
            dev: int = struct.unpack('<I', stat[4:8])[0]
            qid: bytes = Qid.from_bytes(stat[8:21])
            mode: int = struct.unpack('<I', stat[21:25])[0]
            atime: int = struct.unpack('<I', stat[25:29])[0]
            mtime: int = struct.unpack('<I', stat[29:33])[0]
            length: int = struct.unpack('<Q', stat[33:41])[0]

            _name_offset: int = struct.unpack(
                '<H',
                stat[41:41 + STR_LEN])[0] + 41 + STR_LEN
            name: bytes = stat[41 + STR_LEN:_name_offset].decode()

            _uid_offset: int = struct.unpack(
                '<H',
                stat[_name_offset:_name_offset + STR_LEN],
            )[0] + _name_offset + STR_LEN
            uid: bytes = stat[_name_offset + STR_LEN:_uid_offset].decode()

            _gid_offset: int = struct.unpack(
                '<H',
                stat[_uid_offset:_uid_offset + STR_LEN],
            )[0] + _uid_offset + STR_LEN
            gid: bytes = stat[_uid_offset + STR_LEN:_gid_offset].decode()

            _muid_offset: int = struct.unpack(
                '<H',
                stat[_gid_offset:_gid_offset + STR_LEN],
            )[0] + _gid_offset + STR_LEN
            muid: bytes = stat[_gid_offset + STR_LEN:_muid_offset].decode()
        except Exception:
            raise Exception(
                "Error in parsing stat data. " +
                "Is provided data a valid stat?")

        return cls(
            size,
            _type,
            dev,
            qid,
            mode,
            atime,
            mtime,
            length,
            name,
            uid,
            gid,
            muid,
        )

    def to_bytes(self) -> bytes:
        buff = b''

        buff += struct.pack('<H', self._type)
        buff += struct.pack('<I', self.dev)
        buff += self.qid.to_bytes()
        buff += struct.pack('<I', self.mode)
        buff += struct.pack('<I', self.atime)
        buff += struct.pack('<I', self.mtime)
        buff += struct.pack('<Q', self.length)
        buff += encode_string(self.name)
        buff += encode_string(self.uid)
        buff += encode_string(self.gid)
        buff += encode_string(self.muid)

        size = struct.pack('<H', len(buff))

        return size + buff

    def __iter__(self) -> dict:
        yield '_type', self._type
        yield 'dev', self.dev
        yield 'qid', self.qid
        yield 'mode', self.mode
        yield 'atime', self.atime
        yield 'mtime', self.mtime
        yield 'length', self.length
        yield 'name', self.name
        yield 'uid', self.uid
        yield 'gid', self.gid
        yield 'muid', self.muid

    def __str__(self) -> str:
        return str(dict(self))
