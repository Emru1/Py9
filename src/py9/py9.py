from enum import Enum
from abc import abstractmethod

import selectors
import socket
import struct
import time

STR_LEN = 2


class Py9:
    # http://man.cat-v.org/plan_9/5
    # http://9p.cat-v.org/documentation/rfc/
    # http://man.9front.org/5/

    class TRs(Enum):
        Tversion = 100
        Rversion = 101
        Tauth = 102
        Rauth = 103
        Tattach = 104
        Rattach = 105
        Terror = 106  # illegal
        Rerror = 107
        Tflush = 108
        Rflush = 109
        Twalk = 110
        Rwalk = 111
        Topen = 112
        Ropen = 113
        Tcreate = 114
        Rcreate = 115
        Tread = 116
        Rread = 117
        Twrite = 118
        Rwrite = 119
        Tclunk = 120
        Rclunk = 121
        Tremove = 122
        Rremove = 123
        Tstat = 124
        Rstat = 125
        Twstat = 126
        Rwstat = 127

    class Qid:
        def __init__(
                self,
                type: int,
                version: int,
                path: int,
        ) -> None:
            self.type: int = type
            self.version: int = version
            self.path: int = path

        @classmethod
        def from_bytes(cls, qid: bytes):
            type: int = struct.unpack('<B', qid[0:1])[0]
            version: int = struct.unpack('<I', qid[1:5])[0]
            path: int = struct.unpack('<Q', qid[5:13])[0]

            return cls(type, version, path)

        def to_bytes(self) -> bytes:
            buff = b''

            buff += struct.pack('<B', self.type)
            buff += struct.pack('<I', self.version)
            buff += struct.pack('<Q', self.path)

            return buff

        def __iter__(self) -> dict:
            yield 'type', self.type
            yield 'version', self.version
            yield 'path', self.path

        def __str__(self) -> str:
            return str(dict(self))

    class Stat:
        def __init__(
                self,
                size: int,
                type: int,
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
            self.type: int = type
            self.dev: int = dev
            self.qid: Py9.Qid = qid
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
                type: int = struct.unpack('<H', stat[2:4])[0]
                dev: int = struct.unpack('<I', stat[4:8])[0]
                qid: bytes = Py9.Qid.from_bytes(stat[8:21])
                mode: int = struct.unpack('<I', stat[21:25])[0]
                atime: int = struct.unpack('<I', stat[25:29])[0]
                mtime: int = struct.unpack('<I', stat[29:33])[0]
                length: int = struct.unpack('<Q', stat[33:41])[0]

                _name_offset: int = struct.unpack('<H', stat[41:41 + STR_LEN])[0] + 41 + STR_LEN
                name: bytes = stat[41 + STR_LEN:_name_offset].decode()

                _uid_offset: int = struct.unpack('<H', stat[_name_offset:_name_offset + STR_LEN])[0] + _name_offset + STR_LEN
                uid: bytes = stat[_name_offset + STR_LEN:_uid_offset].decode()

                _gid_offset: int = struct.unpack('<H', stat[_uid_offset:_uid_offset + STR_LEN])[0] + _uid_offset + STR_LEN
                gid: bytes = stat[_uid_offset + STR_LEN:_gid_offset].decode()

                _muid_offset: int = struct.unpack('<H', stat[_gid_offset:_gid_offset + STR_LEN])[0] + _gid_offset + STR_LEN
                muid: bytes = stat[_gid_offset + STR_LEN:_muid_offset].decode()
            except Exception:
                raise Exception("Error in parsing stat data. Is provided data a valid stat?")

            return cls(
                size,
                type,
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

            buff += struct.pack('<H', self.type)
            buff += struct.pack('<I', self.dev)
            buff += self.qid.to_bytes()
            buff += struct.pack('<I', self.mode)
            buff += struct.pack('<I', self.atime)
            buff += struct.pack('<I', self.mtime)
            buff += struct.pack('<Q', self.length)
            buff += Py9._encode_string(self.name)
            buff += Py9._encode_string(self.uid)
            buff += Py9._encode_string(self.gid)
            buff += Py9._encode_string(self.muid)

            size = struct.pack('<H', len(buff))

            return size + buff

        def __iter__(self) -> dict:
            yield 'type', self.type
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

    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
            version: str = "9P2000",
    ) -> None:
        self.ip: str = ip
        self.port: int = port
        self.msize: int = msize
        self._version: str = version
        self.selector: selectors.BaseSelector = selectors.DefaultSelector()
        self.socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.selector.register(self.socket, selectors.EVENT_READ)

        self.tag: int = -1

    def get_tag(self):
        self.tag += 1
        if self.tag > 65535:
            self.tag = 0

        return self.tag

    def _recv_n(
            self,
            sock: socket.socket,
            num: int,
    ) -> bytes:
        assert num > 0

        buffer: bytes = b''
        i: int = 0

        while i < num:
            buffer += sock.recv(num - i)
            i = len(buffer)

        return buffer

    def _recv(
            self,
            sock: socket.socket,
    ) -> dict:
        size: int = struct.unpack('<I', self._recv_n(sock, 4))[0]
        buf: bytes = self._recv_n(sock, size - 4)
        operation: self.TRs = self.TRs(struct.unpack('<B', buf[0:1])[0])
        tag: int = struct.unpack('<H', buf[1:3])[0]
        other_data: dict = self._parse_data(operation, buf[3:])

        return {
            'operation': operation,
            'tag': tag,
        } | other_data

    @staticmethod
    def _encode_string(string: str) -> bytes:
        buff = string.encode()
        buff = struct.pack('<H', len(buff)) + buff

        return buff

    def _decode_qid(self, qid: bytes) -> dict:
        type: int = struct.unpack('<B', qid[0:1])[0]
        version: int = struct.unpack('<I', qid[1:5])[0]
        path: int = struct.unpack('<Q', qid[5:13])[0]

        ret = {
            'type': type,
            'version': version,
            'path': path,
        }

        return ret

    def _parse_data(
            self,
            operation,
            data: bytes,
    ) -> dict:
        ret: dict
        match operation:
            case self.TRs.Tversion:
                msize: int = struct.unpack('<I', data[0:4])[0]
                version_len: int = struct.unpack('<H', data[4:6])[0]
                version: bytes = data[4 + STR_LEN:4 + STR_LEN + version_len]

                ret = {
                    'msize': msize,
                    'version': version,
                }

            case self.TRs.Rversion:
                msize: int = struct.unpack('<I', data[0:4])[0]
                version_len: int = struct.unpack('<H', data[4:6])[0]
                version: bytes = data[4 + STR_LEN:4 + STR_LEN + version_len]

                ret = {
                    'msize': msize,
                    'version': version,
                }

            case self.TRs.Tauth:
                uname_len: int = struct.unpack('<H', data[4: 4 + STR_LEN])[0]
                aname_len: int = struct.unpack('<H', data[4 + STR_LEN + uname_len: 4 + STR_LEN + uname_len + STR_LEN])[0]

                afid: int = struct.unpack('<I', data[0:4])[0]
                uname: bytes = data[4 + STR_LEN: 4 + STR_LEN + uname_len]
                aname: bytes = data[4 + STR_LEN + uname_len + STR_LEN: 4 + STR_LEN + uname_len + STR_LEN + aname_len]

                ret = {
                    'afid': afid,
                    'uname': uname,
                    'aname': aname,
                }

            case self.TRs.Rauth:
                aqid: bytes = data[0:13]

                ret = {
                    'aqid': aqid,
                }

            case self.TRs.Tattach:
                uname_len: int = struct.unpack('<H', data[8: 8 + STR_LEN])[0]
                aname_len: int = struct.unpack('<H', data[8 + STR_LEN + uname_len: 8 + STR_LEN + uname_len + STR_LEN])[0]

                fid: int = struct.unpack('<I', data[0:4])[0]
                afid: int = struct.unpack('<I', data[4:8])[0]
                uname: bytes = data[8 + STR_LEN: 8 + STR_LEN + uname_len]
                aname: bytes = data[8 + STR_LEN + uname_len + STR_LEN: 8 + STR_LEN + uname_len + STR_LEN + aname_len]

                ret = {
                    'fid': fid,
                    'afid': afid,
                    'uname': uname,
                    'aname': aname,
                }

            case self.TRs.Rattach:
                qid: bytes = data[0:13]

                ret = {
                    'qid': self.Qid.from_bytes(qid),
                }

            case self.TRs.Terror:
                raise Exception('There is no Terror code')

            case self.TRs.Rerror:
                ename_len: int = struct.unpack('<H', data[0:0 + STR_LEN])[0]

                ename: bytes = data[0 + STR_LEN:0 + STR_LEN + ename_len]

                ret = {
                    'ename': ename,
                }

            case self.TRs.Tflush:
                oldtag: int = struct.unpack('<H', data[0:2])[0]

                ret = {
                    'oldtag': oldtag,
                }

            case self.TRs.Rflush:
                ret = {}

            case self.TRs.Twalk:
                fid: int = struct.unpack('<I', data[0:4])[0]
                newfid: int = struct.unpack('<I', data[4:8])[0]
                nwname: int = struct.unpack('<H', data[8:10])[0]

                wnames: list = []
                offset: int = 10

                for _ in range(nwname):
                    wname_len = struct.unpack('<H', data[offset:offset + STR_LEN])[0]
                    wname: bytes = data[offset + STR_LEN:offset + STR_LEN + wname_len]
                    wnames.append(wname)
                    offset += wname_len + STR_LEN

                ret = {
                    'fid': fid,
                    'newfid': newfid,
                    'nwname': nwname,
                    'wnames': wnames,
                }

            case self.TRs.Rwalk:
                nwqid: int = struct.unpack('<H', data[0:2])[0]

                qids: list = []
                offset: int = 2

                for _ in range(nwqid):
                    qid: bytes = data[offset:offset + 13]
                    qids.append(self.Qid.from_bytes(qid))
                    offset += 13

                ret = {
                    'qids': qids,
                }

            case self.TRs.Topen:
                fid: int = struct.unpack('<I', data[0:4])[0]
                mode: int = struct.unpack('<B', data[4:5])[0]

                ret = {
                    'fid': fid,
                    'mode': mode,
                }

            case self.TRs.Ropen:
                qid: bytes = data[0:13]
                iounit: int = struct.unpack('<I', data[13:17])[0]

                ret = {
                    'qid': self.Qid.from_bytes(qid),
                    'iounit': iounit,
                }

            case self.TRs.Tcreate:
                name_len = struct.unpack('<H', data[4:4 + STR_LEN])[0]

                fid: int = struct.unpack('<I', data[0:4])[0]
                name: bytes = data[4 + STR_LEN:4 + STR_LEN + name_len]
                perm: int = struct.unpack('<I', data[4 + STR_LEN + name_len:4 + STR_LEN + name_len + 4])[0]
                mode: int = struct.unpack('<B', data[4 + STR_LEN + name_len + 4: 4 + STR_LEN + name_len + 4 + 1])[0]

                ret = {
                    'fid': fid,
                    'name': name,
                    'perm': perm,
                    'mode': mode,
                }

            case self.TRs.Rcreate:
                qid: bytes = data[0:13]
                iounit: bytes = data[13:17]

                ret = {
                    'qid': self.Qid.from_bytes(qid),
                    'iounit': iounit,
                }

            case self.TRs.Tread:
                fid: int = struct.unpack('<I', data[0:4])[0]
                offset: int = struct.unpack('<Q', data[4:12])[0]
                count: int = struct.unpack('<I', data[12:16])[0]

                ret = {
                    'fid': fid,
                    'offset': offset,
                    'count': count,
                }

            case self.TRs.Rread:
                count: int = struct.unpack('<I', data[0:4])[0]
                _data: bytes = data[4:4 + count]

                ret = {
                    'count': count,
                    'data': _data,
                }

            case self.TRs.Twrite:
                fid: int = struct.unpack('<I', data[0:4])[0]
                offset: int = struct.unpack('<Q', data[4:12])[0]
                count: int = struct.unpack('<I', data[12:16])[0]
                _data: bytes = data[16:16 + count]

                ret = {
                    'fid': fid,
                    'offset': offset,
                    'count': count,
                    'data': _data,
                }

            case self.TRs.Rwrite:
                count: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'count': count,
                }

            case self.TRs.Tclunk:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case self.TRs.Rclunk:
                ret = {}

            case self.TRs.Tremove:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case self.TRs.Rremove:
                ret = {}

            case self.TRs.Tstat:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case self.TRs.Rstat:
                stat_len: int = struct.unpack('<H', data[0:2])[0]
                stats: bytes = data[0 + STR_LEN:0 + STR_LEN + stat_len]

                ret = {
                    'stat': self.Stat.from_bytes(stats),
                }

            case self.TRs.Twstat:
                fid: int = struct.unpack('<I', data[0:4])[0]
                stat: bytes = data[4:]

                ret = {
                    'fid': fid,
                    'stat': stat,
                }

            case self.TRs.Rwstat:
                ret = {}

            case _:
                raise Exception('No such operation')
        return ret

    def _encode_packet(
            self,
            type,
            data: bytes
    ) -> bytes:
        size: bytes = struct.pack('<I', len(data) + 7)
        t: bytes = struct.pack('<B', type.value)
        tag: bytes = struct.pack('<H', self.get_tag())

        return size + t + tag + data

    def _encode_Tversion(self) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', self.msize)
        buff += struct.pack('<H', len(self._version))
        buff += self._version.encode()

        return self._encode_packet(self.TRs.Tversion, buff)

    def _encode_Tauth(self, afid: int, uname: str, aname: str) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', afid)
        buff += self._encode_string(uname)
        buff += self._encode_string(aname)

        return self._encode_packet(self.TRs.Tauth, buff)

    def _encode_Tflush(
            self,
            oldtag: int
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<H', oldtag)

        return self._encode_packet(self.TRs.Tflush, buff)

    def _encode_Tattach(
            self,
            fid: int = 0,
            afid: int = 0,
            uname: str = 'testuser',
            aname: str = '',
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<I', afid)
        buff += self._encode_string(uname)
        buff += self._encode_string(aname)

        return self._encode_packet(self.TRs.Tattach, buff)

    def _encode_Twalk(
            self,
            fid: int,
            newfid: int,
            names: list[str],
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<I', newfid)
        buff += struct.pack('<H', len(names))

        for name in names:
            buff += self._encode_string(name)

        return self._encode_packet(self.TRs.Twalk, buff)

    def _encode_Topen(
            self,
            fid: int,
            mode: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<B', mode)

        return self._encode_packet(self.TRs.Topen, buff)

    def _encode_Tcreate(
            self,
            fid: int,
            name: str,
            perm: int,
            mode: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += self._encode_string(name)
        buff += struct.pack('<I', perm)
        buff += struct.pack('<B', mode)

        return self._encode_packet(self.TRs.Tcreate, buff)

    def _encode_Tread(
            self,
            fid: int,
            offset: int,
            count: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<Q', offset)
        buff += struct.pack('<I', count)

        return self._encode_packet(self.TRs.Tread, buff)

    def _encode_Twrite(
            self,
            fid: int,
            offset: int,
            data: bytes,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<Q', offset)
        buff += struct.pack('<I', len(data))
        buff += data

        return self._encode_packet(self.TRs.Twrite, buff)

    def _encode_Tclunk(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(self.TRs.Tclunk, buff)

    def _encode_Tremove(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(self.TRs.Tremove, buff)

    def _encode_Tstat(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(self.TRs.Tstat, buff)

    def _encode_Twstat(
            self,
            fid: int,
            stat: Stat,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += stat.to_bytes()

        return self._encode_packet(self.TRs.Tremove, buff)

    @abstractmethod
    def __del__(self):
        ...


class Py9Client(Py9):
    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
            version: str = "9P2000",
    ) -> None:
        super().__init__(ip, port, msize, version)

    def connect(self) -> None:
        self.socket.connect((self.ip, self.port))

        data = self.version()

        if data['operation'] != self.TRs.Rversion:
            raise Exception("Server hasn't responded with Rversion")
        if data['tag'] != 0:
            raise Exception("Server has responded to Tversion with invali tag")
        if data['version'].decode() != self._version:
            raise Exception(
                f"Server has responded with version {data['version'].decode()}, expected {self._version}"
            )

    def version(self) -> dict:
        self.socket.sendall(self._encode_Tversion())
        data: dict = self.recv()
        return data

    def auth(self, afid: int, uname: str, aname: str) -> dict:
        self.socket.sendall(self._encode_Tauth(afid, uname, aname))
        data: dict = self.recv()
        return data

    def flush(self, oldtag: int) -> dict:
        self.socket.sendall(self._encode_Tflush(oldtag))
        data: dict = self.recv()
        return data

    def attach(self) -> dict:
        self.socket.sendall(self._encode_Tattach())
        data: dict = self.recv()
        return data

    def walk(self, fid: int, newfid: int, names: list[str]) -> dict:
        self.socket.sendall(self._encode_Twalk(fid, newfid, names))
        data: dict = self.recv()
        return data

    def open(self, fid: int, mode: int) -> dict:
        self.socket.sendall(self._encode_Topen(fid, mode))
        data: dict = self.recv()
        return data

    def create(self, fid: int, name: str, perm: int, mode: int) -> dict:
        raise NotImplementedError

    def read(self, fid: int, offset: int, count: int) -> dict:
        self.socket.sendall(self._encode_Tread(fid, offset, count))
        data: dict = self.recv()
        return data

    def write(self, fid: int, offset: int, data: bytes) -> dict:
        self.socket.sendall(self._encode_Twrite(fid, offset, data))
        data: dict = self.recv()
        return data

    def clunk(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tclunk(fid))
        data: dict = self.recv()
        return data

    def remove(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tremove(fid))
        data: dict = self.recv()
        return data

    def stat(self, fid: int) -> dict:
        self.socket.sendall(self._encode_Tstat(fid))
        data: dict = self.recv()
        return data

    def wstat(self, fid: int, stat: Py9.Stat) -> dict:
        self.socket.sendall(self._encode_Twstat(fid, stat))
        data: dict = self.recv()
        return data

    def recv(self) -> dict:
        return self._recv(self.socket)

    def read_dir(self, fid: int, offset: int, count: int) -> list[Py9.Stat]:
        self.socket.sendall(self._encode_Tread(fid, offset, count))
        pkt: dict = self.recv()
        data = pkt['data']

        stats: list[Py9.Stat] = []
        offset = 0

        while offset < len(data):
            stat = Py9.Stat.from_bytes(data[offset:])
            offset += stat.size + 2
            stats.append(stat)
        return stats

    def __del__(self) -> None:
        self.socket.shutdown(socket.SHUT_RDWR)
        time.sleep(1)
        self.socket.close()
