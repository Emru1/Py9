from abc import abstractmethod

import selectors
import socket
import struct

from trs import TRs
from qid import Qid
from stat9 import Stat

from utils import (
    encode_string,
    STR_LEN,
)


class Py9:
    # http://man.cat-v.org/plan_9/5
    # http://9p.cat-v.org/documentation/rfc/
    # http://man.9front.org/5/

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
        self.socket: socket.socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
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
        operation: TRs = TRs(struct.unpack('<B', buf[0:1])[0])
        tag: int = struct.unpack('<H', buf[1:3])[0]
        other_data: dict = self._parse_data(operation, buf[3:])

        return {
            'operation': operation,
            'tag': tag,
        } | other_data

    def _decode_qid(self, qid: bytes) -> dict:
        _type: int = struct.unpack('<B', qid[0:1])[0]
        version: int = struct.unpack('<I', qid[1:5])[0]
        path: int = struct.unpack('<Q', qid[5:13])[0]

        ret = {
            '_type': _type,
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
            case TRs.Tversion:
                msize: int = struct.unpack('<I', data[0:4])[0]
                version_len: int = struct.unpack('<H', data[4:6])[0]
                version: bytes = data[4 + STR_LEN:4 + STR_LEN + version_len]

                ret = {
                    'msize': msize,
                    'version': version,
                }

            case TRs.Rversion:
                msize: int = struct.unpack('<I', data[0:4])[0]
                version_len: int = struct.unpack('<H', data[4:6])[0]
                version: bytes = data[4 + STR_LEN:4 + STR_LEN + version_len]

                ret = {
                    'msize': msize,
                    'version': version,
                }

            case TRs.Tauth:
                uname_len: int = struct.unpack('<H', data[4: 4 + STR_LEN])[0]
                aname_len: int = struct.unpack(
                    '<H',
                    data[4 + STR_LEN + uname_len:
                         4 + STR_LEN + uname_len + STR_LEN])[0]

                afid: int = struct.unpack('<I', data[0:4])[0]
                uname: bytes = data[4 + STR_LEN: 4 + STR_LEN + uname_len]
                aname: bytes = data[4 + STR_LEN + uname_len + STR_LEN:
                                    4 + STR_LEN + uname_len + STR_LEN +
                                    aname_len]

                ret = {
                    'afid': afid,
                    'uname': uname,
                    'aname': aname,
                }

            case TRs.Rauth:
                aqid: bytes = data[0:13]

                ret = {
                    'aqid': aqid,
                }

            case TRs.Tattach:
                uname_len: int = struct.unpack('<H', data[8: 8 + STR_LEN])[0]
                aname_len: int = struct.unpack(
                    '<H',
                    data[8 + STR_LEN + uname_len:
                         8 + STR_LEN + uname_len + STR_LEN])[0]

                fid: int = struct.unpack('<I', data[0:4])[0]
                afid: int = struct.unpack('<I', data[4:8])[0]
                uname: bytes = data[8 + STR_LEN: 8 + STR_LEN + uname_len]
                aname: bytes = data[8 + STR_LEN + uname_len + STR_LEN:
                                    8 + STR_LEN + uname_len + STR_LEN +
                                    aname_len]

                ret = {
                    'fid': fid,
                    'afid': afid,
                    'uname': uname,
                    'aname': aname,
                }

            case TRs.Rattach:
                qid: bytes = data[0:13]

                ret = {
                    'qid': Qid.from_bytes(qid),
                }

            case TRs.Terror:
                raise Exception('There is no Terror code')

            case TRs.Rerror:
                ename_len: int = struct.unpack('<H', data[0:0 + STR_LEN])[0]

                ename: bytes = data[0 + STR_LEN:0 + STR_LEN + ename_len]

                ret = {
                    'ename': ename,
                }

            case TRs.Tflush:
                oldtag: int = struct.unpack('<H', data[0:2])[0]

                ret = {
                    'oldtag': oldtag,
                }

            case TRs.Rflush:
                ret = {}

            case TRs.Twalk:
                fid: int = struct.unpack('<I', data[0:4])[0]
                newfid: int = struct.unpack('<I', data[4:8])[0]
                nwname: int = struct.unpack('<H', data[8:10])[0]

                wnames: list = []
                offset: int = 10

                for _ in range(nwname):
                    wname_len = struct.unpack(
                        '<H', data[offset:offset + STR_LEN])[0]
                    wname: bytes = data[offset + STR_LEN:
                                        offset + STR_LEN + wname_len]
                    wnames.append(wname)
                    offset += wname_len + STR_LEN

                ret = {
                    'fid': fid,
                    'newfid': newfid,
                    'nwname': nwname,
                    'wnames': wnames,
                }

            case TRs.Rwalk:
                nwqid: int = struct.unpack('<H', data[0:2])[0]

                qids: list = []
                offset: int = 2

                for _ in range(nwqid):
                    qid: bytes = data[offset:offset + 13]
                    qids.append(Qid.from_bytes(qid))
                    offset += 13

                ret = {
                    'qids': qids,
                }

            case TRs.Topen:
                fid: int = struct.unpack('<I', data[0:4])[0]
                mode: int = struct.unpack('<B', data[4:5])[0]

                ret = {
                    'fid': fid,
                    'mode': mode,
                }

            case TRs.Ropen:
                qid: bytes = data[0:13]
                iounit: int = struct.unpack('<I', data[13:17])[0]

                ret = {
                    'qid': Qid.from_bytes(qid),
                    'iounit': iounit,
                }

            case TRs.Tcreate:
                name_len = struct.unpack('<H', data[4:4 + STR_LEN])[0]

                fid: int = struct.unpack('<I', data[0:4])[0]
                name: bytes = data[4 + STR_LEN:4 + STR_LEN + name_len]
                perm: int = struct.unpack(
                    '<I',
                    data[4 + STR_LEN + name_len:
                         4 + STR_LEN + name_len + 4])[0]
                mode: int = struct.unpack(
                    '<B',
                    data[4 + STR_LEN + name_len + 4:
                         4 + STR_LEN + name_len + 4 + 1])[0]

                ret = {
                    'fid': fid,
                    'name': name,
                    'perm': perm,
                    'mode': mode,
                }

            case TRs.Rcreate:
                qid: bytes = data[0:13]
                iounit: bytes = data[13:17]

                ret = {
                    'qid': Qid.from_bytes(qid),
                    'iounit': iounit,
                }

            case TRs.Tread:
                fid: int = struct.unpack('<I', data[0:4])[0]
                offset: int = struct.unpack('<Q', data[4:12])[0]
                count: int = struct.unpack('<I', data[12:16])[0]

                ret = {
                    'fid': fid,
                    'offset': offset,
                    'count': count,
                }

            case TRs.Rread:
                count: int = struct.unpack('<I', data[0:4])[0]
                _data: bytes = data[4:4 + count]

                ret = {
                    'count': count,
                    'data': _data,
                }

            case TRs.Twrite:
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

            case TRs.Rwrite:
                count: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'count': count,
                }

            case TRs.Tclunk:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case TRs.Rclunk:
                ret = {}

            case TRs.Tremove:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case TRs.Rremove:
                ret = {}

            case TRs.Tstat:
                fid: int = struct.unpack('<I', data[0:4])[0]

                ret = {
                    'fid': fid,
                }

            case TRs.Rstat:
                stat_len: int = struct.unpack('<H', data[0:2])[0]
                stats: bytes = data[0 + STR_LEN:0 + STR_LEN + stat_len]

                ret = {
                    'stat': Stat.from_bytes(stats),
                }

            case TRs.Twstat:
                fid: int = struct.unpack('<I', data[0:4])[0]
                stat: bytes = data[4:]

                ret = {
                    'fid': fid,
                    'stat': stat,
                }

            case TRs.Rwstat:
                ret = {}

            case _:
                raise Exception('No such operation')
        return ret

    def _encode_packet(
            self,
            _type,
            data: bytes,
            tag: bytes = None,
    ) -> bytes:
        size: bytes = struct.pack('<I', len(data) + 7)
        t: bytes = struct.pack('<B', _type.value)
        if not tag:
            tag = self.get_tag()

        if isinstance(tag, int):
            tag: bytes = struct.pack('<H', tag)

        return size + t + tag + data

    def _encode_Tversion(self) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', self.msize)
        buff += struct.pack('<H', len(self._version))
        buff += self._version.encode()

        return self._encode_packet(TRs.Tversion, buff)

    def _encode_Rversion(self, tag: int) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', self.msize)
        buff += struct.pack('<H', len(self._version))
        buff += self._version.encode()

        return self._encode_packet(TRs.Rversion, buff, tag)

    def _encode_Tauth(self, afid: int, uname: str, aname: str) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', afid)
        buff += encode_string(uname)
        buff += encode_string(aname)

        return self._encode_packet(TRs.Tauth, buff)

    def _encode_Rauth(self, aqid: Qid, tag: int) -> bytes:
        buff: bytes = b''

        buff += aqid.to_bytes()

        return self._encode_packet(TRs.Rauth, tag)

    def _encode_Rerror(self, ename: str, tag: int) -> bytes:
        buff: bytes = b''

        buff += encode_string(ename)

        return self._encode_packet(TRs.Rerror, tag)

    def _encode_Tflush(
            self,
            oldtag: int
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<H', oldtag)

        return self._encode_packet(TRs.Tflush, buff)

    def _encode_Rflush(
            self,
            tag: int
    ) -> bytes:
        buff: bytes = b''

        return self._encode_packet(TRs.Rflush, buff, tag)

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
        buff += encode_string(uname)
        buff += encode_string(aname)

        return self._encode_packet(TRs.Tattach, buff)

    def _encode_Rattach(
            self,
            qid: Qid,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += qid.to_bytes()

        return self._encode_packet(TRs.Rattach, buff, tag)

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
            buff += encode_string(name)

        return self._encode_packet(TRs.Twalk, buff)

    def _encode_Rwalk(
            self,
            nwqids: list[Qid],
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', len(nwqids))

        for nwqid in nwqids:
            buff += nwqid.to_bytes()

        return self._encode_packet(TRs.Rwalk, buff, tag)

    def _encode_Topen(
            self,
            fid: int,
            mode: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += struct.pack('<B', mode)

        return self._encode_packet(TRs.Topen, buff)

    def _encode_Ropen(
            self,
            qid: Qid,
            iounit: int,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += qid.to_bytes()
        buff += struct.pack('<I', iounit)

        return self._encode_packet(TRs.Ropen, buff, tag)

    def _encode_Tcreate(
            self,
            fid: int,
            name: str,
            perm: int,
            mode: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += encode_string(name)
        buff += struct.pack('<I', perm)
        buff += struct.pack('<B', mode)

        return self._encode_packet(TRs.Tcreate, buff)

    def _encode_Rcreate(
            self,
            qid: Qid,
            iounit: int,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += qid.to_bytes()
        buff += struct.pack('<I', iounit)

        return self._encode_packet(TRs.Rcreate, buff, tag)

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

        return self._encode_packet(TRs.Tread, buff)

    def _encode_Rread(
            self,
            data: bytes,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', len(data))
        buff += data

        return self._encode_packet(TRs.Rread, buff, tag)

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

        return self._encode_packet(TRs.Twrite, buff)

    def _encode_Rwrite(
            self,
            count: int,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', count)

        return self._encode_packet(TRs.Rwrite, buff, tag)

    def _encode_Tclunk(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(TRs.Tclunk, buff)

    def _encode_Rclunk(
            self,
            tag: int
    ) -> bytes:
        buff: bytes = b''

        return self._encode_packet(TRs.Rclunk, buff, tag)

    def _encode_Tremove(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(TRs.Tremove, buff)

    def _encode_Rremove(
            self,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        return self._encode_packet(TRs.Rremove, buff, tag)

    def _encode_Tstat(
            self,
            fid: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)

        return self._encode_packet(TRs.Tstat, buff)

    def _encode_Rstat(
            self,
            stats: list[Stat],
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<H', len(stats))

        for stat in stats:
            buff += stat.to_bytes()

        return self._encode_packet(TRs.Rstat, buff, tag)

    def _encode_Twstat(
            self,
            fid: int,
            stat: Stat,
    ) -> bytes:
        buff: bytes = b''

        buff += struct.pack('<I', fid)
        buff += stat.to_bytes()

        return self._encode_packet(TRs.Tremove, buff)

    def _encode_Rwstat(
            self,
            tag: int,
    ) -> bytes:
        buff: bytes = b''

        return self._encode_packet(TRs.Rremove, buff, tag)

    @abstractmethod
    def __del__(self):
        ...
