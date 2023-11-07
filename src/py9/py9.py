from enum import Enum
from abc import abstractmethod

import selectors
import socket
import struct

STR_LEN=2


class Py9:

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

    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
    ) -> None:
        self.ip = ip
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.selector.register(self.socket, selectors.EVENT_READ)

        self.msize = msize

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
        size: int = struct.unpack('<I', self._recv_n(4))
        buf: bytes = self._recv_n(sock, size - 4)
        operation: self.TRs = self.TRs(int(buf[0]))
        tag: int = struct.unpack('<H', buf[1:3])
        other_data: dict = self._parse_data(operation, buf[3:])

        return {
            'operation': operation,
            'tag': tag,
        } | other_data

    def _parse_data(
            self,
            operation,
            data: bytes,
    ) -> dict:
        ret: dict
        match operation:
            case self.TRs.Tversion:
                ret = {
                    'msize': struct.unpack('<I', data[0:4]),
                    'version': data[4:].decode(),
                }

            case self.TRs.Rversion:
                ret = {
                    'msize': struct.unpack('<I', data[0:4]),
                    'version': data[4:].decode(),
                }

            case self.TRs.Tauth:
                uname_len: int = struct.unpack(
                    '<H',
                    data[
                        4:
                        4 + STR_LEN
                    ]
                )
                aname_len: int = struct.unpack(
                    '<H',
                    data[
                        4 + STR_LEN + uname_len:
                        4 + STR_LEN + uname_len + STR_LEN
                    ]
                )
                ret = {
                    'afid': struct.unpack('<I', data[0:4]),
                    'uname': struct.unpack(
                        '<s',
                        data[
                            4 + STR_LEN:
                            4 + STR_LEN + uname_len
                        ],
                    ),
                    'aname': struct.unpack(
                        '<s',
                        data[
                            4 + STR_LEN + uname_len + STR_LEN:
                            4 + STR_LEN + uname_len + STR_LEN + aname_len
                        ]
                    ),
                }

            case self.TRs.Rauth:
                ret = {
                    'aqid': struct.unpack('<s', data[0:13]),
                }

            case self.TRs.Tattach:
                uname_len: int = struct.unpack(
                    '<H',
                    data[
                        8:
                        8 + STR_LEN
                    ]
                )
                aname_len: int = struct.unpack(
                    '<H',
                    data[
                        8 + STR_LEN + uname_len:
                        8 + STR_LEN + uname_len + STR_LEN
                    ]
                )
                ret = {
                    'fid': struct.unpack('<I', data[0:4]),
                    'afid': struct.unpack('<I', data[4:8]),
                    'uname': struct.unpack(
                        '<s',
                        data[
                            8 + STR_LEN:
                            8 + STR_LEN + uname_len
                        ]
                    ),
                    'aname': struct.unpack(
                        '<s',
                        data[
                            8 + STR_LEN + uname_len + STR_LEN:
                            8 + STR_LEN + uname_len + STR_LEN + aname_len
                        ]
                    ),
                }

            case self.TRs.Rattach:
                ret = {
                    'qid': struct.unpack('<s', data[0:13]),
                }

            case self.TRs.Terror:
                raise Exception('There is no Terror code')

            case self.TRs.Rerror:
                ename_len: int = struct.unpack('<H', data[0:0 + STR_LEN])
                ret = {
                    'ename': struct.unpack(
                        '<s',
                        data[0 + STR_LEN:0 + STR_LEN + ename_len]
                    ),
                }

            case self.TRs.Tflush:
                ret = {
                    'oldtag': struct.unpack('<H', data[0:2]),
                }

            case self.TRs.Rflush:
                ret = {}

            case self.TRs.Twalk:
                nwname: int = struct.unpack('<H', data[8:10])

                wnames: list = []
                offset: int = 10
                for _ in range(nwname):
                    wname_len = struct.unpack(
                        '<H',
                        data[offset:offset + STR_LEN]
                    )
                    wname = struct.unpack(
                        '<s',
                        data[offset + STR_LEN:offset + STR_LEN + wname_len]
                    )
                    wnames.append(wname)
                    offset += wname_len + STR_LEN

                ret = {
                    'fid': struct.unpack('<I', data[0:4]),
                    'newfid': struct.unpack('<I', data[4:8]),
                    'nwname': nwname,
                    'wnames': wnames,
                }

            case self.TRs.Rwalk:
                nwqid: int = struct.unpack('<H', data[0:2])

                qids: list = []
                offset: int = 2

                for _ in range(nwqid):
                    qid_len = struct.unpack(
                        '<H',
                        data[offset:offset + STR_LEN]
                    )
                    qid = struct.unpack(
                        '<s',
                        data[offset + STR_LEN:offset + STR_LEN + qid_len]
                    )
                    qids.append(qid)
                    offset += qid_len + STR_LEN

                ret = {
                    'nwqid': nwqid,
                    'qids': qids,
                }

            case self.TRs.Topen:
                ret = {
                    'fid': struct.unpack('<I', data[0:4]),
                    'mode': struct.unpack('<B', data[4:5]),
                }

            case self.TRs.Ropen:
                ret = {
                    'qid': struct.unpack('<s', data[0:13]),
                    'iounit': struct.unpack('<I', data[13:17]),
                }

            case self.TRs.Tcreate:
                name_len = struct.unpack('<H', data[4:4 + STR_LEN])
                ret = {
                    'fid': struct.unpack('<I', data[0:4]),
                    'name': struct.unpack(
                        '<s',
                        data[4 + STR_LEN:4 + STR_LEN + name_len]
                    ),
                    'perm': struct.unpack(
                        '<I',
                        data[4 + STR_LEN + name_len:4 + STR_LEN + name_len + 4]
                    ),
                    'mode': struct.unpack(
                        '<B',
                        data[
                            4 + STR_LEN + name_len + 4:
                            4 + STR_LEN + name_len + 4 + 1
                        ]
                    )
                }

            case self.TRs.Rcreate:
                ret = {
                    'qid': struct.decode('<s', data[0:13]),
                    'iounit': struct.decode('<s', data[13:17]),
                }

            case self.TRs.Tread:
                ret = {
                    'fid': struct.decode('<I', data[0:4]),
                    'offset': struct.decode('<Q', data[4:12]),
                    'count': struct.decode('<I', data[12:16]),
                }

            case self.TRs.Rread:
                count = struct.decode('<I', data[0:4])
                ret = {
                    'count': count,
                    'data': struct.decode('<s', data[4:4 + count]),
                }

            case self.TRs.Twrite:
                ...

            case self.TRs.Rwrite:
                ...
            case self.TRs.Tclunk:
                ...
            case self.TRs.Rclunk:
                ...
            case self.TRs.Tremove:
                ...
            case self.TRs.Rremove:
                ...
            case self.TRs.Tstat:
                ...
            case self.TRs.Rstat:
                ...
            case self.TRs.Twstat:
                ...
            case self.TRs.Rwstat:
                ...
            case _:
                raise Exception('No such operation')
        return ret

    @abstractmethod
    def connect(self):
        ...


class Py9Client(Py9):
    def __init__(
            self,
            ip: str,
            port: int,
            msize: int = 32768,
    ) -> None:
        super().__init__(self, ip, port, msize)
        self.socket.connect((self.ip, self.port))

    def recv(self) -> dict:
        return self._recv(self.socket)
