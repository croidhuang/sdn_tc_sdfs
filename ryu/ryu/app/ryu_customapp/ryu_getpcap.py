import struct
import sys
import time


class PcapFileHdr(object):
 
    _FILE_HDR_FMT = '4sHHIIII'
    _FILE_HDR_FMT_BIG_ENDIAN = '>' + _FILE_HDR_FMT
    _FILE_HDR_FMT_LITTLE_ENDIAN = '<' + _FILE_HDR_FMT
    FILE_HDR_SIZE = struct.calcsize(_FILE_HDR_FMT)

    # Magic Number field is used to detect the file format itself and
    # the byte ordering.
    MAGIC_NUMBER_IDENTICAL = b'\xa1\xb2\xc3\xd4'  # Big Endian
    MAGIC_NUMBER_SWAPPED = b'\xd4\xc3\xb2\xa1'    # Little Endian

    def __init__(self, magic=MAGIC_NUMBER_SWAPPED, version_major=2,
                 version_minor=4, thiszone=0, sigfigs=0, snaplen=0,
                 network=0):
        self.magic = magic
        self.version_major = version_major
        self.version_minor = version_minor
        self.thiszone = thiszone
        self.sigfigs = sigfigs
        self.snaplen = snaplen
        self.network = network

    @classmethod
    def parser(cls, buf):
        magic_buf = buf[:4]
        if magic_buf == cls.MAGIC_NUMBER_IDENTICAL:
            # Big Endian
            fmt = cls._FILE_HDR_FMT_BIG_ENDIAN
            byteorder = 'big'
        elif magic_buf == cls.MAGIC_NUMBER_SWAPPED:
            # Little Endian
            fmt = cls._FILE_HDR_FMT_LITTLE_ENDIAN
            byteorder = 'little'
        else:
            raise struct.error('Invalid byte ordered pcap file.')

        return cls(*struct.unpack_from(fmt, buf)), byteorder

    def serialize(self):
        if sys.byteorder == 'big':
            # Big Endian
            fmt = self._FILE_HDR_FMT_BIG_ENDIAN
            self.magic = self.MAGIC_NUMBER_IDENTICAL
        else:
            # Little Endian
            fmt = self._FILE_HDR_FMT_LITTLE_ENDIAN
            self.magic = self.MAGIC_NUMBER_SWAPPED

        return struct.pack(fmt, self.magic, self.version_major,
                           self.version_minor, self.thiszone,
                           self.sigfigs, self.snaplen, self.network)


class PcapPktHdr(object):

    _PKT_HDR_FMT = 'IIII'
    _PKT_HDR_FMT_BIG_ENDIAN = '>' + _PKT_HDR_FMT
    _PKT_HDR_FMT_LITTLE_ENDIAN = '<' + _PKT_HDR_FMT
    PKT_HDR_SIZE = struct.calcsize(_PKT_HDR_FMT)

    def __init__(self, ts_sec=0, ts_usec=0, incl_len=0, orig_len=0):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.incl_len = incl_len
        self.orig_len = orig_len

    @classmethod
    def parser(cls, buf, byteorder='little'):
        if not buf:
            raise IndexError('No data')

        if byteorder == 'big':
            # Big Endian
            fmt = cls._PKT_HDR_FMT_BIG_ENDIAN
        else:
            # Little Endian
            fmt = cls._PKT_HDR_FMT_LITTLE_ENDIAN

        (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack_from(fmt, buf)
        hdr = cls(ts_sec, ts_usec, incl_len, orig_len)

        return hdr, buf[cls.PKT_HDR_SIZE:cls.PKT_HDR_SIZE + incl_len]

    def serialize(self):
        if sys.byteorder == 'big':
            # Big Endian
            fmt = self._PKT_HDR_FMT_BIG_ENDIAN
        else:
            # Little Endian
            fmt = self._PKT_HDR_FMT_LITTLE_ENDIAN

        return struct.pack(fmt, self.ts_sec, self.ts_usec,
                           self.incl_len, self.orig_len)


class Reader(object):

    def __init__(self, file_obj):
        self._fp = file_obj
        buf = self._fp.read(PcapFileHdr.FILE_HDR_SIZE)
        # Read only pcap file header
        self.pcap_header, self._file_byteorder = PcapFileHdr.parser(buf)
        # Read pcap data with out header
        self._pcap_body = self._fp.read()
        self._fp.close()
        self._next_pos = 0

    def __iter__(self):
        return self

    def next(self):
        try:
            pkt_hdr, pkt_data = PcapPktHdr.parser(
                self._pcap_body[self._next_pos:], self._file_byteorder)
            self._next_pos += pkt_hdr.incl_len + PcapPktHdr.PKT_HDR_SIZE

        except IndexError:
            raise StopIteration()

        return pkt_hdr.ts_sec + (pkt_hdr.ts_usec / 1e6), pkt_data

    # for Python 3 compatible
    __next__ = next


class Writer(object):

    def __init__(self, file_obj, snaplen=65535, network=1):
        self._f = file_obj
        self.snaplen = snaplen
        self.network = network
        self._write_pcap_file_hdr()

    def _write_pcap_file_hdr(self):
        pcap_file_hdr = PcapFileHdr(snaplen=self.snaplen,
                                    network=self.network)
        self._f.write(pcap_file_hdr.serialize())

    def _write_pkt_hdr(self, ts, buf_len):
        sec = int(ts)
        usec = int(round(ts % 1, 6) * 1e6) if sec != 0 else 0

        pc_pkt_hdr = PcapPktHdr(ts_sec=sec, ts_usec=usec,
                                incl_len=buf_len, orig_len=buf_len)

        self._f.write(pc_pkt_hdr.serialize())

    def write_pkt(self, buf, ts=None):
        ts = time.time() if ts is None else ts

        # Check the max length of captured packets
        buf_len = len(buf)
        if buf_len > self.snaplen:
            buf_len = self.snaplen
            buf = buf[:self.snaplen]

        self._write_pkt_hdr(ts, buf_len)

        self._f.write(buf)

    def __del__(self):
        self._f.close()
