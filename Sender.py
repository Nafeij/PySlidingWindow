import sys
from zlib import crc32
from dataclasses import dataclass
import socket

# GBN with two key modifications:
#   1. Sel. Rep. buffering  :   reciever buffers out-of-order packets
#   2. RFC 2001 fast retrans:   immediately retrans on Nth duplicate ack

# fix-len header (8 byte check# + 2 byte seq#), sent in hex
# seq# are sent serialized (i.e. can wrap around without side-effects),
#   allowing for unlimited total size & # of msgs
#   https://en.wikipedia.org/wiki/Serial_number_arithmetic
#   https://en.wikipedia.org/wiki/Sliding_window_protocol#Sequence_number_range_required

CSUM_BYTES = 8  # len(hex(crc32))
SNUM_BYTES = 2  # len(hex(MAX_SNUM))
MAX_PKT_BYTES = 64
MAX_CSUM = 16 ** CSUM_BYTES - 1
MAX_SNUM = 16 ** SNUM_BYTES - 1
MAX_CONT = MAX_PKT_BYTES - CSUM_BYTES - SNUM_BYTES
MAX_WINDOW_SIZE = 2 ** (SNUM_BYTES - 1) * 8 ** SNUM_BYTES  # 1/2 of # possible SNUMs or MAX_SNUM + 1
N = MAX_SNUM + 1
WINDOW_SIZE = MAX_WINDOW_SIZE
#    can be lower if consec lost pkts are uncommon (i.e. in reliable networks)

MAX_DUPLICATES = 1
ACK_SIZE = SNUM_BYTES + CSUM_BYTES

inpBuffer = bytearray()
n_a = 0  # lowest not acked
n_t = 0  # lowest not transmted
# n_t <= n_a + WINDOW_SIZE
awaitAck = list()


def bPush(byteStr):
    global inpBuffer
    inpBuffer += byteStr


def bPop(n):
    global inpBuffer
    o = inpBuffer[:n]
    inpBuffer = inpBuffer[n:]
    return o


def cSumToHexStr(csum):
    if csum > MAX_CSUM or csum < 0: raise ValueError("checksum out of range")
    return format(csum, f'#0{CSUM_BYTES + 2}x')[2:]


def hexStrToCSum(hexstring):
    if len(hexstring) != CSUM_BYTES: raise ValueError("checksum hexstr len mismatch")
    stripped = hexstring.lstrip('0')
    return int(stripped, 16) if stripped else 0


def sNumToHexStr(snum):
    if snum > MAX_SNUM or snum < 0: raise ValueError("seq num out of range")
    return format(snum, f'#0{SNUM_BYTES + 2}x')[2:]


def hexStrToSNum(hexstring):
    if len(hexstring) != SNUM_BYTES: raise ValueError("seq num hexstr len mismatch")
    stripped = hexstring.lstrip('0')
    return int(stripped, 16) if stripped else 0


def parsePacket(rawStr):
    header = rawStr[:CSUM_BYTES + SNUM_BYTES].decode('ascii')
    return hexStrToCSum(header[:CSUM_BYTES]), \
           hexStrToSNum(header[CSUM_BYTES:CSUM_BYTES + SNUM_BYTES]), \
           rawStr[CSUM_BYTES + SNUM_BYTES:]


@dataclass
class Frame:
    cSum: int
    sNum: int
    cont: bytes
    check: bool = None

    def __post_init__(self):
        if self.check is None:
            self.check = self.verify()

    @classmethod
    def fromBytes(cls, cont, sNum):
        if not 0 <= len(cont) <= MAX_CONT:
            raise ValueError("frame content size mismatch")
        return cls(cSum=crc32(str(sNum).encode('ascii') + cont), sNum=sNum, cont=cont, check=True)

    @classmethod
    def fromPacket(cls, rawStr):
        c, sn, ct = parsePacket(rawStr)
        return cls(cSum=c, sNum=sn, cont=ct)

    def toBytes(self) -> bytes:
        return (cSumToHexStr(self.cSum) + sNumToHexStr(self.sNum)).encode('ascii') + self.cont

    def verify(self) -> bool:
        return crc32(str(self.sNum).encode('ascii') + self.cont) == self.cSum


def makeFrame(a):
    while len(inpBuffer) < MAX_CONT:
        try:
            inp = input()
        except EOFError:
            break
        bPush(bytes(inp + '\n', 'ascii'))
    if not inpBuffer:
        return None
    return Frame.fromBytes(bytes(bPop(MAX_CONT)), a)


def recvBufferClear(soc):
    soc.setblocking(False)
    while True:
        try:
            soc.recv(4096)
        except BlockingIOError:
            break
    soc.setblocking(True)


def serialLessThan(a, b):
    return (a < b and b - a < WINDOW_SIZE) or (a > b and a - b > WINDOW_SIZE)


def serialBetween(a, b, c):
    return (a == b or serialLessThan(a, b)) and (b == c or serialLessThan(b, c))


if __name__ == "__main__":
    s = socket.socket(type=socket.SOCK_DGRAM)
    port = int(sys.argv[1])
    hasData = True
    dup = 0

    while hasData or awaitAck:
        while hasData and n_t < n_a + WINDOW_SIZE:
            frame = makeFrame(n_t % N)
            if not frame:
                hasData = False
            else:
                s.settimeout(None)
                s.sendto(frame.toBytes(), ('localhost', port))
                awaitAck.append(frame)
                n_t += 1
        try:
            s.settimeout(.05)
            r = s.recv(ACK_SIZE)
            ackFrame = Frame.fromPacket(r)
            if not ackFrame.check:
                raise ValueError
            numAcked = (ackFrame.sNum - n_a) % N
            if not numAcked:
                if dup >= MAX_DUPLICATES:
                    recvBufferClear(s)
                    dup = 0
                    raise ValueError
                dup += 1
                continue
        except (ValueError, TimeoutError):
            s.settimeout(None)
            for aw in awaitAck:
                s.sendto(aw.toBytes(), ('localhost', port))
        else:
            awaitAck = awaitAck[numAcked:]
            n_a += numAcked
    s.sendto(b'', ('localhost', port))
    s.close()
