import struct
import crcmod

from protocol import MessageID

SOF = b'\xaa\xaa'
HEADER_SIZE = 6     # SOF(2) + msg_id(2) + payload_len(2)
CHECKSUM_SIZE = 2
_crc16 = crcmod.mkCrcFun(0x11021, 0xFFFF, rev=False)

# assumes len(payload) <= 1024 bytes
def build_frame(msg_id: MessageID, payload: bytes) -> bytes:
    checksum = crc(payload) if payload else 0x0000
    
    # TODO: check endianness    
    
    # > is big endian, H is unsigned 2 bytes
    frame = (
        SOF                             +
        struct.pack(">H", msg_id)       +
        struct.pack(">H", len(payload)) +
        payload                         +
        struct.pack(">H", checksum)
    )
    return frame

# first two bytes need to be 0xAA
def parse_frame(data: bytes) -> tuple[MessageID, bytes]:
    if data[:2] != b'\xAA\xAA':
        raise ValueError("Invalid SOF")
    # > is big endian, H is unsigned 2 bytes
    msg_id = struct.unpack(">H", data[2:4])[0]
    payload_len = struct.unpack(">H", data[4:6])[0]
    payload = data[6 : 6 + payload_len]
    checksum = struct.unpack(">H", data[6 + payload_len:])[0]

    expected = crc(payload) if payload else 0x0000    
    if checksum != expected:
        raise ValueError("Invalid checksum")

    return MessageID(msg_id), payload

def get_payload_len_from_header(header: bytes) -> int:
    return struct.unpack(">H", header[4:6])[0]

# TODO: the documentation says "If there is no payload, the checksum field should be 0x00."
# Does this mean that the crc of any empty field should manually be forced to 0x00 (i.e. if check down here).
# Or that if the message is without a payload, the crc should be 0x00. If there is a payload and the payload 
# is 0x00, the crc is normally computed. (Right now I'm doing the second one)
def crc(data: bytes) -> int:
    # using seed 0xFFFF and no reversed algorithm. Needs to match the config on HSM
    # (crcmod documentation says reversed algorithm is faster)
    return _crc16(data)