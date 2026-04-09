import struct
import crcmod

from protocol import MessageID

SOF = b'\xAA'
HEADER_SIZE = 3    # SOF(1) + msg_id(1) + payload_len(1)
CHECKSUM_SIZE = 2
_crc16 = crcmod.mkCrcFun(0x11021, 0xFFFF, rev=False)

# len(payload) must be <= 255 bytes
def build_frame(msg_id: MessageID, payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("payload is larger than 255 bytes")


    checksum = crc(payload) if payload else 0x0000
    
    # TODO: check endianness    
    
    # > is big endian, B is unsigned 1 byte, H is unsigned 2 bytes
    frame = (
        SOF                             +
        struct.pack("B", msg_id)       +
        struct.pack("B", len(payload)) +
        payload                         +
        struct.pack(">H", checksum)
    )
    return frame

# first byte needs to be 0xAA
def parse_frame(data: bytes) -> tuple[MessageID, bytes]:
    if len(data) < HEADER_SIZE:
        raise ValueError("Received frame shorter than header size")

    # SOF[0] = 0xAA, indexing a bytes returns an int
    if data[0] != SOF[0]:
        raise ValueError("Invalid SOF")
    msg_id = data[1]
    payload_len = data[2]
    payload = data[HEADER_SIZE : HEADER_SIZE + payload_len]
    # > is big endian, H is unsigned 2 bytes
    checksum = struct.unpack(">H", data[HEADER_SIZE + payload_len:])[0]

    expected = crc(payload) if payload else 0x0000    
    if checksum != expected:
        raise ValueError("Invalid checksum")

    return MessageID(msg_id), payload

def get_payload_len_from_header(header: bytes) -> int:
    return header[2]

# TODO: the documentation says "If there is no payload, the checksum field should be 0x00."
# Does this mean that the crc of any empty field should manually be forced to 0x00 (i.e. if check down here).
# Or that if the message is without a payload, the crc should be 0x00. If there is a payload and the payload 
# is 0x00, the crc is normally computed. (Right now I'm doing the second one)
def crc(data: bytes) -> int:
    # using seed 0xFFFF and no reversed algorithm. Needs to match the config on HSM
    # (crcmod documentation says reversed algorithm is faster)
    return _crc16(data)