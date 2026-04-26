from transport import Transport
import framing
from protocol import MessageID
import struct
from crypto import Crypto

class Session:
    def __init__(self, transport: Transport):
        self._transport = transport
        self._crypto = Crypto()

    def _receive_frame(self) -> tuple[MessageID, bytes]:
        header = self._transport.receive(framing.HEADER_SIZE)
        payload_len = framing.get_payload_len_from_header(header)
        rest = self._transport.receive(payload_len + framing.CHECKSUM_SIZE)
        full_frame = header + rest 
        print(f"Received frame: {full_frame.hex(' ').upper()}")
        return framing.parse_frame(full_frame)
    
    def _expect_frame(self, expected_id: MessageID) -> bytes:
        msg_id, payload = self._receive_frame()
        if msg_id != expected_id:
            raise ValueError(f"Expected {expected_id.name}, got {msg_id.name}")
        
        return payload

    def open(self) -> None:
        frame = framing.build_frame(MessageID.SESSION_OPEN, b'\x41')
        self._transport.send(frame)

        # receive nothing

    def exchange_keys(self) -> None:
        frame = framing.build_frame(MessageID.KEY_EXCHANGE, self._crypto.public_key())
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.KEY_EXCHANGE)
        self._crypto.compute_shared_key(payload)

    def exchange_pin(self, pin: str) -> bool:
        plaintext = pin.encode('ascii')
        frame = framing.build_frame(MessageID.PIN_EXCHANGE, plaintext)    
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.PIN_ACK)
        return payload == b'\x00'
    
    def close(self) -> None: 
        frame = framing.build_frame(MessageID.SESSION_CLOSE, b'')
        self._transport.send(frame)

        # receive nothing

    def write(self, local_path: str, file_id: str) -> bool:
        with open(local_path, 'rb') as f:
            file_content = f.read()
            if len(file_content) != 88:
                print(f"File must be exactly 88 bytes, got {len(file_content)}")
                return False

        print(f"Requesting write for file ID {file_id}...")
        file_id_bytes = struct.pack("B", int(file_id))
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x77' + file_id_bytes) # 0x77 at the beginning specifies write
        self._transport.send(frame)
        payload = self._expect_frame(MessageID.FILE_REQ_ACK) 

        if payload != b'\x00':
            print("File request rejected by HSM")
            return False

        print("Sending file contents...")
        frame = framing.build_frame(MessageID.FILE_CONTENT, file_content)
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.FILE_COMPLETE_ACK) 
        if payload != b'\x00':
            print("File transfer failed: CRC mismatch report by HSM")
            return False

        print("Write successful.")        
        return True

    def read(self, local_path: str, file_id: str) -> bool:
        print(f"Requesting read for file ID {file_id}...")
        file_id_bytes = struct.pack("B", int(file_id))
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x72' + file_id_bytes) # 0x72 at the beginning specifies read
        self._transport.send(frame)
        payload = self._expect_frame(MessageID.FILE_REQ_ACK) 

        if payload != b'\x00':
            print("File request rejected by HSM")
            return False

        print("Sending file contents...")
        try:
            file_content = self._expect_frame(MessageID.FILE_CONTENT)
        except ValueError as e:
            # technically this catches also other exceptions, not just checksum mismatches
            # I think it's an acceptable behavior
            frame = framing.build_frame(MessageID.FILE_COMPLETE_ACK, b'\x01') # checksum mismatch
            self._transport.send(frame)
            raise e

        with open(local_path, 'wb') as f:
            f.write(file_content)

        print("Read successful, saved to {local_path}")   
        return True 