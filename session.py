from transport import Transport
import framing
from protocol import MessageID
import struct
from crypto import Crypto

class Session:
    def __init__(self, transport: Transport, debug: bool):
        self._transport = transport
        self._crypto = Crypto()
        self._debug = debug

    def _receive_frame(self) -> tuple[MessageID, bytes]:
        header = self._transport.receive(framing.HEADER_SIZE)
        payload_len = framing.get_payload_len_from_header(header)
        rest = self._transport.receive(payload_len + framing.CHECKSUM_SIZE)
        full_frame = header + rest 

        if self._debug:
            print(f"Received frame: {full_frame.hex(' ').upper()}")
        
        return framing.parse_frame(full_frame)
    
    def _expect_frame(self, expected_id: MessageID) -> bytes:
        msg_id, payload = self._receive_frame()
        if msg_id != expected_id:
            raise ValueError(f"Expected {expected_id.name}, got {msg_id.name}")
        
        return payload

    def _log(self, direction: str, message: str, **fields) -> None:
        print(f"  [{direction}]  {message}")
        if fields:
            width = max(len(k) for k in fields)
            for key, value in fields.items():
                print(f"           {key:<{width}} : {value}")
        print()

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
        ciphertext = self._crypto.encrypt(plaintext)
        frame = framing.build_frame(MessageID.PIN_EXCHANGE, ciphertext)    
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.PIN_ACK)
        payload_decrypted = self._crypto.decrypt(payload)
        
        return payload_decrypted == b'\x00'
    
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

        file_id_bytes = struct.pack("B", int(file_id))
        self._log("SEND", "FILE_TRANSFER_REQUEST", operation="WRITE", file_id=file_id)
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x77' + file_id_bytes) # 0x77 at the beginning specifies write
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.FILE_REQ_ACK)
        status = "APPROVED" if payload == b'\x00' else "REJECTED"
        self._log("RECV", "FILE_REQUEST_ACK", status=status)
        if payload != b'\x00':
            return False

        self._log("SEND", "FILE_CONTENTS", size=f"{len(file_content)} bytes") # TODO: change this with encryption details
        ciphertext = self._crypto.encrypt(file_content)
        frame = framing.build_frame(MessageID.FILE_CONTENT, ciphertext)
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.FILE_COMPLETE_ACK)
        crc = "OK" if payload == b'\x00' else "MISMATCH"
        self._log("RECV", "FILE_TRANSFER_ACK", crc=crc)
        if payload != b'\x00':
            return False

        print("  Write complete.\n")
        return True

    def read(self, local_path: str, file_id: str) -> bool:
        #print(f"Requesting read for file ID {file_id}...")
        file_id_bytes = struct.pack("B", int(file_id))
        self._log("SEND", "FILE_TRANSFER_REQUEST", operation="READ", file_id=file_id)
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x72' + file_id_bytes) # 0x72 at the beginning specifies read
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.FILE_REQ_ACK)
        status = "APPROVED" if payload == b'\x00' else "REJECTED"
        self._log("RECV", "FILE_REQUEST_ACK", status=status)
        if payload != b'\x00':
            #print("File request rejected by HSM")
            return False

        #print("Receiving file contents...")
        try:
            file_content = self._expect_frame(MessageID.FILE_CONTENT)
        except ValueError as e:
            # technically this catches also other exceptions, not just checksum mismatches
            # I think it's an acceptable behavior
            frame = framing.build_frame(MessageID.FILE_COMPLETE_ACK, b'\x01') # checksum mismatch
            self._transport.send(frame)
            raise e
        
        file_content_decrypted = self._crypto.decrypt(file_content)
        
        self._log("RECV", "FILE_CONTENTS", size=f"{len(file_content)} bytes", crc="OK") # TODO: change this with encryption details

        with open(local_path, 'wb') as f:
            f.write(file_content_decrypted)

        print(f"  Read complete, saved to {local_path}\n")
        return True