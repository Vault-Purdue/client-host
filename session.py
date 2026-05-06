from transport import Transport
import framing
from protocol import MessageID
import struct
from crypto import Crypto
import textwrap

# fatal, resets session
class SessionClosedError(Exception):
    pass

# non-fatal, keeps session alive
class AuthenticationError(Exception):
    pass

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
    
    def _send_frame(self, msg_id: MessageID, payload: bytes) -> None:
        frame = framing.build_frame(msg_id, payload)
        self._transport.send(frame)
        self._log("SEND", msg_id, payload)
    
    def _expect_frame(self, expected_id: MessageID) -> bytes:
        msg_id, payload = self._receive_frame()
        self._log("RECV", msg_id, payload)
        if msg_id == MessageID.SESSION_CLOSE and expected_id != MessageID.SESSION_CLOSE:
            raise SessionClosedError("Session closed by HSM")
        if msg_id != expected_id:
            raise ValueError(f"Expected {expected_id.name}, got {msg_id.name}")
        
        return payload

    def _log(self, direction: str, msg_id: MessageID, payload: bytes) -> None:
        match msg_id:
            case MessageID.SESSION_OPEN:
                label = "SESSION_OPEN"
                fields = {"encrypted": "False", "payload": payload.decode()}
            case MessageID.KEY_EXCHANGE:
                label = "KEY_EXCHANGE"
                fields = {"encrypted": "False", "size": f"{len(payload)} bytes"}
            case MessageID.PIN_EXCHANGE:
                label = "PIN_EXCHANGE"
                fields = {"encrypted": "True", "size": f"{len(payload)} bytes"}
            case MessageID.PIN_ACK:
                label = "PIN_ACK"
                decrypted_pin = self._crypto.decrypt(payload)
                ack_value = "VALID" if decrypted_pin == b'\x00' else "INVALID"
                fields = {"encrypted": "True", "size": f"{len(payload)} bytes", "value" : ack_value}
            case MessageID.SESSION_CLOSE:
                label = "SESSION_CLOSE"
                fields = {"encrypted": "False", "payload": payload.decode()}
            case MessageID.FILE_TRANSFER_REQ:
                label = "FILE_TRANSFER_REQ"
                op = "WRITE" if payload[0] == 0x77 else "READ"
                fields = {"encrypted": "False", "operation": op, "file_id": str(payload[1])}
            case MessageID.FILE_CONTENT:
                label = "FILE_CONTENT"
                fields = {"encrypted": "True", "size": f"{len(payload)} bytes", "plaintext": self._crypto.decrypt(payload).decode(), 
                           "ciphertext": payload.hex(' ', 4), "crc": f"{framing.crc(payload):04X}"}
            case MessageID.FILE_REQ_ACK:
                label = "FILE_REQ_ACK"
                fields = {"encrypted": "False", "status": "APPROVED" if payload == b'\x00' else "REJECTED"}
            case MessageID.FILE_COMPLETE_ACK:
                label = "FILE_COMPLETE_ACK"
                fields = {"encrypted": "False", "crc_check": "OK" if payload == b'\x00' else "MISMATCH"}
            case _:
                label = f"UNKNOWN({msg_id:#04x})"
                fields = {"size": f"{len(payload)} bytes"}

        print(f"  [{direction}]  {label}")
        if fields:
            width = max(len(k) for k in fields)
            for key, value in fields.items():
                prefix = f"           {key:<{width}} : "
                indent = " " * len(prefix)
                print(textwrap.fill(str(value), width=120, initial_indent=prefix, subsequent_indent=indent))
        print()

    
    def authenticate(self, pin: str) -> None:
        if not self._open():
            raise SessionClosedError("Handshake failed")
        else:
            print("Open session successful.\n")

        if not self._exchange_keys():
            raise SessionClosedError("Key exchange failed")
        else:
            print("Key exchange successful.\n")

        if not self._exchange_pin(pin):
            raise AuthenticationError("Invalid PIN")
        else:
            print("Authentication successful.\n")


    def _open(self) -> bool:
        self._send_frame(MessageID.SESSION_OPEN, b'\x41')
        payload = self._expect_frame(MessageID.SESSION_OPEN)
        return payload == b'\x41'

    def _exchange_keys(self) -> bool:
        self._send_frame(MessageID.KEY_EXCHANGE, self._crypto.public_key())
        payload = self._expect_frame(MessageID.KEY_EXCHANGE)
        self._crypto.compute_shared_key(payload)
        return True 
    
    def _exchange_pin(self, pin: str) -> bool:
        plaintext = pin.encode('ascii')
        ciphertext = self._crypto.encrypt(plaintext)
        self._send_frame(MessageID.PIN_EXCHANGE, ciphertext)
        payload = self._expect_frame(MessageID.PIN_ACK)
        payload_decrypted = self._crypto.decrypt(payload)
        return payload_decrypted == b'\x00'
    
    def close(self) -> bool: 
        self._send_frame(MessageID.SESSION_CLOSE, b'\x43')
        payload = self._expect_frame(MessageID.SESSION_CLOSE)
        return payload == b'\x43'

    def write(self, local_path: str, file_id: str) -> bool:
        with open(local_path, 'rb') as f:
            file_content = f.read()
            if len(file_content) != 88:
                print(f"File must be exactly 88 bytes, got {len(file_content)}.")
                return False

        file_id_bytes = struct.pack("B", int(file_id))
        self._send_frame(MessageID.FILE_TRANSFER_REQ, b'\x77' + file_id_bytes)

        payload = self._expect_frame(MessageID.FILE_REQ_ACK)
        if payload != b'\x00':
            print(f"    Write failed. Hsm rejected the request.\n")
            return False

        ciphertext = self._crypto.encrypt(file_content)
        self._send_frame(MessageID.FILE_CONTENT, ciphertext)

        payload = self._expect_frame(MessageID.FILE_COMPLETE_ACK)
        if payload != b'\x00':
            return False

        print("  Write complete.\n")
        return True

    def read(self, local_path: str, file_id: str) -> bool:
        file_id_bytes = struct.pack("B", int(file_id))
        self._send_frame(MessageID.FILE_TRANSFER_REQ, b'\x72' + file_id_bytes)

        payload = self._expect_frame(MessageID.FILE_REQ_ACK)
        if payload != b'\x00':
            print(f"    Read failed. Hsm rejected the request.\n")
            return False

        try:
            file_content = self._expect_frame(MessageID.FILE_CONTENT)
        except ValueError as e:
            self._send_frame(MessageID.FILE_COMPLETE_ACK, b'\x01')
            raise e

        file_content_decrypted = self._crypto.decrypt(file_content)

        with open(local_path, 'wb') as f:
            f.write(file_content_decrypted)

        print(f"  Read complete, saved to {local_path}\n")
        return True