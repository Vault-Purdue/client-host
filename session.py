from transport import Transport
import framing
from protocol import MessageID
import struct

class Session:
    def __init__(self, transport: Transport):
        self._transport = transport

    def _receive_frame(self) -> tuple[MessageID, bytes]:
        header = self._transport.receive(framing.HEADER_SIZE)
        payload_len = framing.get_payload_len_from_header(header)
        rest = self._transport.receive(payload_len + framing.CHECKSUM_SIZE)
        return framing.parse_frame(header + rest)
    
    def _expect_frame(self, expected_id: MessageID) -> bytes:
        msg_id, payload = self._receive_frame()
        if msg_id != expected_id:
            raise ValueError(f"Expected {expected_id.name}, got {msg_id.name}")
        
        return payload

    def open(self) -> None:
        frame = framing.build_frame(MessageID.SESSION_OPEN, b'')
        self._transport.send(frame)

        # receive nothing

    def exchange_keys(self) -> None:
        frame = framing.build_frame(MessageID.KEY_EXCHANGE, b'')    # TODO: payload content
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.KEY_EXCHANGE)

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

    def status(self) -> bytes:
        frame = framing.build_frame(MessageID.STATUS_QUERY, b'')    # TODO: payload content
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.STATUS_RESPONSE)
        return payload
    
    def _chunk_file(self, path: str, chunk_size: int = 1024):
        with open(path, 'rb') as f:
            while chunk := f.read(chunk_size):
                yield chunk

    def write(self, local_path: str, remote_path: str) -> bool:
        path_bytes = remote_path.encode('ascii') + b'\x00'
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x00' + path_bytes) # 0x00 at the beginning specifies write
        self._transport.send(frame)
        payload = self._expect_frame(MessageID.FILE_REQ_ACK) 

        if payload != b'\x00':
            print("File request was rejected")
            return False

        # TODO: check how to send FILE_START FILE_END if file is only one chunk
        # Right now, in this case (only this case), I send an empty FILE_END at the end
        chunks = list(self._chunk_file(local_path))
        last_index = len(chunks) - 1

        for i, chunk in enumerate(chunks):
            if i == 0:
                msg_id = MessageID.FILE_START
            elif i == last_index:
                msg_id = MessageID.FILE_END
            else:
                msg_id = MessageID.FILE_BLOCK

            frame = framing.build_frame(msg_id, chunk)
            self._transport.send(frame)

        if last_index == 0: # file is only one chunk. Didn't send FILE_END
            frame = framing.build_frame(MessageID.FILE_END, b'')
            self._transport.send(frame)

        file_checksum = framing.crc(b''.join(chunks))
        frame = framing.build_frame(MessageID.FILE_TRANSFER_COMPLETE, struct.pack(">H", file_checksum))
        self._transport.send(frame)

        payload = self._expect_frame(MessageID.FILE_COMPLETE_ACK) 
        if payload != b'\x00':
            print("File transfer failed: data may be corrupted (CRC mismatch)")
            return False
        
        return True

    def read(self, local_path: str, remote_path: str) -> bool:
        path_bytes = remote_path.encode('ascii') + b'\x00'
        frame = framing.build_frame(MessageID.FILE_TRANSFER_REQ, b'\x01' + path_bytes) # 0x01 at the beginning specifies read
        self._transport.send(frame)
        payload = self._expect_frame(MessageID.FILE_REQ_ACK) 

        if payload != b'\x00':
            print("File request was rejected")
            return False

        file_start = self._expect_frame(MessageID.FILE_START)
        file_blocks = []

        # TODO: some timing check so that it's impossible to be stuck here forever
        MAX_BLOCKS = 1024   # sanity limit
        reached_file_end = False
        for _ in range(MAX_BLOCKS):
            msg_id, payload = self._receive_frame()

            if msg_id == MessageID.FILE_END:
                file_end = payload 
                reached_file_end = True
                break
            elif msg_id == MessageID.FILE_BLOCK:
                file_blocks.append(payload)
            else:
                raise ValueError(f"Expected File-related ID, got {msg_id.name}")
            
        if not reached_file_end:
            raise ValueError("File transfer exceeded maximum block count")

        expected_crc = struct.unpack(">H", self._expect_frame(MessageID.FILE_TRANSFER_COMPLETE))[0]
        whole_file = file_start + b''.join(file_blocks) + file_end
        computed_crc = framing.crc(whole_file)

        if computed_crc == expected_crc:
            frame = framing.build_frame(MessageID.FILE_COMPLETE_ACK, b'\x00') # success
            self._transport.send(frame)

            with open(local_path, 'wb')  as f:
                f.write(whole_file)

            return True 
        else:
            frame = framing.build_frame(MessageID.FILE_COMPLETE_ACK, b'\x01') # failure
            self._transport.send(frame)
            print("File transfer failed: data may be corrupted (CRC mismatch)")
            return False

