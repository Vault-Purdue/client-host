from abc import ABC, abstractmethod
import serial

# the abstract class exists because there is a MockTransport in the tests.
class Transport(ABC):
    @abstractmethod 
    def send(self, data: bytes) -> None: ...

    @abstractmethod 
    def receive(self, n: int) -> bytes: ... 

class SerialTransport(Transport):
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        # defaults to 8N1
        self._ser = serial.Serial(port, baudrate, timeout=timeout)

    def send(self, data: bytes) -> None:
        self._ser.write(data)

    def receive(self, n: int) -> bytes:
        res = self._ser.read(n)
        if len(res) < n:
            raise TimeoutError(f"Expected {n} bytes, got {len(res)}")
        return res