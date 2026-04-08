from abc import ABC, abstractmethod
import serial

class Transport(ABC):
    @abstractmethod 
    def send(self, data: bytes) -> None: ...

    @abstractmethod 
    def receive(self, n: int) -> bytes: ... 

class SerialTransport(Transport):
    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 2.0):
        self._port = port
        self._baudrate = baudrate
        self._timeout = timeout
        self._ser = None

    # this exists so that the serial connection is opened lazily on the first send/receive
    # without this the script crashes at startup if the hsm is not connected
    def _connect(self):
        if self._ser is None:
            # defaults to 8N1
            self._ser = serial.Serial(self._port, self._baudrate, timeout=self._timeout)

    def send(self, data: bytes) -> None:
        self._connect()
        self._ser.write(data) # type: ignore

    def receive(self, n: int) -> bytes:
        self._connect()
        res = self._ser.read(n) # type: ignore
        if len(res) < n:
            raise TimeoutError(f"Expected {n} bytes, got {len(res)}")
        return res