import cmd 
import argparse
from protocol import MessageID
from session import Session
from transport import *


class Shell(cmd.Cmd):
    intro = "HSM Host Tool. Type 'help' for commands."
    prompt = "hsm> "

    def __init__(self, transport: Transport):
        super().__init__()
        self._transport = transport
        self._session = None

    def _check_session(self) -> bool:
        if self._session is None:
            print("Not authenticated. Run 'auth' first.")
            return False 
        return True

    def do_auth(self, arg):
        self._session = Session(self._transport)
        self._session.open()
        self._session.exchange_keys()
        success = self._session.exchange_pin()

        if not success:             # TODO: this assumes the HSM closes the session after a failed pin exchanged
            self._session = None    #       without having to send a SESSION_CLOSE. Check with whoever
            print("Authentication failed")


    def do_close(self, arg):
        if not self._check_session():
            return 
        self._session.close() # type: ignore

    def do_status(self, arg):
        if not self._check_session():
           return
        _ = self._session.status() # type: ignore


    def do_write(self, arg):
        if not self._check_session():
            return 
        args = arg.split()

        if len(args) != 2:
            print("Usage write <local_path> <remote_path>")
            return 

        self._session.write(args[0], args[1]) # type: ignore

    def do_read(self, arg):
        if not self._check_session():
            return 
        args = arg.split()

        if len(args) != 2:
            print("Usage <remote_path> <local_path>")
            return

        self._session.read(args[1], args[0]) # type: ignore

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HSM Host Tool")
    parser.add_argument("port", nargs="?", help="Serial port")
    parser.add_argument("--timeout", type=float, default=2.0, help="Serial read timeout in seconds")
    args = parser.parse_args()

    if args.port:
        transport = SerialTransport(args.port, baudrate=115200, timeout=args.timeout)
    else:
        parser.error("Please provide a port")
    Shell(transport).cmdloop()