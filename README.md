# HSM Host Tool

Host PC CLI tool for communicating with the HSM over UART.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate               # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Usage

```bash
python main.py <port>                   # e.g. python main.py /dev/ttyUSB0
python main.py <port> --timeout 5.0     # custom timeout in seconds (default: 2.0)
```

## Commands

| Command | Description | Usage |
| --- | --- | --- |
| `auth` | Authenticate with the HSM | `auth <pin ?>` |
| `status` | Query HSM status | `status` |
| `write` | Upload a file to the HSM | `write <local_path> <remote_path>` |
| `read` | Download a file from the HSM | `read <remote_path> <local_path>` |
| `close` | Close the session | `close` |
| `help` | List available commands | `help` or `help <command>` |