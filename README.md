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
python main.py <port> [--timeout <seconds>] [--pin <file>]
```

**Options**

| Option | Default | Description |
| --- | --- | --- |
| `--timeout <seconds>` | `2.0` | UART receive timeout |
| `--pin <file>` | ### | Path to file containing PIN (dev only, see note) |

*`--pin`: this option is clearly unsafe as the pin is stored in plaintext. It's intended for development only. It will probably be removed eventually*


## Commands

| Command | Description | Usage |
| --- | --- | --- |
| `auth`   | Authenticate with the HSM | `auth` |
| `pin`    | Set / update pin for current session | `pin <pin> ` |
| `status` | Query HSM status | `status` |
| `write`  | Upload a file to the HSM | `write <local_path> <file_id>` |
| `read`   | Download a file from the HSM | `read <local_path> <file_id>` |
| `close`  | Close the session | `close` |
| `help`   | List available commands | `help` or `help <command>` |