# Valkey TLS Connection Storm

This script, `test_rate_limit.py`, is designed to test a Valkey server's ability to handle multiple parallel TLS connections. It spawns a configurable number of threads, each of which attempts to connect to the Valkey server over TLS, execute a `PING` command, and then disconnect.

## Features

- **Parallel Testing**: Sends multiple requests concurrently to simulate a high-load scenario.
- **TLS Support**: Connects to Valkey using TLS, ensuring secure communication.
- **Configurable**: All settings, including host, port, TLS certificates, and the number of parallel requests, are managed through a `config.ini` file.
- **Error Handling**: Reports connection, timeout, and other potential errors for each thread.

## Prerequisites

Before running the script, ensure you have the following:

1.  Valkey Server running with TLS enabled. Instructions [here](https://valkey.io/topics/encryption/)
2.  **Python 3**: The script is written for Python 3.
3.  **Valkey Python Client**: The `valkey-py` library is required. You can install it via pip:
    ```bash
    pip install valkey
    ```
4.  **TLS Certificates**: You need valid TLS certificate files (`.crt`), a key file (`.key`), and a CA certificate file (`.crt`).
5. Do not run on the server as the XDP program  doesnt work on the loopback interface 

## Configuration

The script requires a `config.ini` file in the same directory. This file contains the necessary parameters for connecting to the Valkey server.

Create a file named `config.ini` with the following format:

```ini
[valkey]
host = <remote ip>
port = 6379
cert_file = <cert file>
key_file = <key file>
ca_cert_file = <cert authority cert>
num_parallel_requests = 10
```

### Configuration Options

-   `host`: The IP address or hostname of the Valkey server.
-   `port`: The port number for the Valkey server.
-   `cert_file`: Path to the client's TLS certificate file.
-   `key_file`: Path to the client's TLS key file.
-   `ca_cert_file`: Path to the Certificate Authority (CA) certificate file.
-   `num_parallel_requests`: The number of concurrent threads to spawn for the test.

## Usage

To run the script, simply execute it from your terminal:

```bash
python3 tls_rate_limit.py
```

The script will read the `config.ini` file, spawn the specified number of threads, and print the status of each connection attempt.
