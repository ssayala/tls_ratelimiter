#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A script to send multiple parallel TLS requests to a Valkey server."""

import valkey
import threading
import time
import configparser
import os
import sys

def load_config(file_path: str) -> dict:
    """Loads and validates Valkey configuration from an INI file."""
    if not os.path.exists(file_path):
        sys.exit(f"❌ Error: Configuration file '{file_path}' not found.")

    config = configparser.ConfigParser()
    try:
        config.read(file_path)
        valkey_config = config['valkey']
        return {
            'host': valkey_config.get('host', '127.0.0.1'),
            'port': valkey_config.getint('port', 6379),
            'cert_file': valkey_config.get('cert_file', 'valkey.crt'),
            'key_file': valkey_config.get('key_file', 'valkey.key'),
            'ca_cert_file': valkey_config.get('ca_cert_file', 'ca.crt'),
            'num_parallel_requests': valkey_config.getint('num_parallel_requests', 10),
        }
    except (configparser.Error, KeyError, ValueError) as e:
        sys.exit(f"❌ Error in configuration file '{file_path}': {e}")

def make_tls_request(thread_id: int, config: dict):
    """Connects to Valkey with TLS, performs a PING, and disconnects."""
    print(f"[Thread {thread_id:02d}] Starting...")
    client = None
    try:
        client = valkey.Valkey(
            host=config['host'], port=config['port'], ssl=True,
            ssl_certfile=config['cert_file'], ssl_keyfile=config['key_file'],
            ssl_ca_certs=config['ca_cert_file'], ssl_cert_reqs="required",
            socket_connect_timeout=1, socket_timeout=1
        )
        result = "✅ Success! Connected and PINGed Valkey." if client.ping() else "⚠️ PING failed but connection was made."
        print(f"[{thread_id:02d}] {result}")
    except (valkey.exceptions.ConnectionError, valkey.exceptions.TimeoutError) as e:
        print(f"❌ [Thread {thread_id:02d}] Error: {e}")
    except Exception as e:
        print(f"❌ [Thread {thread_id:02d}] An unexpected error occurred: {e}")
    finally:
        if client:
            client.close()
        print(f"[Thread {thread_id:02d}] Finished.")

def main():
    """Main execution function."""
    print("--- Starting Valkey Parallel TLS Connection Test ---")
    
    config = load_config('config.ini')
    num_requests = config.pop('num_parallel_requests')

    print(f"\n🚀 Spawning {num_requests} parallel threads...")
    
    start_time = time.time()
    threads = [threading.Thread(target=make_tls_request, args=(i + 1, config)) for i in range(num_requests)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    print("\n--- All threads have completed. ---")
    print(f"Total execution time: {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()(storm) 
