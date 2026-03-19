from __future__ import annotations

import socket
import time

HOST = "127.0.0.1"
PORT = 1389


def main() -> None:
    for attempt in range(1, 61):
        try:
            with socket.create_connection((HOST, PORT), timeout=2):
                print(f"LDAP port became reachable on attempt {attempt}")
                return
        except OSError as exc:
            print(f"waiting for LDAP service attempt={attempt} error={exc}")
            time.sleep(2)
    raise SystemExit("LDAP service did not become reachable in time")


if __name__ == "__main__":
    main()
