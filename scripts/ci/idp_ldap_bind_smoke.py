from __future__ import annotations

import os
import time

import ldap


def main() -> None:
    uri = os.environ["LDAP_TEST_URI"]
    bind_dn = os.environ["LDAP_TEST_BIND_DN"]
    bind_password = os.environ["LDAP_TEST_BIND_PASSWORD"]

    for attempt in range(1, 16):
        conn = None
        try:
            conn = ldap.initialize(uri)
            conn.simple_bind_s(bind_dn, bind_password)
            print(f"LDAP bind succeeded on attempt {attempt}")
            return
        except ldap.LDAPError as exc:
            print(f"LDAP bind not ready yet attempt={attempt} error={exc}")
            time.sleep(2)
        finally:
            if conn is not None:
                try:
                    conn.unbind_s()
                except Exception:
                    pass
    raise SystemExit("LDAP bind smoke never succeeded")


if __name__ == "__main__":
    main()
