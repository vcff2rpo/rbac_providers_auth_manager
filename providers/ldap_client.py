"""LDAP client facade for the custom Airflow auth manager."""

from __future__ import annotations

import logging
from typing import Any

from rbac_providers_auth_manager.config import LdapConfig
from rbac_providers_auth_manager.core.exceptions import LdapAuthError
from rbac_providers_auth_manager.providers.ldap_connection_service import (
    LdapConnectionService,
    ldap_module,
)
from rbac_providers_auth_manager.providers.ldap_identity_service import (
    LdapUserInfo,
    build_user_info,
    validate_username,
)

log = logging.getLogger(__name__)


class LdapClient:
    """Stateless LDAP client configured from ``permissions.ini``."""

    def __init__(self, cfg: LdapConfig) -> None:
        self.cfg = cfg
        self._connection_service = LdapConnectionService(cfg)

    def reconfigure(self, cfg: LdapConfig) -> None:
        """Replace the active LDAP configuration."""
        self.cfg = cfg
        self._connection_service.reconfigure(cfg)

    def authenticate(self, username: str, password: str) -> LdapUserInfo:
        """Authenticate a username/password pair against LDAP."""
        normalized_username = validate_username(
            username=username,
            pattern=self.cfg.username_pattern,
            max_length=self.cfg.username_max_length,
        )
        if not password:
            raise LdapAuthError("Missing password")

        ldap = ldap_module()
        conn: Any | None = None
        try:
            conn = self._connection_service.connect()

            if self.cfg.username_dn_format:
                user_dn = self._connection_service.format_user_dn(normalized_username)
                log.debug("LDAP direct-bind attempt user_dn=%s", user_dn)
                try:
                    conn.simple_bind_s(user_dn, password)
                except ldap.INVALID_CREDENTIALS as exc:
                    raise LdapAuthError("Invalid credentials") from exc

                attrs = self._connection_service.fetch_user_attrs(
                    conn,
                    username=normalized_username,
                    user_dn=user_dn,
                )
                attrs = self._connection_service.augment_group_attrs(
                    conn, user_dn=user_dn, attrs=attrs
                )
                return build_user_info(
                    cfg=self.cfg,
                    username=normalized_username,
                    user_dn=user_dn,
                    attrs=attrs,
                )

            self._connection_service.bind_service(conn)
            user_dn, attrs = self._connection_service.search_user(
                conn, username=normalized_username
            )
            log.debug("LDAP search found user_dn=%s", user_dn)

            try:
                conn.simple_bind_s(user_dn, password)
            except ldap.INVALID_CREDENTIALS as exc:
                raise LdapAuthError("Invalid credentials") from exc

            attrs = self._connection_service.augment_group_attrs(
                conn, user_dn=user_dn, attrs=attrs
            )
            return build_user_info(
                cfg=self.cfg,
                username=normalized_username,
                user_dn=user_dn,
                attrs=attrs,
            )

        except LdapAuthError:
            raise
        except ldap.LDAPError as exc:
            log.exception(
                "LDAP error during authentication for %r", normalized_username
            )
            raise LdapAuthError("LDAP failure") from exc
        except Exception as exc:  # noqa: BLE001
            log.exception(
                "Unexpected error during LDAP authentication for %r",
                normalized_username,
            )
            raise LdapAuthError("LDAP failure") from exc
        finally:
            if conn is not None:
                try:
                    conn.unbind_s()
                except Exception:  # noqa: BLE001
                    log.debug(
                        "LDAP connection unbind failed during cleanup", exc_info=True
                    )


__all__ = ("LdapClient", "LdapUserInfo")
