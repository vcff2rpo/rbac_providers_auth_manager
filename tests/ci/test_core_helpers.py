from __future__ import annotations

import logging

import pytest

from rbac_providers_auth_manager.core.session_guards import (
    execute_scalars_all,
    rollback_session_quietly,
)
from rbac_providers_auth_manager.core.util import (
    canonicalize_dn,
    dedupe_preserve_order,
    ip_in_trusted_proxies,
    parse_bool,
    parse_csv,
)


class _OkSession:
    def __init__(self, rows):
        self._rows = rows
        self.rollback_calls = 0

    def execute(self, statement):
        del statement
        return self

    def scalars(self):
        return self

    def all(self):
        return self._rows

    def rollback(self) -> None:
        self.rollback_calls += 1


class _FailingSession:
    def __init__(self) -> None:
        self.rollback_calls = 0

    def execute(self, statement):
        del statement
        raise RuntimeError("db failed")

    def rollback(self) -> None:
        self.rollback_calls += 1


class _BrokenRollbackSession:
    def rollback(self) -> None:
        raise RuntimeError("rollback failed")


@pytest.mark.unit
def test_core_util_parsers_and_proxy_matching() -> None:
    assert parse_bool(" true ") is True
    assert parse_bool("", default=True) is True
    assert parse_csv(
        "Viewer, Op,\
 Admin"
    ) == ["Viewer", "Op", "Admin"]
    assert dedupe_preserve_order(["a", "b", "a", "c"]) == ["a", "b", "c"]
    assert canonicalize_dn(" CN = Alice , OU = Users , DC = Example , DC = COM ") == (
        "cn=alice,ou=users,dc=example,dc=com"
    )
    assert ip_in_trusted_proxies("10.0.0.9", ["10.0.0.0/24"]) is True
    assert ip_in_trusted_proxies("10.0.1.9", ["10.0.0.0/24"]) is False


@pytest.mark.unit
def test_execute_scalars_all_rolls_back_on_failure() -> None:
    ok_session = _OkSession([1, 2, 3])
    assert execute_scalars_all(ok_session, "select") == [1, 2, 3]
    assert ok_session.rollback_calls == 0

    failing_session = _FailingSession()
    with pytest.raises(RuntimeError, match="db failed"):
        execute_scalars_all(failing_session, "select")
    assert failing_session.rollback_calls == 1


@pytest.mark.unit
def test_rollback_session_quietly_swallows_rollback_failures(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    rollback_session_quietly(_BrokenRollbackSession())
    assert "Session rollback failed" in caplog.text
