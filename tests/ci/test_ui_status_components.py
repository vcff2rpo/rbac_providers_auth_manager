from __future__ import annotations

import pytest

from rbac_providers_auth_manager.ui.status_panel_renderer import StatusPanelRenderer
from rbac_providers_auth_manager.ui.status_presenter import LoginStatusPresenter
from rbac_providers_auth_manager.ui.status_query_service import StatusQueryService

from . import test_browser_token_flow_matrix as browser_matrix


@pytest.fixture()
def auth_cfg():
    factory = getattr(browser_matrix.auth_cfg, "__wrapped__", browser_matrix.auth_cfg)
    return factory()


@pytest.fixture()
def manager(auth_cfg):
    return browser_matrix._FakeManager(auth_cfg)


@pytest.mark.unit
def test_status_query_service_maps_errors_titles_and_roles(manager) -> None:
    service = StatusQueryService(manager)

    assert service.retry_after_from_query(" 12 ") == 12
    assert service.retry_after_from_query("bad") == 0
    assert service.status_from_query(error="invalid", status_value=None) == (
        "error",
        "Sign-in failed",
    )
    assert service.status_message_from_query(
        error="csrf", status_value=None
    ).startswith("The login session expired")
    assert service.login_status_roles_from_query(" Viewer, Op ,Viewer ") == [
        "Viewer",
        "Op",
        "Viewer",
    ]


@pytest.mark.unit
def test_status_presenter_uses_configured_ui_texts(manager) -> None:
    presenter = LoginStatusPresenter(manager)

    title = presenter.login_status_title(
        error=None,
        status_value="success",
        method="ldap",
    )
    message = presenter.login_status_message(
        error=None,
        status_value="success",
        method="entra",
        stage="mapping_roles",
    )

    assert title == manager._cfg_loader.get_config().ui.title_success
    assert message == manager._cfg_loader.get_config().ui.entra_success_text


@pytest.mark.unit
def test_status_panel_renderer_renders_compact_success_details(manager) -> None:
    renderer = StatusPanelRenderer(manager, StatusQueryService(manager))

    html = renderer.render_rich_status_panel(
        error=None,
        status_value="success",
        reference="REF-123",
        retry_after=0,
        method="entra",
        stage="mapping_roles",
        roles=["Viewer", "Op"],
        next_url="/graph",
        auto_redirect_seconds=0,
    )

    assert "Access granted" in html
    assert "Method:</strong> Microsoft Sign-In" in html
    assert "Mapped roles:</strong> Viewer, Op" in html
    assert "Environment:</strong> CI" in html
    assert "Reference:</strong> REF-123" in html


@pytest.mark.unit
def test_status_panel_renderer_renders_throttle_countdown(manager) -> None:
    renderer = StatusPanelRenderer(manager, StatusQueryService(manager))

    html = renderer.render_status_banner(
        error="throttled",
        status_value=None,
        reference="REF-456",
        retry_after=15,
    )

    assert "Retry available in" in html
    assert 'id="itim-retry-after"' in html
    assert "REF-456" in html
