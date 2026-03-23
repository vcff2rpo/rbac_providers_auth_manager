"""Custom Airflow auth-manager package for LDAP/ITIM and Azure Entra ID.

This package is intentionally lightweight because Airflow imports plugin
packages at startup during plugin discovery. Keeping the package root free from
heavy imports reduces startup fragility and prevents side effects during import.

Public root surface::

    rbac_providers_auth_manager/
        __init__.py
        auth_manager.py   # Airflow entrypoint facade
        config.py         # public config facade

Canonical runtime layout::

    rbac_providers_auth_manager/
        entrypoints/
            __init__.py
            auth_manager.py
        compatibility/
            __init__.py
            airflow_public_api.py
            fab_adapter.py
            internal_shims.py
        api/
            __init__.py
            models.py
            routes.py
            routes_api.py
        config_runtime/
            __init__.py
            facade.py
            models.py
            advisories.py
            advisory_rules.py
            parse_helpers.py
            section_parsers.py
            provider_parsers.py
            mapping_parsers.py
            parser.py
            permissions.ini
        core/
            __init__.py
            exceptions.py
            logging_utils.py
            session_guards.py
            util.py
        identity/
            __init__.py
            models.py
            mapper.py
            ldap_mapper.py
            entra_mapper.py
        authorization/
            __init__.py
            compat_matrix.py
            helpers.py
            policy_models.py
            resource_contracts.py
            rbac.py
            resource_filters.py
            vocabulary.py
        providers/
            __init__.py
            base.py
            entra_client.py
            entra_http_service.py
            entra_identity_service.py
            entra_provider.py
            ldap_client.py
            ldap_connection_service.py
            ldap_identity_service.py
            ldap_provider.py
        runtime/
            __init__.py
            auth_state_backends.py
            compat_governance.py
            config_integrity.py
            fingerprints.py
            pkce.py
            rate_limit_backends.py
            rate_limiter.py
            secret_references.py
            security.py
            url_security.py
            version_policy.py
        services/
            __init__.py
            audit_schema.py
            audit_service.py
            auth_flow_service.py
            authorization_lookup_service.py
            authorization_policy_service.py
            authorization_service.py
            browser_flow_service.py
            entrypoint_app_service.py
            ldap_browser_flow_service.py
            oauth_browser_flow_service.py
            flow_payloads.py
            identity_auth_service.py
            provider_runtime_service.py
            redirect_service.py
            runtime_context_service.py
            session_service.py
            token_flow_service.py
            user_session_service.py
        ui/
            __init__.py
            renderer.py
            status_panel_renderer.py
            status_presenter.py
            status_query_service.py
            static/auth.css
            templates/intermediate.html
            templates/login.html

Airflow activation::

    [core]
    auth_manager = rbac_providers_auth_manager.auth_manager.RbacAuthManager

The package root is preserved mainly as a stable compatibility surface while
canonical implementations are organized into logic-based folders.
"""

from __future__ import annotations

__version__ = "0.86.0"

__all__: tuple[str, ...] = ("__version__",)
