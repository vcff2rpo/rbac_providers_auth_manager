# RBAC Providers Auth Manager for Apache Airflow 3.1.x

<p align="left">
  <img src="https://img.shields.io/badge/Airflow-3.1.x-017CEE?style=flat-square&logo=apacheairflow&logoColor=white" alt="Airflow 3.1.x">
  <img src="https://img.shields.io/badge/Python-3.10--3.13-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10-3.13">
  <img src="https://img.shields.io/badge/Auth-LDAP-2E8B57?style=flat-square" alt="LDAP">
  <img src="https://img.shields.io/badge/Auth-Entra_ID-0078D4?style=flat-square&logo=microsoftazure&logoColor=white" alt="Entra ID">
  <img src="https://img.shields.io/badge/API-JWT_tokens-BB2A2A?style=flat-square&logo=jsonwebtokens&logoColor=white" alt="JWT tokens">
  <img src="https://img.shields.io/badge/RBAC-File--driven-6F42C1?style=flat-square" alt="File-driven RBAC">
  <img src="https://img.shields.io/badge/UI-FastAPI_routes-0A9EDC?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI routes">
  <img src="https://img.shields.io/badge/Config-Hot_reload-FF8C00?style=flat-square" alt="Hot reload">
  <img src="https://img.shields.io/badge/Scope-Enterprise_auth-4B5563?style=flat-square" alt="Enterprise auth">
  <img src="https://img.shields.io/badge/Sessions-authz_epoch_revocation-B22222?style=flat-square" alt="Session revocation">
  <img src="https://img.shields.io/badge/Promotion-Core--only_PR_gate-1F6FEB?style=flat-square" alt="Core-only PR gate">
  <img src="https://img.shields.io/badge/CI-Self--check_%2B_summary-6B7280?style=flat-square" alt="CI governance and summary">
</p>

> GUIDE:

## Table of contents

1. [What this project is](#what-this-project-is)
2. [Why this plugin exists](#why-this-plugin-exists)
3. [Core plugin state in plugin](#core-plugin-state-in-plugin)
4. [Current Airflow context](#current-airflow-context)
5. [What plugin does and does not do](#what-plugin-does-and-does-not-do)
6. [High-level architecture](#high-level-architecture)
7. [Package layout and responsibilities](#package-layout-and-responsibilities)
8. [Unified low-level functional mental flow](#unified-low-level-functional-mental-flow)
9. [End-to-end auth and authorization flows](#end-to-end-auth-and-authorization-flows)
10. [Configuration model](#configuration-model)
11. [`permissions.ini` reference](#permissionsini-reference)
12. [Role model and permission semantics](#role-model-and-permission-semantics)
13. [UI behavior and customization](#ui-behavior-and-customization)
14. [Logging, audit, and diagnostics](#logging-audit-and-diagnostics)
15. [Security model](#security-model)
16. [Security interaction mental flows](#security-interaction-mental-flows)
17. [Edge cases and functional scenario catalog](#edge-cases-and-functional-scenario-catalog)
18. [Performance and scalability](#performance-and-scalability)
19. [Comparison with the official FAB auth manager](#comparison-with-the-official-fab-auth-manager)
20. [Operational checklist](#operational-checklist)
21. [Troubleshooting](#troubleshooting)
22. [Known limits and explicit non-goals](#known-limits-and-explicit-non-goals)
23. [Glossary and vocabulary](#glossary-and-vocabulary)
24. [FAQ](#faq)
25. [Contributing and repository collaboration](#contributing-and-repository-collaboration)
26. [References](#references)
---

## What this project is

`rbac_providers_auth_manager` is a custom Airflow auth manager for the Airflow 3.x line. It is built around three core ideas:

1. **authentication should come from enterprise identity systems**, not from manually curated local Airflow users,
2. **authorization should remain deterministic and auditable**, driven by a file-based RBAC policy rather than by ad hoc database edits,
3. **Airflow-facing compatibility should stay thin**, while the real logic is split into focused modules for providers, identity mapping, authorization, runtime safety, UI, and diagnostics.

In practice, plugin provides:

- **LDAP username/password browser login**
- **Azure Entra ID browser SSO**
- **LDAP-backed JWT issuance for API/CLI token flows**
- **file-driven role mapping and permission expansion from `permissions.ini`**
- **optional scoped role filters for DAG tags, environment labels, and resource prefixes**
- **hot-reloadable configuration with last-known-good fallback**
- **structured audit logging and operator advisories**
- **FastAPI-based auth routes instead of custom Flask/FAB views**

---

## Why this plugin exists

This project is best understood as an **enterprise-oriented alternative to the official FAB auth manager**, not as a generic drop-in clone of it.

The code makes the intent clear:

- the root package is intentionally import-light to reduce startup fragility during plugin discovery,
- provider logic is isolated so LDAP and Entra can evolve independently,
- authorization is decoupled from authentication and expressed in a stable action/resource vocabulary,
- runtime compatibility, advisories, and “doctor” reports are first-class concerns,
- the login UI is treated as an operational surface, not just a basic form.

### Primary design intentions visible in plugin

#### 1. External identity as source of truth

Instead of using the Airflow database as the system of record for everyday user onboarding, plugin authenticates users against external identity systems and maps external attributes to Airflow roles.

#### 2. Deterministic file-based RBAC

Roles and permissions are declared in `permissions.ini`. This makes role behavior:

- reviewable in Git,
- reproducible between environments,
- auditable,
- easier to promote through CI/CD.

#### 3. Better operator ergonomics

The code includes:

- runtime capability reporting,
- version policy reporting,
- compatibility/doctor reporting,
- advisory rules for multi-worker risk, undefined roles, risky public role settings, and more.

#### 4. Thin Airflow-facing boundary

The Airflow entrypoint is deliberately small. Most logic lives in services and runtime modules. This reduces coupling to Airflow internals and makes future adaptation easier.

#### 5. Enterprise login UX

The custom login page supports:

- environment label,
- support contact,
- structured status panels,
- correlation/reference IDs,
- per-method status text,
- rich messages for success, failure, throttling, and “no role mapped”.

---

### Production-readiness reading

From a production standpoint, the plugin is no longer just an authentication adapter. It behaves as a small auth platform for Airflow:

- authentication can come from LDAP or Entra ID;
- authorization is file-driven and hot-reloadable;
- existing sessions can be invalidated after security-sensitive policy changes through the `authz_epoch` model;
- degraded-mode startup and provider-readiness reporting are built into runtime orchestration;
- CI is structured to validate static quality, deep validation, Airflow integration, identity-provider integration, FAB compatibility, license compliance, and optional external-real validation.

### Best-practice summary

The current design follows several good long-term practices:

- **single-responsibility services** instead of one oversized security manager module;
- **configuration as code** through typed parsing and Git-reviewable policy;
- **reusable boundaries** between providers, identity normalization, authorization, and UI/API surfaces;
- **operator-focused observability** through structured audit events, advisories, and CI-generated governance inventories;
- **safe promotion to main** only after all enabled gates complete successfully.

## Current Airflow context

Airflow 3 uses a pluggable **auth manager** model. Only one auth manager can be configured at a time, and it is selected with `[core] auth_manager`. The default in Airflow 3 is the **Simple auth manager**, while FAB-based authentication remains available through the separate `apache-airflow-providers-fab` provider. The official FAB auth manager is documented as a backward-compatible user-management experience and stores its entities in the Airflow database. It also supports token-based API authentication and generic OAuth2-based SSO patterns.
See the official docs:

- [Airflow auth manager overview](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/auth-manager/index.html)
- [Airflow 3 release notes](https://airflow.apache.org/docs/apache-airflow/stable/release_notes.html)
- [FAB auth manager docs](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/index.html)
- [FAB auth manager API authentication](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/api-authentication.html)
- [FAB auth manager SSO integration](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/sso.html)

The plugin code also embeds its own runtime version policy with these baselines:

- tested Airflow baseline: **3.1.8**
- FAB provider baseline: **3.5.0**
- supported Python minors: **3.10–3.13**
- recommended Python minor: **3.13**

Those values come from `runtime/version_policy.py`.

---

## What plugin does and does not do

### It does

- implement a custom `RbacAuthManager` for Airflow 3.x,
- expose a FastAPI auth app under `/auth`,
- support browser login via LDAP and Entra ID,
- support token creation through `/auth/token` and `/auth/token/cli`,
- normalize LDAP/Entra identities into one internal user model,
- apply file-driven roles and permissions,
- support optional runtime role filters,
- support hot reload of `permissions.ini`,
- emit structured audit events and human-readable operator logs.

### It does not do

- manage custom DB tables,
- register custom legacy Flask API endpoints,
- register extra FAB views,
- add extra Airflow UI menu items,
- expose extra Airflow CLI commands,
- show evidence of SAML support in plugin,
- show evidence of database-backed user/role administration as the primary model.

---

## High-level architecture

### System view

```text
+-------------------------------------------------------------------------------------+
|                                   Apache Airflow 3.x                                |
|              [core] auth_manager = rbac_providers_auth_manager.auth_manager...      |
+----------------------------------------------+--------------------------------------+
                                               |
                                               v
+-------------------------------------------------------------------------------------+
|                    rbac_providers_auth_manager/auth_manager.py                      |
|                           lightweight compatibility facade                          |
+----------------------------------------------+--------------------------------------+
                                               |
                                               v
+-------------------------------------------------------------------------------------+
|                 entrypoints/auth_manager.py -> RbacAuthManager                      |
|                    composition root and Airflow auth-manager adapter                |
+----------------------------------------------+--------------------------------------+
                                               |
           +-----------------------------------+-----------------------------------+
           |                                   |                                   |
           v                                   v                                   v
+-------------------------+         +--------------------------+        +------------------------+
|       services/         |         |      authorization/      |        |    config_runtime/     |
| flow orchestration,     |         | RBAC policy engine,      |        | parser, typed models,  |
| session/cookies,        |         | resource vocabulary,     |        | advisories, reload,    |
| provider lifecycle,     |         | resource filters         |        | validation             |
| redirect, audit         |         |                          |        |                        |
+-------------------------+         +--------------------------+        +------------------------+
           |                                   |                                   |
           v                                   v                                   v
+-------------------------+         +--------------------------+        +------------------------+
|      providers/         |<------->|       identity/          |<------>|       runtime/         |
| LDAP and Entra client   |         | external identity ->     |        | rate limits, auth      |
| implementations         |         | role mapping             |        | state, PKCE, integrity |
+-------------------------+         +--------------------------+        +------------------------+
           |
           +-------------------------------+-------------------------------+
                                           |
                                           v
                              +------------------------------+
                              |      api/ and ui/            |
                              | FastAPI routes + login UI    |
                              +------------------------------+
```

**Mental model**

Airflow only sees one auth manager. Inside the plugin, that auth manager is mostly a coordinator. Real work is delegated into modular layers.

---

### Runtime composition inside `RbacAuthManager`

```text
RbacAuthManager.__init__()
|
+--> validate_ui_renderer_bindings()
+--> ConfigLoader()
+--> AuditService()
+--> RedirectService()
+--> SessionService()
+--> RuntimeContextService()
+--> UserSessionService()
+--> SessionRevocationService()
+--> EntrypointAppService()
+--> AuthorizationService()
+--> ProviderRuntimeService()
+--> IdentityAuthService()
+--> IdentityMapper()
+--> AuthFlowService()
+--> UIRenderer()
|
+--> load permissions.ini
      |
      +--> configure plugin log level
      +--> initialize provider clients
      |     +--> LDAP client (optional)
      |     +--> Entra client (optional)
      |
      +--> build provider wrappers
      |     +--> LdapAuthProvider
      |     +--> EntraAuthProvider
      |
      +--> build RbacPolicy
      +--> configure rate limiters
      +--> initialize session revocation backend and authz epoch tracking
      +--> emit capability / version / compatibility reports
```

**Mental model**

The manager is a composition root, not a monolith. That is one of the strongest maintainability improvements in plugin.

---

### Package layout and responsibilities

```text
rbac_providers_auth_manager/
├── __init__.py                    # import-light package root
├── auth_manager.py                # Airflow-facing lazy facade
├── config.py                      # public config facade
├── entrypoints/
│   └── auth_manager.py            # canonical RbacAuthManager
├── compatibility/                 # lazy Airflow/FAB compatibility boundaries
├── api/                           # FastAPI route registration + payload models
├── config_runtime/                # permissions.ini parser, models, advisories
├── core/                          # utilities, logging, exceptions, session guards
├── identity/                      # normalized external identity mapping
├── authorization/                 # RBAC engine, vocabulary, contracts, filters
├── providers/                     # LDAP + Entra providers and clients
├── runtime/                       # security, PKCE, state backends, rate limiters
├── services/                      # orchestration layer used by the manager
└── ui/                            # HTML rendering, CSS, status presenters
```

**Mental model**

Folder names describe *responsibility*, not framework type. That keeps the code easier to navigate for future maintainers.

---

## Package layout and responsibilities

### Thin root surface

The root package intentionally stays light:

- `auth_manager.py` is a compatibility facade that lazy-imports the real entrypoint,
- `config.py` is a facade over config-runtime internals,
- `__init__.py` documents the canonical layout and exposes the package version.

This matters because Airflow imports plugin packages during startup. Heavy import side effects here would increase fragility.

### Compatibility layer

The `compatibility/` folder exists to isolate Airflow/FAB drift:

- `airflow_public_api.py` lazy-loads Airflow public auth-manager symbols,
- `internal_shims.py` and `fab_adapter.py` help bridge version differences,
- `fab_provider_support.py` compares the plugin’s RBAC contract with the official FAB provider’s role bundles.

### Services layer

The service layer is where most orchestration happens:

- `auth_flow_service.py` — high-level facade for browser and token flows
- `browser_flow_service.py` — delegates browser flows to LDAP and OAuth branches
- `ldap_browser_flow_service.py` — POST login form handling
- `oauth_browser_flow_service.py` — Entra start and callback handling
- `identity_auth_service.py` — authentication-to-role-assignment bridge
- `authorization_service.py` — Airflow-facing authorization gateway
- `provider_runtime_service.py` — provider lifecycle, rate limiter wiring, refresh
- `session_service.py` — cookies, CSRF, auth-state storage
- `audit_service.py` — structured audit log emission

### Runtime layer

This folder holds the cross-cutting mechanics:

- HMAC integrity checks for `permissions.ini`
- secret reference resolution (`env:`, `file:`, `airflow_var:`, `literal:`)
- PKCE generation
- rate-limit backends (`memory`, `redis`)
- transient OAuth auth-state backends (`cookie`, `memory`, `redis`)
- URL security helpers
- version policy and compatibility governance

### Authorization layer

The authorization layer is intentionally separate from provider logic. It owns:

- action/resource normalization,
- wildcard semantics,
- DAG umbrella resource handling,
- compiled permission matrix caching,
- optional role filters based on runtime resource metadata.

---


## Unified low-level functional mental flow

This section introduces one large low-level operational flow for the plugin and then breaks it into transition phases. The intention is to show, in one place, what really happens from startup to authenticated request handling, and how each step hands control to the next layer.

### One big low-level mental flow

```text
Airflow process starts
    |
    v
[1] import root facade
    auth_manager.py
    config.py
    __init__.py
    |
    v
[2] load canonical manager
    entrypoints/auth_manager.py -> RbacAuthManager
    |
    +--> validate renderer bindings
    +--> create ConfigLoader
    +--> create AuditService
    +--> create RedirectService
    +--> create SessionService
    +--> create RuntimeContextService
    +--> create UserSessionService
    +--> create EntrypointAppService
    +--> create AuthorizationService
    +--> create ProviderRuntimeService
    +--> create IdentityAuthService
    +--> create IdentityMapper facade
    +--> create AuthFlowService
    +--> create UIRenderer
    |
    v
[3] resolve runtime policy source
    permissions.ini
        |
        +--> section_parsers.py
        +--> provider_parsers.py
        +--> mapping_parsers.py
        +--> parse_helpers.py
        |
        v
    typed config models
        |
        +--> advisories
        +--> capability report
        +--> version policy
        +--> last-known-good cache
    |
    v
[4] enable runtime backends
    |
    +--> LDAP enabled?
    |      -> build LDAP client + provider
    |
    +--> Entra enabled?
    |      -> build Entra client + provider
    |
    +--> rate limiter backend
    |      -> memory or redis
    |
    +--> auth state backend
    |      -> cookie or memory or redis
    |
    +--> JWT cookie policy
    |      -> secure / samesite / httponly
    |
    +--> optional config integrity and secret resolution
    |
    v
[5] expose plugin surfaces
    |
    +--> browser routes under /auth
    +--> JSON routes under /auth/flow/*
    +--> token routes under /auth/token*
    +--> authorization hooks for Airflow resources
    |
    v
[6] user reaches login surface
    |
    +--> GET /auth/login
    |      -> RuntimeContextService
    |      -> status_query_service.py
    |      -> status_presenter.py
    |      -> status_panel_renderer.py
    |      -> renderer.py + login.html + auth.css
    |
    v
[7] user chooses an auth method
    |
    +--> LDAP branch
    |      POST /auth/login
    |         |
    |         +--> validate CSRF
    |         +--> sanitize next URL
    |         +--> check LDAP rate limit
    |         +--> LdapAuthProvider.authenticate_credentials()
    |         +--> LDAP client bind/search
    |         +--> ExternalIdentity
    |
    +--> Entra branch
           GET /auth/oauth-login/azure
              |
              +--> sanitize next URL
              +--> check OAuth start rate limit
              +--> generate state / nonce / PKCE
              +--> persist transient auth state
              +--> redirect to Microsoft
              |
              v
           callback to /auth/oauth-authorized/azure
              |
              +--> load flow state
              +--> validate state / nonce / PKCE
              +--> exchange code
              +--> validate token / claims
              +--> ExternalIdentity
    |
    v
[8] normalize external identity
    |
    +--> ldap_mapper.py
    +--> entra_mapper.py
    |
    v
    RoleMappingResult
    |
    +--> role_mapping
    +--> entra_role_mapping
    +--> optional role_filters
    |
    v
[9] security gate for role survival
    |
    +--> strict_permissions = true
    |      -> drop roles not defined in [role:*]
    |      -> audit auth.role_mapping.dropped if needed
    |
    +--> strict_permissions = false
    |      -> keep role names as mapped
    |
    +--> any usable roles remain?
           |
           +--> yes
           |      -> proceed
           |
           +--> no
                  |
                  +--> auth_user_registration = true
                  |      and fallback role exists
                  |      -> auth.role_mapping.fallback
                  |      -> assign fallback role
                  |
                  +--> otherwise
                         -> auth.role_mapping.empty
                         -> deny login
    |
    v
[10] build authenticated Airflow user
     |
     +--> RbacAuthUser
     +--> issue JWT
     +--> set auth cookie for browser or access_token for API
     +--> write audit success event
     +--> redirect or return JSON
     |
     v
[11] authenticated request lifecycle
     |
     +--> rebuild user from JWT claims
     +--> translate Airflow request into action/resource
     +--> AuthorizationService
     +--> AuthorizationPolicyService
     +--> RbacPolicy / PermissionMatrix
     +--> apply role filters and resource context
     +--> ALLOW or DENY
     |
     v
[12] steady-state operations
     |
     +--> logout clears cookies/state
     +--> expiry triggers reauthentication
     +--> config file changes trigger throttled reload
     +--> reload success refreshes providers/policy
     +--> reload failure keeps last-known-good config
     +--> advisories and audit logs remain available to operators
```

### Transition map: what each phase means

#### Phase 1 — import and bootstrap
The plugin enters through the import-light root files. This stage exists to keep Airflow startup stable and to defer heavy work until the canonical manager is requested.

#### Phase 2 — composition root activation
`RbacAuthManager` becomes the runtime coordinator. It creates the service graph and establishes the boundaries between config, providers, identity, authorization, runtime security, and UI.

#### Phase 3 — config becomes typed runtime state
The INI file is not consumed directly by the login flow. It is parsed into typed config objects, validated, and enriched with advisories. This makes later behavior deterministic and easier to reason about.

#### Phase 4 — runtime capability wiring
Backends are chosen, providers are instantiated, cookie policy is fixed, and safety helpers such as PKCE, config integrity, rate limiting, and secret references become active.

#### Phase 5 — external surfaces are exposed
At this point the plugin is ready to accept browser requests, JSON helper requests, token requests, and Airflow authorization checks.

#### Phase 6 — the login surface becomes a status surface
The login page is rendered with environment, method readiness, status state, and operator-oriented UI messaging. The UI is part of the operational model, not just a form shell.

#### Phase 7 — auth method execution begins
The plugin branches into either LDAP or Entra. This is the provider-specific authentication phase where credentials or authorization codes are verified.

#### Phase 8 — provider output becomes normalized identity
Provider-specific response data is converted into one internal identity shape. This is the point where later logic becomes provider-agnostic.

#### Phase 9 — role survival is decided
This is the most security-sensitive transition. External values are mapped to internal Airflow roles, strict filtering may drop undefined roles, and fallback may convert an empty mapping into baseline access.

#### Phase 10 — authenticated user materialization
Only after successful mapping and policy survival does the plugin create `RbacAuthUser`, issue JWT state, and declare login success.

#### Phase 11 — steady authenticated authorization
Once authenticated, requests are authorized through the internal RBAC engine. This stage is about action/resource evaluation, not about re-running the login flow.

#### Phase 12 — operational continuity
The plugin keeps working after login through reload handling, logout flow, expiry behavior, diagnostics, and compatibility reporting. This phase matters for real operations just as much as the initial sign-in phase.

### How to read the rest of this README from the big flow

Use the large flow above as the master map, then read the sections below as deeper zoom levels:

- **Package layout and responsibilities** explains where each transition stage lives in the source tree.
- **End-to-end auth and authorization flows** expands the LDAP, Entra, token, and authorization branches.
- **Configuration model** explains how phase 3 works and why typed config matters.
- **`permissions.ini` reference** explains what controls phase 3 and phase 9.
- **Security model** and **Security interaction mental flows** explain why phase 9 is the primary security gate.
- **Edge cases and functional scenario catalog** explains what happens when the flow does not take the happy path.

## End-to-end auth and authorization flows

### 1. Browser login flow at a glance

```text
Browser
  |
  +--> GET /auth/login
  |      |
  |      +--> AuthFlowService.render_login_form()
  |      +--> UIRenderer.render_login_page()
  |      +--> show LDAP form and/or Entra button
  |
  +--> POST /auth/login                        [LDAP branch]
  |      |
  |      +--> CSRF validation
  |      +--> rate-limit check
  |      +--> LDAP authenticate
  |      +--> normalize external identity
  |      +--> map external groups -> Airflow roles
  |      +--> issue Airflow JWT cookie
  |      +--> redirect to safe next URL
  |
  +--> GET /auth/oauth-login/azure            [Entra start]
  |      |
  |      +--> rate-limit check
  |      +--> state/nonce/PKCE generation
  |      +--> transient auth-state persisted
  |      +--> redirect to Microsoft
  |
  +--> GET /auth/oauth-authorized/azure       [Entra callback]
         |
         +--> validate state / nonce / PKCE
         +--> exchange code for identity
         +--> normalize claims
         +--> map claims -> Airflow roles
         +--> issue Airflow JWT cookie
         +--> clear transient cookies/state
         +--> redirect to safe next URL
```

---

### 2. LDAP browser login — low-level execution path

```text
POST /auth/login
|
+--> LdapBrowserFlowService.handle_login_submit()
     |
     +--> refresh config if needed
     +--> resolve cookie security using request + trusted proxies
     +--> parse form
     +--> validate CSRF against transient cookie
     +--> sanitize next URL
     +--> reject if LDAP provider disabled
     +--> reject if username/password missing
     +--> check LDAP rate limiter
     +--> IdentityAuthService.authenticate_ldap()
            |
            +--> LdapAuthProvider.authenticate_credentials()
                   |
                   +--> LdapClient.authenticate()
                          |
                          +--> connection setup / TLS options
                          +--> direct bind + search
                          +--> build LdapUserInfo
                   |
                   +--> IdentityMapper.map_ldap_identity()
                   +--> IdentityAuthService.map_ldap_roles()
                          |
                          +--> RbacPolicy.map_dns_to_roles()
                          +--> strict_permissions filtering
                          +--> optional default Public role
                          +--> audit logging
                   |
                   +--> build RbacAuthUser
     |
     +--> clear LDAP failure counters
     +--> issue JWT using Airflow signing
     +--> set auth cookie
     +--> clear flow cookies
     +--> redirect to sanitized target with success status markers
```

**Important behavior**

- form submissions are protected with a plugin-owned CSRF token cookie,
- failed attempts can be throttled and eventually locked,
- successful login clears accumulated LDAP rate-limit state,
- the plugin does not trust arbitrary `next` URLs and only keeps same-origin redirects.

---

### 3. Entra SSO — low-level execution path

```text
GET /auth/oauth-login/azure
|
+--> OauthBrowserFlowService.handle_oauth_login_azure()
     |
     +--> refresh config
     +--> reject if Entra provider disabled
     +--> sanitize next URL
     +--> check OAuth start rate limiter
     +--> generate state + nonce
     +--> optionally generate PKCE verifier + challenge
     +--> persist flow state
     |     +--> cookie backend, or
     |     +--> memory backend, or
     |     +--> redis backend
     +--> build external callback URL
     +--> redirect to Microsoft authorize endpoint


GET /auth/oauth-authorized/azure
|
+--> OauthBrowserFlowService.handle_oauth_authorized_azure()
     |
     +--> load flow state from configured backend
     +--> validate callback parameters
     +--> exchange authorization code
     +--> verify signature/audience/issuer as configured
     +--> extract claims
     +--> IdentityMapper.map_entra_identity()
     +--> IdentityAuthService.map_entra_roles()
     +--> issue Airflow JWT
     +--> set auth cookie
     +--> clear transient auth-state cookies/backend record
     +--> redirect to sanitized target
```

**Important behavior**

- PKCE is controlled globally from `[security] enable_pkce`,
- transient OAuth flow state can stay cookie-only for simple deployments or move to Redis for multi-worker resilience,
- Entra group overage Graph fallback exists in config and is gated by security policy,
- callback URL reconstruction is proxy-aware and depends on `general.trusted_proxies`.

---

### 4. API and CLI token issuance flow

```text
API client / CLI
   |
   +--> POST /auth/token
   |        body = {"username": "...", "password": "..."}
   |
   +--> POST /auth/token/cli
            body = {"username": "...", "password": "..."}
            |
            +--> TokenFlowService
            +--> AuthFlowPayloadBuilder.issue_token_result()
            +--> manager.create_token(...)
                   |
                   +--> LDAP credential auth only
                   +--> map LDAP groups -> Airflow roles
                   +--> build RbacAuthUser
            +--> issue JWT
                   |
                   +--> uses [api_auth] jwt_expiration_time or
                   +--> uses [api_auth] jwt_cli_expiration_time
            +--> return {"access_token": "..."}
```

**Important behavior**

- token issuance in plugin is **LDAP credential based**,
- browser SSO and token issuance share the same downstream role-mapping logic,
- CLI tokens and normal API tokens use different Airflow expiry settings.

---

### 5. Authorization decision flow

```text
Airflow authorization hook
   |
   +--> is_authorized_view(...)
   +--> is_authorized_dag(...)
   +--> is_authorized_connection(...)
   +--> is_authorized_pool(...)
   +--> is_authorized_variable(...)
   +--> filter_authorized_menu_items(...)
          |
          v
AuthorizationService
          |
          v
AuthorizationPolicyService
          |
          +--> translate method -> action
          |       GET    -> can_read
          |       POST   -> can_create
          |       PUT    -> can_edit
          |       DELETE -> can_delete
          |       menu   -> menu_access
          |
          +--> translate object -> resource
          |
          +--> optionally build AuthorizationContext
                  dag_id
                  dag_tags
                  environments
          |
          v
RbacPolicy.is_allowed(...)
          |
          +--> compile active roles
          +--> apply optional role_filters
          +--> normalize action/resource
          +--> expand DAG umbrella resources
          +--> evaluate wildcard/resource matches
          v
ALLOW / DENY
```

**Mental model**

Authentication determines *who* the user is. The RBAC engine determines *what* that user may do, using only roles plus optional resource context.

---

### 6. Config reload and degraded-mode flow

```text
permissions.ini changes on disk
    |
    v
ConfigLoader.get_config()
    |
    +--> reload checks throttled by general.config_reload_seconds
    +--> compare file mtime
    +--> parse + validate full config
    |
    +--> first load fails
    |     -> auth manager starts degraded / unavailable
    |
    +--> later reload fails
    |     -> keep last-known-good config
    |
    +--> later reload succeeds
          -> rebuild providers
          -> rebuild RBAC policy
          -> reconfigure rate limiters
          -> log recovery from degraded mode if applicable
```

This is one of the strongest operational features in plugin. It prevents transient config or filesystem errors from instantly breaking a previously healthy running auth layer.

---

### 7. Transient auth-state storage model

```text
Entra browser flow state
(state, nonce, next_url, code_verifier)
        |
        +--> security.auth_state_backend = cookie
        |       -> stored in short-lived browser cookies
        |
        +--> security.auth_state_backend = memory
        |       -> process-local in-memory TTL store
        |
        +--> security.auth_state_backend = redis
                -> shared Redis-backed store
```

**Operational rule**

For enterprise multi-worker deployments, Redis is the safest choice for SSO transient state.

---

### 8. Secret resolution and config integrity flow

```text
permissions.ini secret-bearing field
   |
   +--> env:VAR_NAME
   +--> file:/absolute/path
   +--> airflow_var:VARIABLE_NAME
   +--> literal:secret
   +--> plaintext value (only if explicitly allowed)
          |
          v
resolve_secret_reference(...)
          |
          +--> success -> resolved value + source
          +--> failure -> SecurityConfigError
```

```text
permissions.ini
   |
   +--> verify_hmac_integrity(file)
          |
          +--> reads key from env or key file
          +--> reads detached signature file
          +--> validates before full parse
```

---

## Configuration model

### Activation

Airflow points to the plugin through `[core] auth_manager`:

```ini
[core]
auth_manager = rbac_providers_auth_manager.auth_manager.RbacAuthManager
```

The plugin resolves `permissions.ini` using this order:

1. `[core] itim_ldap_permissions_ini` if set,
2. packaged `config_runtime/permissions.ini`,
3. fallback `$AIRFLOW_HOME/permissions.ini` if relevant.

### Configuration principles

plugin’s config model is intentionally split into:

- **syntax and typed models** — `config_runtime/models.py`
- **section parsing** — `section_parsers.py`
- **provider parsing and validation** — `provider_parsers.py`
- **role and mapping parsing** — `mapping_parsers.py`
- **advisories and capability reports** — `advisories.py` and `advisory_rules.py`
- **reload and caching** — `facade.py`

This separation is important because it lets maintainers evolve validation, defaults, and operator messaging without entangling provider logic.


### Config-to-runtime mental model

```text
permissions.ini
   |
   +--> section_parsers.py         -> [meta] [general] [security] [ui] [jwt]
   +--> provider_parsers.py        -> [ldap] [entra_id]
   +--> mapping_parsers.py         -> [role_mapping] [entra_role_mapping] [role:*] [role_filters:*]
   |
   v
AuthConfig (typed models)
   |
   +--> validation results
   +--> advisories
   |
   v
RbacAuthManager runtime
   |
   +--> provider clients
   +--> auth flow services
   +--> session/cookie behavior
   +--> RBAC policy
   +--> UI wording/presentation
   +--> rate limiter and auth-state backends
```

The key design choice here is that the INI file is not read “ad hoc” by the login code. It is parsed once into typed runtime objects, validated, enriched with advisories, and only then consumed by the provider, session, UI, and authorization layers.

### Minimal activation example

```ini
[core]
auth_manager = rbac_providers_auth_manager.auth_manager.RbacAuthManager
itim_ldap_permissions_ini = /opt/airflow/plugins/rbac_providers_auth_manager/permissions.ini
```

### Minimal LDAP-oriented example

```ini
[general]
enable_ldap = true
enable_entra_id = false
strict_permissions = true
deny_if_no_roles = true

[ldap]
enabled = true
server_uri = ldaps://ldap.example.com:636
username_dn_format = CN=%s,OU=Users,DC=example,DC=com
search_base = OU=Users,DC=example,DC=com
tls_ca_cert_file = /etc/pki/ca-trust/source/anchors/corp-ca.pem

[role_mapping]
Viewer = CN=AIRFLOW_VIEWER,OU=Groups,DC=example,DC=com
Op = CN=AIRFLOW_OP,OU=Groups,DC=example,DC=com
Admin = CN=AIRFLOW_ADMIN,OU=Groups,DC=example,DC=com

[role:Viewer]
menu_access = DAGs, DAG Runs
can_read = DAGs, DAG Runs, Task Instances, Website
can_edit = My Profile, My Password
```

### Minimal Entra-oriented example

```ini
[general]
enable_ldap = false
enable_entra_id = true
strict_permissions = true
deny_if_no_roles = true
trusted_proxies = 127.0.0.1/32, 10.0.0.0/8

[security]
auth_state_backend = redis
auth_state_redis_url = redis://redis.example.com:6379/3
rate_limit_backend = redis
redis_url = redis://redis.example.com:6379/2
enable_pkce = true

[entra_id]
enabled = true
tenant_id = 00000000-0000-0000-0000-000000000000
client_id = 11111111-1111-1111-1111-111111111111
client_secret = env:AIRFLOW_ENTRA_CLIENT_SECRET
roles_claim_key = groups
scope = openid, email, profile, groups

[entra_role_mapping]
airflow viewers = Viewer
airflow operators = Op
airflow admins = Admin
```


---

## `permissions.ini` reference

### File-level concepts

`permissions.ini` is the source of truth for:

- provider enablement,
- LDAP connectivity and TLS behavior,
- Entra SSO behavior,
- LDAP DN → Airflow role mapping,
- Entra claim value → Airflow role mapping,
- Airflow role → action/resource permission expansion,
- optional role filters,
- login page customization.

### Accepted secret reference prefixes

| Prefix | Meaning | Notes |
|---|---|---|
| `env:VAR_NAME` | Read from environment | preferred for container/systemd secrets |
| `file:/absolute/path` | Read from a file | useful with mounted secret files |
| `airflow_var:NAME` | Read from Airflow Variable | supported by `resolve_secret_reference` |
| `literal:value` | explicit literal secret | opt-in explicitness |
| plaintext | raw secret value | rejected unless `allow_plaintext_secrets=true` |

### HMAC integrity environment variables

The config-integrity check supports these environment variables:

- `AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY`
- `AIRFLOW_ITIM_LDAP_CONFIG_HMAC_KEY_FILE`
- `AIRFLOW_ITIM_LDAP_CONFIG_HMAC_SIG_FILE`

If configured, the file is verified before parsing.

---

### `[meta]`

Schema metadata that protects the plugin from loading a config intended for something else.

| Key | Expected / possible values | Behavior |
|---|---|---|
| `schema_version` | currently `1` | must match the code’s supported schema version or load fails |
| `plugin_family` | `rbac_providers_auth_manager` | prevents cross-loading configs from other plugins |

---

### `[general]`

Global runtime behavior and provider enablement.

| Key | Values | Effect |
|---|---|---|
| `config_reload_seconds` | integer `>=0` | throttles how often the file system is checked for config changes |
| `strict_permissions` | `true` / `false` | if true, only roles defined in `[role:*]` sections survive mapping |
| `log_level` | standard Python log level text | configures the plugin logger namespace |
| `deny_if_no_roles` | `true` / `false` | if true, authentication without mapped roles becomes access denial |
| `auth_user_registration` | `true` / `false` | when true, the plugin may apply the fallback self-registration role |
| `auth_user_registration_role` | role name | fallback role assigned when self-registration is allowed |
| `trusted_proxies` | comma-separated CIDRs/IPs | controls whether forwarded headers are trusted for redirect/callback/security decisions |
| `enable_ldap` | `true` / `false` | global LDAP enablement hint |
| `enable_entra_id` | `true` / `false` | global Entra enablement hint |

**Important interaction**

`strict_permissions=true` is the safer enterprise mode. It prevents mappings to undefined roles from quietly becoming effective.

---

### `[security]`

Security hardening, throttling, and distributed-state behavior.

| Key | Values | Effect |
|---|---|---|
| `allow_plaintext_secrets` | `true` / `false` | whether raw secret values in config are allowed |
| `sensitive_debug_logging` | `true` / `false` | enables more detailed sensitive debug logs/fingerprints |
| `allow_insecure_ldap_tls` | `true` / `false` | required before `ldap.allow_self_signed=true` is accepted |
| `rate_limit_backend` | `memory`, `in_memory`, `local`, `redis` | selects LDAP/OAuth rate limiter backend |
| `redis_url` | Redis URL | required when `rate_limit_backend=redis` |
| `redis_prefix` | string | namespace prefix for rate-limit keys |
| `auth_state_backend` | `cookie`, `browser_cookie`, `memory`, `in_memory`, `local`, `redis` | selects Entra transient flow-state backend |
| `auth_state_redis_url` | Redis URL | used by auth-state Redis backend |
| `auth_state_redis_prefix` | string | Redis namespace prefix for auth-state records |
| `auth_state_ttl_seconds` | integer | TTL for Entra transient state in shared backends |
| `enable_ldap_rate_limit` | `true` / `false` | enables LDAP throttling logic |
| `ldap_max_failures` | integer | maximum failed LDAP attempts in the window before denial/lockout |
| `ldap_failure_window_seconds` | integer | LDAP rate-limit window |
| `ldap_lockout_seconds` | integer | lockout duration after limit hit |
| `enable_oauth_rate_limit` | `true` / `false` | enables Entra login-start throttling |
| `oauth_max_starts` | integer | max Entra starts in the window |
| `oauth_window_seconds` | integer | Entra login-start rate-limit window |
| `oauth_lockout_seconds` | integer | lockout duration for Entra start flow |
| `enable_pkce` | `true` / `false` | globally enables PKCE for OAuth browser flow |
| `allow_graph_group_fallback` | `true` / `false` | must be true before Entra Graph group-overage fetch is allowed |

**Enterprise reading**

- `memory` is fine for single-worker baselines.
- `redis` is the safer choice when multiple API workers or multiple instances are involved.
- advisory rules warn when a non-shared backend is risky for the actual deployment shape.

---

### `[ui]`

Login-page text and presentation controls.

| Key | Values | Effect |
|---|---|---|
| `enable_rich_login_status` | `true` / `false` | enables the richer status panel instead of only a basic banner |
| `show_environment` | `true` / `false` | shows environment label in the login UI |
| `show_mapped_roles` | `true` / `false` | exposes mapped role summary in status details |
| `show_reference_id` | `true` / `false` | shows a support/correlation reference ID |
| `show_auth_method` | `true` / `false` | shows the auth method label in status |
| `compact_status_details_line` | `true` / `false` | uses a compact detail line in the status panel |
| `compact_success_status_line` | `true` / `false` | compresses success messaging |
| `title_ready` | text | title used for idle/ready state |
| `title_success` | text | title used on successful sign-in |
| `title_failure` | text | title used on failures |
| `title_no_roles` | text | title used when auth succeeds but no role is mapped |
| `ldap_method_label` | text | label shown for LDAP method |
| `entra_method_label` | text | label shown for Entra method |
| `ldap_ready_text` | text | helper text for LDAP idle state |
| `ldap_success_text` | text | LDAP success message |
| `ldap_no_roles_text` | text | LDAP no-role message |
| `entra_ready_text` | text | helper text for Entra idle state |
| `entra_progress_text` | text | progress text while Entra flow is in-flight |
| `entra_success_text` | text | Entra success message |
| `entra_no_roles_text` | text | Entra no-role message |

### Environment-driven UI values

These are **not** in the INI file:

| Variable | Effect |
|---|---|
| `AIRFLOW_ITIM_UI_ENV_LABEL` | short environment badge shown in the login page |
| `AIRFLOW_ITIM_UI_SUPPORT_CONTACT` | support/help contact text shown in the UI |

If unset, the code falls back to a default environment label derived from Airflow executor info and a default support contact string.

---

### `[jwt]` or `[jwt_cookie]`

Cookie transport settings for browser login.

| Key | Values | Effect |
|---|---|---|
| `cookie_httponly` | `true` / `false` | forced to true; false is warned and overridden |
| `cookie_samesite` | `lax`, `strict`, `none` | invalid values are forced to `lax` |
| `cookie_path` | path string | cookie path for JWT cookie |
| `cookie_domain` | domain or empty | optional cookie domain |
| `cookie_secure` | `true`, `false`, `auto` | if `auto`/empty, the plugin infers security from request/proxy context |

**Important interaction**

If `cookie_samesite=none`, the code forces `secure=true` even when auto detection would say otherwise.

---

### `[ldap]`

LDAP provider configuration.

#### Required for enabled LDAP

- `server_uri` or `uri`
- `username_dn_format`
- `search_base`

If LDAP is enabled but these are missing, LDAP is disabled and a validation warning is emitted. If no other provider remains usable, the auth manager starts unavailable.

#### Main keys

| Key | Values | Effect |
|---|---|---|
| `enabled` | `true` / `false` | provider-local enablement |
| `server_uri` / `uri` | LDAP/LDAPS URI | target directory |
| `bind_dn` | DN | optional bind identity if the client/path uses it |
| `bind_password` | secret reference | bind secret |
| `username_dn_format` | format string | used for direct bind style username → DN |
| `search_base` | DN | base DN for user lookup |
| `user_base_dn` / `base_dn` | DN | alias/fallback for search base |
| `user_filter` | LDAP filter | search filter template |
| `group_attribute` / `group_attr` | attribute name | group membership attribute |
| `attr_uid` / `uid_attr` | attribute name | stable user ID attribute |
| `attr_username` / `username_attr` | attribute name | canonical username attribute |
| `attr_first_name` / `first_name_attr` | attribute name | first-name attribute |
| `attr_last_name` / `last_name_attr` | attribute name | last-name attribute |
| `attr_email` / `email_attr` | attribute name | email attribute |
| `start_tls` | `true` / `false` | enables StartTLS on the connection |
| `allow_self_signed` | `true` / `false` | only accepted if `[security] allow_insecure_ldap_tls=true` |
| `tls_ca_cert_file` / `ca_cert_file` | path | CA certificate file |
| `tls_require_cert` | `demand`, `hard`, `allow`, etc. | certificate validation mode; coerced when self-signed mode is enabled |
| `resolve_nested_groups` | `true` / `false` | enables nested-group expansion logic |
| `nested_groups_base_dn` | DN | optional nested-group search base |
| `nested_group_match_rule` | OID | nested-group matching rule OID |
| `connect_timeout_seconds` | integer | connection timeout |
| `network_timeout_seconds` | integer | network timeout |
| `operation_timeout_seconds` | integer | operation timeout |
| `search_time_limit_seconds` / `search_timeout_seconds` | integer | server-side search limit |
| `size_limit` | integer | LDAP search size limit |
| `chase_referrals` | `true` / `false` | whether referrals are chased |
| `username_pattern` | regex | input validation pattern |
| `username_max_length` | integer | max accepted username length |

**Behavior notes**

- `allow_self_signed=true` without security opt-in is rejected.
- if `allow_self_signed=true` and `tls_require_cert` is too strict, the code logs a warning and coerces it to `allow`.
- username validation is part of the LDAP identity service and reduces injection/abuse risk.

---

### `[entra_id]` (aliases also accepted)

Entra ID / OAuth2 browser SSO configuration.

#### Required for enabled Entra

- `tenant_id`
- `client_id`
- `client_secret`
- `scope` must include `openid`
- `roles_claim_key` must be `groups` or `roles`
- `allowed_oidc_hosts` must not be empty

If enabled Entra fails validation and LDAP is also unavailable, the auth manager becomes unavailable.

#### Main keys

| Key | Values | Effect |
|---|---|---|
| `enabled` | `true` / `false` | provider-local enablement |
| `tenant_id` | tenant GUID/string | used to derive metadata URL if not explicitly set |
| `client_id` | app registration ID | Entra application identifier |
| `client_secret` | secret reference | OAuth client secret |
| `provider_name` / `name` | text | provider identifier |
| `button_text` | text | button label in login UI |
| `icon` | text | icon class for UI |
| `scope` / `scopes` | comma or space separated | requested OAuth scopes |
| `roles_claim_key` | `groups` or `roles` | which claim is used for role mapping |
| `verify_signature` | `true` / `false` | token signature verification toggle |
| `allowed_audiences` | comma-separated values | accepted token audiences; defaults to `client_id` |
| `http_timeout_seconds` | integer | HTTP timeout for metadata/token requests |
| `http_max_retries` | integer | outbound retry count |
| `http_retry_backoff_seconds` | integer | retry backoff |
| `metadata_url` | URL | OIDC metadata endpoint |
| `authorize_url` | URL | optional override |
| `access_token_url` | URL | optional override |
| `jwks_uri` | URL | optional override |
| `issuer` | URL/string | optional override |
| `username_claim` | claim name | username claim |
| `email_claim` | claim name | email claim |
| `first_name_claim` | claim name | first name claim |
| `last_name_claim` | claim name | last name claim |
| `display_name_claim` | claim name | full display name claim |
| `graph_fetch_groups_on_overage` | `true` / `false` | enables Graph fallback for group overage if security allows it |
| `graph_memberof_url` | URL | Graph URL for group membership lookup |
| `clock_skew_seconds` | integer | tolerance for token validation time skew |
| `allowed_oidc_hosts` | comma-separated hosts | outbound host allowlist for OIDC/Graph fetches |

**Behavior notes**

- if `metadata_url` is not set, the code derives it from `tenant_id`,
- Graph fallback requires both the feature flag in `[entra_id]` and security opt-in in `[security]`,
- PKCE behavior is inherited from `[security] enable_pkce`.

---

### `[role_mapping]`

LDAP group mapping to Airflow roles.

The parser supports **two styles**.

#### Legacy style

```ini
[role_mapping]
CN=MY_GROUP,OU=Groups,DC=example,DC=com = Viewer
```

#### Recommended style

```ini
[role_mapping]
Viewer = CN=MY_GROUP_1,OU=Groups,DC=example,DC=com | CN=MY_GROUP_2,OU=Groups,DC=example,DC=com
```

**Behavior**

- the parser canonicalizes DNs,
- multiple roles can be assigned,
- multiple DNs can map to one role,
- with `strict_permissions=true`, only roles that also exist in `[role:*]` sections remain active.

---

### `[entra_role_mapping]`

Maps a normalized Entra claim value to one or more Airflow roles.

```ini
[entra_role_mapping]
finance airflow viewer = Viewer
data platform operators = Op
```

**Behavior**

- keys are normalized case-insensitively,
- the mapping targets the claim selected by `roles_claim_key`,
- undefined role targets trigger advisories.

---

### `[role:<RoleName>]`

Declares the actual permissions attached to an Airflow role.

Supported action keys are:

- `menu_access`
- `can_read`
- `can_edit`
- `can_create`
- `can_delete`

Each value is parsed as a comma-separated resource list.

```ini
[role:Viewer]
menu_access = DAGs, DAG Runs
can_read = DAGs, DAG Runs, Task Instances
can_edit = My Profile, My Password
```

**Behavior**

- action names are normalized,
- resource names are normalized,
- wildcard `*` is supported,
- DAG-like resources participate in umbrella/prefix logic inside the RBAC engine.

---

### `[role_filters:<RoleName>]`

Optional runtime scoping of a role.

| Key | Values | Effect |
|---|---|---|
| `dag_tags` | comma-separated tags | role only stays active when current DAG tags intersect |
| `environments` | comma-separated labels | role only stays active when runtime environment labels intersect |
| `resource_prefixes` | comma-separated prefixes | role only stays active when `resource_id` begins with one of these prefixes |

```ini
[role_filters:Viewer]
dag_tags = finance, critical
environments = prod
resource_prefixes = dag_fin_
```

**Important behavior**

If no runtime resource context is available, the role remains active. This preserves backward compatibility for checks that cannot supply metadata.

---

## Role model and permission semantics

### Supported actions

The plugin uses a FAB-style action vocabulary:

```text
menu_access
can_read
can_edit
can_create
can_delete
*
```

### Resource examples in the shipped config

The shipped role bundles reference resources such as:

```text
Assets
Asset Aliases
Audit Logs
Backfills
Cluster Activity
Configurations
Connections
DAGs
DAG Code
DAG Dependencies
DAG Runs
DAG Versions
DAG Warnings
HITL Detail
ImportError
Jobs
My Password
My Profile
Plugins
Pools
Providers
SLA Misses
Task Instances
Task Logs
Task Reschedules
Triggers
Variables
Website
XComs
```

### Permission matching semantics

The RBAC engine supports:

- exact action/resource matches,
- `action=*`,
- `resource=*`,
- full `*:*`,
- DAG umbrella matches, for example concrete DAG resources can fall back to broader DAG resource grants,
- resource-prefix checks for discovery logic.

### Strict vs non-strict role handling

With `strict_permissions=true`:

- mapped roles that are not defined in `[role:*]` sections are dropped,
- dropped roles are audit-logged.

With `strict_permissions=false`:

- mapped roles may remain even if not explicitly defined in the current config.

### No-role outcomes

If authentication succeeds but no role is mapped:

- the plugin logs a dedicated audit event,
- the UI can show a custom “no Airflow access assigned” message,
- in the provided plugin code, the effective runtime outcome is determined by `auth_user_registration` and the validity of `auth_user_registration_role`,
- `deny_if_no_roles` is included in audit payloads for operator visibility, but it is not used as a separate enforcement branch in the plugin implementation.

---

## UI behavior and customization

### Login page model

The login UI is not just a plain form. It acts as an operational status surface.

```text
+---------------------------------------------------------------------+
| Header: logo/title/environment badge                                |
|---------------------------------------------------------------------|
| Left column                                                         |
|   - LDAP form if LDAP enabled                                       |
|   - Microsoft sign-in button if Entra enabled                       |
|                                                                     |
| Right column                                                        |
|   - support/help text                                               |
|   - provider guidance                                               |
|   - environment/support metadata                                    |
|---------------------------------------------------------------------|
| Status area                                                         |
|   - title                                                           |
|   - message                                                         |
|   - method label                                                    |
|   - mapped roles summary                                            |
|   - reference ID                                                    |
|   - retry-after                                                     |
+---------------------------------------------------------------------+
```

### Status states recognized by the presenter

The UI status query service recognizes and renders states such as:

| Trigger | Typical title | Typical meaning |
|---|---|---|
| `status=logged_out` | signed out/info | logout completed |
| `status=expired` | session expired | reauthentication required |
| `status=success` | access granted | authentication and mapping succeeded |
| `error=missing` | sign-in failed / info | username or password missing |
| `error=unauthorized` | no Airflow access assigned | auth succeeded but role mapping empty |
| `error=invalid` | sign-in failed | bad credentials or failed auth |
| `error=csrf` | session expired | form token mismatch/expiry |
| `error=sso` | single sign-on failed | Entra callback failure |
| `error=ldap_disabled` | password login disabled | LDAP branch disabled |
| `error=throttled` | too many attempts | rate limit or lockout |
| `error=config_disabled` | authentication unavailable | no usable provider remains |

### JSON diagnostic endpoints for the UI and future automation

The FastAPI app also exposes normalized JSON flow endpoints:

| Endpoint | Purpose |
|---|---|
| `/auth/flow/providers` | provider readiness snapshot |
| `/auth/flow/login-status` | normalized login status payload |
| `/auth/flow/oauth-callback-state` | callback-state diagnostic payload |
| `/auth/flow/logout-state` | logout target + cleanup scope |

These endpoints do not replace the browser flow. They make the same auth-flow state reusable for future clients and debugging.

---

## Logging, audit, and diagnostics

### Logging model

The plugin deliberately does **not** take over global Airflow logging. Instead it:

- configures its own logger namespace,
- keeps legacy namespace compatibility,
- adds a fallback DEBUG handler only when needed.

### Typical startup log examples

```text
INFO rbac_providers_auth_manager.auth_manager: Initialized ITIM auth manager; methods=['ldap'] strict_permissions=True reload=30s schema_version=1 advisories=0
INFO rbac_providers_auth_manager.auth_manager: Runtime capability report: airflow_public_api=available, api_worker_count=1, auth_state_backend=cookie, config_advisories=0, ...
INFO rbac_providers_auth_manager.auth_manager: Runtime version policy: airflow_runtime_version=3.1.8, fab_provider_version=3.5.0, python_runtime_version=3.13.x, ...
INFO rbac_providers_auth_manager.auth_manager: Compatibility doctor report: non_admin_contract_gap_count=0, target_airflow_lines=3.1.x,3.2.x,3.3.x,4.x, ...
```

### Typical reload and advisory examples

```text
INFO rbac_providers_auth_manager.config_runtime.facade: Loaded permissions.ini from /path/to/permissions.ini (mtime_ns=...)
WARNING rbac_providers_auth_manager.config_runtime.parser: LDAP provider disabled due to config validation errors: ['LDAP is enabled but search_base is missing.']
WARNING rbac_providers_auth_manager.config_runtime.parser: Ignoring role_filters sections for undefined roles: ['FinanceViewer']
WARNING rbac_providers_auth_manager.config_runtime.parser: Config advisory [memory_rate_limit_multi_worker]: security.rate_limit_backend=memory is configured while Airflow API workers=4; lockout state will not be shared across workers. Consider the Redis backend for enterprise deployments.
ERROR rbac_providers_auth_manager.auth_manager: Auth manager remains in degraded mode after reload: Entra ID is enabled but client_secret is missing.
INFO rbac_providers_auth_manager.auth_manager: Auth manager recovered from degraded mode; methods=['ldap', 'entra_id']
```

### Structured audit examples

The audit service emits JSON payloads. The exact timestamp and values vary, but the shape is stable.

#### Successful browser login

```json
{
  "timestamp": "2026-03-22T20:15:03.000000+00:00",
  "schema_version": 1,
  "event": "ui.auth.login.success",
  "severity": "info",
  "surface": "ui",
  "outcome": "success",
  "provider": "ldap",
  "principal": "jdoe",
  "subject": "uid=jdoe",
  "ip_address": "10.10.10.25",
  "roles": ["Viewer", "Op"],
  "external_values_count": 3,
  "mapped_values_count": 2,
  "strict_permissions": true
}
```

#### Authentication succeeded but no role mapped

```json
{
  "timestamp": "2026-03-22T20:16:11.000000+00:00",
  "schema_version": 1,
  "event": "auth.role_mapping.empty",
  "severity": "info",
  "outcome": "empty",
  "provider": "entra",
  "principal": "user@example.com",
  "subject": "oid:12345678-....",
  "ip_address": "10.10.10.25",
  "external_values_count": 5,
  "mapped_values_count": 0,
  "strict_permissions": true,
  "deny_if_no_roles": true
}
```

#### Token issuance

```json
{
  "timestamp": "2026-03-22T20:20:00.000000+00:00",
  "schema_version": 1,
  "event": "api.auth.token.success",
  "severity": "info",
  "surface": "api",
  "outcome": "success",
  "mode": "cli",
  "principal": "jdoe",
  "ip_address": "10.10.10.25",
  "detail": "jwt_cli_expiration_time"
}
```

### What the logs mean operationally

- **startup capability report** tells you what the running instance actually supports,
- **version policy** tells you how close the runtime is to the tested baseline,
- **compatibility doctor** tells you how the shipped role bundles compare to the intended contract,
- **audit logs** tell you what happened for real login and mapping events,
- **config advisories** warn about risky but non-fatal deployment choices.

---

## Security model

### 1. Redirect safety

The plugin sanitizes `next` URLs and only preserves same-origin redirects. Suspicious values are collapsed to `/`.

### 2. Proxy awareness

Trusted proxy handling is explicit. Forwarded headers are only trusted when the caller IP matches `general.trusted_proxies`.

### 3. CSRF on LDAP browser login

LDAP form submission uses a transient CSRF cookie token, and mismatches lead to a safe failure path.

### 4. Cookie hardening

- `HttpOnly` is enforced,
- `SameSite` is validated and normalized,
- `Secure` can be auto-detected or explicitly forced,
- `SameSite=None` forces `Secure=true`.

### 5. Secret hygiene

Secret-bearing fields are resolved through explicit references. Raw plaintext can be rejected.

### 6. Config integrity

Detached HMAC verification can protect `permissions.ini` against tampering.

### 7. Rate limiting

Both LDAP and OAuth start flows can be rate limited, with optional lockout windows.

### 8. PKCE support

PKCE generation is built into the runtime and enabled through security config.

### 9. Sensitive debug mode is gated

The code distinguishes normal debug logging from more sensitive/fingerprinted diagnostics.

### 10. No-role denial path

This is important in enterprise setups: successful authentication is not enough. Access is only granted when a valid mapped Airflow role survives policy evaluation.

### 11. Security interaction of `strict_permissions`, `deny_if_no_roles`, and `auth_user_registration`

These three keys look like one policy block, but in the provided plugin code they do not all influence runtime in the same way.

`strict_permissions` is an active enforcement switch. It changes how external roles are treated during mapping:

- for LDAP, mapped roles that are not defined in `[role:*]` sections are dropped before the user model is finalized,
- for Entra, undefined mapped roles are also dropped before the authenticated user is built,
- when dropping happens, the plugin emits `auth.role_mapping.dropped`,
- if everything is dropped and nothing remains, the flow enters the no-role path.

`auth_user_registration` is also an active enforcement switch. In plugin it controls whether the plugin may recover from a no-role condition by assigning `auth_user_registration_role`. The fallback is only applied when:

- `auth_user_registration=true`,
- `auth_user_registration_role` is non-empty,
- that role exists in `[role:<RoleName>]`.

If any of those conditions is false, the login flow raises a no-role error and the browser flow returns the user to the login page.

`deny_if_no_roles` is present in the typed config model and is written into audit payloads, but in the plugin code it is not used as a separate decision point after role mapping. Practically, that means changing it alone does not alter the enforcement result in these files.

#### Effective decision model in plugin

```text
External identity authenticated
        |
        v
Role mapping performed
        |
        +--> roles found -----------------------------> authenticated user created
        |
        +--> no roles survive mapping
                |
                +--> auth_user_registration = true
                |       and fallback role exists
                |
                |       ---> fallback role assigned
                |            ---> authenticated user created
                |
                +--> otherwise
                        ---> login denied with no-role error
```

#### Combination matrix for the three settings

```text
+----+--------------------+------------------+------------------------+-----------------------------------------------+
| #  | strict_permissions | deny_if_no_roles | auth_user_registration | Effective security behavior in plugin            |
+----+--------------------+------------------+------------------------+-----------------------------------------------+
| 1  | true               | true             | false                  | Most restrictive. Undefined roles are dropped;|
|    |                    |                  |                        | if nothing remains, login is denied.          |
| 2  | true               | false            | false                  | Same runtime outcome as #1 in plugin.            |
| 3  | true               | true             | true                   | Strict mapping first; if no roles remain,     |
|    |                    |                  |                        | fallback registration role may grant access.  |
| 4  | true               | false            | true                   | Same runtime outcome as #3 in plugin.            |
| 5  | false              | true             | false                  | Non-strict mapping keeps undefined roles in   |
|    |                    |                  |                        | the user object; if still no roles, deny.     |
| 6  | false              | false            | false                  | Same runtime outcome as #5 in plugin.            |
| 7  | false              | true             | true                   | Broadest acceptance. Non-strict mapping keeps |
|    |                    |                  |                        | more roles, and empty mapping can still       |
|    |                    |                  |                        | fall back to registration role.               |
| 8  | false              | false            | true                   | Same runtime outcome as #7 in plugin.            |
+----+--------------------+------------------+------------------------+-----------------------------------------------+
```

#### Security reading of those combinations

The safest combinations are `strict_permissions=true` and `auth_user_registration=false`, because they require every granted Airflow role to be both explicitly mapped and explicitly defined in `permissions.ini`. That minimizes accidental privilege caused by typos, stale role names, or upstream directory drift.

Turning `strict_permissions=false` is operationally permissive. It allows mapped role names to survive even when they are not currently defined in `[role:*]`. That reduces friction during migrations, but it also weakens the guarantee that every granted role has a locally reviewed permission definition.

Turning `auth_user_registration=true` changes the security posture much more than the name may suggest. In this plugin it is effectively a no-role fallback switch. A successfully authenticated identity that resolves to no Airflow roles can still enter Airflow through `auth_user_registration_role`. If that role is `Public`, the real security boundary becomes the permission set attached to `[role:Public]`.

That is why the config advisory layer warns when auto-registration is enabled and the `Public` role carries broad permissions.

#### Logged output for the key cases

Successful mapped login produces a structured audit success entry and an operator-facing role summary. Representative examples:

```json
{"event":"ui.auth.login.success","external_values_count":3,"ip_address":"10.20.30.40","mapped_values_count":2,"principal":"jsmith","provider":"ldap","roles":["Admin","Viewer_custom"],"schema_version":1,"severity":"info","strict_permissions":true,"surface":"ui","timestamp":"2026-03-22T20:10:11.000000+00:00"}
```

```text
Final mapped roles for user=jsmith roles=['Admin', 'Viewer_custom']
```

If `strict_permissions=true` causes undefined roles to be discarded, the plugin emits a drop event:

```json
{"dropped_roles":["LegacyRole","TypoRole"],"event":"auth.role_mapping.dropped","principal":"jsmith","provider":"ldap","schema_version":1,"severity":"info","strict_mode":true,"timestamp":"2026-03-22T20:10:11.000000+00:00"}
```

If authentication succeeds but no usable Airflow role remains, the plugin emits the empty-mapping event. Notice that `deny_if_no_roles` is present in the audit payload even though it does not independently change runtime enforcement in plugin:

```json
{"deny_if_no_roles":true,"event":"auth.role_mapping.empty","external_values_count":4,"ip_address":"10.20.30.40","mapped_values_count":0,"principal":"jsmith","provider":"ldap","schema_version":1,"severity":"info","strict_permissions":true,"subject":"CN=John Smith,OU=Users,DC=example,DC=com","timestamp":"2026-03-22T20:10:11.000000+00:00"}
```

If fallback registration is enabled and valid, the plugin emits a dedicated fallback event before completing login:

```json
{"event":"auth.role_mapping.fallback","fallback_role":"Public","ip_address":"10.20.30.40","principal":"jsmith","provider":"registration","schema_version":1,"severity":"info","subject":"CN=John Smith,OU=Users,DC=example,DC=com","timestamp":"2026-03-22T20:10:11.000000+00:00"}
```

If fallback is not allowed or not valid, the LDAP browser flow returns the user to the login page with `error=unauthorized`, and the flow logs `ui.auth.login.failure`. In the Entra callback flow, the same no-role condition is surfaced through the generic SSO failure redirect and logged as `ui.auth.oauth_callback.failure`.

#### Behavior while the user is already authenticated

After a successful login, the plugin issues an Airflow JWT and stores it in the configured auth cookie using the cookie hardening settings from `[jwt]` or `[jwt_cookie]`. Subsequent requests are rebuilt from JWT claims into `RbacAuthUser`; the request is then authorized by the internal RBAC policy layer.

Operationally that means:

- the three `[general]` keys discussed here matter primarily at authentication and role-resolution time,
- they do not continuously re-evaluate the already issued JWT on every request,
- authorization for each request is based on the roles already embedded in the authenticated user context,
- if configuration reload later changes mappings or role definitions, the new policy applies to future authentications and future authorization checks after reload, but an already issued token still represents the roles that were issued at login time until expiry or logout,
- normal authenticated requests do not emit a repeated `ui.auth.login.success` event; the main recurring runtime behavior is authorization checks, plus any explicit logout, token, or flow-state events.

When `security.sensitive_debug_logging=true`, the plugin additionally logs external values and permission expansion. That can be very useful for incident response and role-mapping diagnostics, but it increases exposure of identity-adjacent data and should therefore stay off in normal production operation.

---

## Security interaction mental flows

This section translates the core security branches into operator-oriented mental flows. The intent is to make the plugin easier to reason about during reviews, incident handling, and change approval.

### 1. Security control plane mental model

```text
External authentication succeeds
        |
        v
External values collected
        |
        +--> LDAP groups
        +--> Entra groups/roles claims
        |
        v
Role mapping
        |
        +--> [role_mapping]
        +--> [entra_role_mapping]
        |
        v
Role validation
        |
        +--> strict_permissions = true
        |       -> drop roles not defined in [role:*]
        |
        +--> strict_permissions = false
                -> keep mapped role names as-is
        |
        v
Do usable Airflow roles remain?
        |
        +--> yes
        |      -> build authenticated user
        |      -> issue JWT cookie/token
        |      -> authorize requests by RBAC policy
        |
        +--> no
               |
               +--> auth_user_registration = true
               |      and fallback role exists
               |      -> assign fallback role
               |      -> build authenticated user
               |
               +--> otherwise
                      -> deny login
```

**Why this matters**

The plugin separates three concerns that often get conflated:

- upstream authentication proves identity,
- mapping translates external values into internal Airflow roles,
- authorization evaluates those internal roles against actions and resources.

A successful upstream login is therefore not equivalent to Airflow access.

### 2. Effective behavior of the three `[general]` switches

```text
strict_permissions
    -> active enforcement
    -> drops undefined roles when true

deny_if_no_roles
    -> present in config and audit payloads
    -> not a separate enforcement branch in the provided plugin files

auth_user_registration
    -> active fallback branch
    -> may assign auth_user_registration_role when mapping is empty
```

### 3. Secure-vs-permissive posture flow

```text
Need deterministic enterprise RBAC?
        |
        +--> yes
        |      -> strict_permissions = true
        |      -> auth_user_registration = false
        |      -> every surviving role must be both mapped and defined
        |
        +--> need permissive bootstrap behavior?
               |
               +--> auth_user_registration = true
                       |
                       +--> fallback role minimal?
                       |      -> lower risk
                       |
                       +--> fallback role broad?
                              -> unintended access risk
```

### 4. What happens after the user is authenticated

```text
Successful login
    |
    +--> JWT issued
    +--> auth cookie set
    +--> RbacAuthUser built with resolved roles
    |
Subsequent requests
    |
    +--> user rebuilt from JWT claims
    +--> authorization checks use embedded roles
    +--> three [general] switches are not re-decided on every request
```

**Operational meaning**

- role mapping decisions primarily happen at login time,
- an already issued token keeps its effective role set until expiry or logout,
- later upstream changes are not retroactive for that token unless the user logs in again.

### 5. Security signals in logs

```text
auth.role_mapping.hits
    -> external values successfully matched configured role mappings

auth.role_mapping.dropped
    -> strict mode removed one or more mapped roles because they are undefined locally

auth.role_mapping.empty
    -> authentication succeeded but no usable Airflow role remained

auth.role_mapping.fallback
    -> empty mapping was converted into access through auth_user_registration_role

ui.auth.login.success / api.auth.token.success
    -> authenticated user was actually created
```

**Interpretation pattern**

This is the most important incident-response sequence to recognize:

```text
auth.role_mapping.dropped
    -> auth.role_mapping.empty
    -> auth.role_mapping.fallback
    -> ui.auth.login.success
```

That sequence means strict mode correctly rejected undefined roles, but fallback still admitted the user.

### 6. Risk interaction matrix

```text
+--------------------+------------------------+-----------------------------------------------+
| strict_permissions | auth_user_registration | Effective risk reading                         |
+--------------------+------------------------+-----------------------------------------------+
| true               | false                  | safest and most deterministic                  |
| true               | true                   | controlled, but fallback can mask mapping bugs |
| false              | false                  | permissive mapping, weaker local review guard  |
| false              | true                   | broadest acceptance and highest access risk    |
+--------------------+------------------------+-----------------------------------------------+
```

### 7. Practical security guidance

```text
Recommended secure enterprise baseline
    strict_permissions = true
    deny_if_no_roles = true   # policy intent / audit visibility
    auth_user_registration = false
```

Keep these additional guardrails in place:

- keep `[role:Public]` minimal,
- do not use `Admin` or `Op` as `auth_user_registration_role`,
- keep `sensitive_debug_logging=false` in normal production,
- use short JWT lifetimes if rapid de-provisioning matters,
- use Redis-backed shared state in multi-worker SSO deployments.

---

## Edge cases and functional scenario catalog

This section groups the most important runtime situations into mental models and explicit outcomes. It is intended as a practical operator reference and as a checklist for testing.

### 1. Edge-case mental flow

```text
User reaches plugin
    |
    +--> provider unavailable?
    |      -> login page shows unavailable/degraded status
    |
    +--> authentication fails?
    |      -> invalid / throttled / csrf / sso failure path
    |
    +--> authentication succeeds
           |
           +--> mapped roles present
           |      -> normal authenticated user
           |
           +--> no mapped roles
                  |
                  +--> fallback enabled and valid
                  |      -> authenticated with fallback role
                  |
                  +--> otherwise
                         -> denied after successful upstream auth
```

### 2. Edge case: user has only ITIM `User` in the shipped sample

In the provided plugin sample `permissions.ini`, the `User` mapping line in `[role_mapping]` is commented out. That means an external identity that only has the ITIM `User` group behaves the same as a user with no mapped Airflow role at all.

```text
ITIM roles = User only
        |
        v
No active [role_mapping] hit for User
        |
        v
Mapped Airflow roles = empty
        |
        +--> auth_user_registration = false
        |      -> login denied
        |
        +--> auth_user_registration = true
               -> fallback role assigned
               -> in shipped sample that fallback is Public
```

**Result in the shipped sample**

- no full Admin access,
- no Op access,
- no User access,
- only minimal `Public` access if fallback is enabled.

### 3. Edge case: user has no ITIM roles at all

This is functionally the same as the prior case in the shipped sample.

```text
ITIM roles = none
        |
        v
No mapping hits
        |
        v
Mapped Airflow roles = empty
        |
        +--> auth_user_registration = false -> denied
        +--> auth_user_registration = true  -> fallback role
```

**Result in the shipped sample**

- no full Admin access,
- no implicit privilege escalation,
- only fallback `Public` if enabled and valid.

### 4. Edge case: user has ITIM `op + admin + user`

For the shipped sample, `Admin` and `Op` map successfully, while `User` remains ignored because its mapping is commented.

```text
ITIM roles = op + admin + user
        |
        v
Mapped Airflow roles = Admin + Op
        |
        v
Authenticated user created
        |
        v
Effective permissions = union(Admin, Op)
```

Because `Admin` is already present, this user behaves as an Admin-class user in practice.

### 5. Edge case: strict mode drops all roles

```text
External roles mapped
        |
        v
Mapped roles = ["LegacyRole", "TypoRole"]
        |
        +--> strict_permissions = true
               -> roles not defined in [role:*] are dropped
               -> mapping becomes empty
               -> fallback or denial path starts
```

**What to look for in logs**

- `auth.role_mapping.dropped`
- `auth.role_mapping.empty`
- optionally `auth.role_mapping.fallback`

### 6. Edge case: permissive mode keeps undefined roles

```text
External roles mapped
        |
        v
Mapped roles include undefined local role names
        |
        +--> strict_permissions = false
               -> role names survive user construction
               -> local permission matrix may still have no grants for them
```

This usually creates confusing “login succeeded but access is weird” incidents rather than outright privilege escalation.

### 7. Edge case: fallback role is too broad

```text
No mapped roles
    |
    +--> auth_user_registration = true
    +--> auth_user_registration_role = Admin / Op / broad Public
            |
            v
Unintended baseline access granted after otherwise empty mapping
```

This is the highest-risk configuration pattern in the provided design.

### 8. Edge case: already-authenticated user is de-provisioned upstream

```text
User logs in
    |
    +--> JWT issued with resolved roles
    |
User removed from ITIM/Entra group later
    |
    +--> existing JWT may still work until expiry or logout
```

This is normal token behavior, but it matters in environments that expect immediate revocation.

### 9. Functional plugin scenario catalog

```text
+----+ Scenario family                    + Trigger / setup                               + Expected behavior                           +
| 01 | Startup: valid LDAP only           | LDAP enabled, config valid                    | manager starts ready, methods=['ldap']      |
| 02 | Startup: valid Entra only          | Entra enabled, config valid                   | manager starts ready, methods=['entra_id']  |
| 03 | Startup: both providers valid      | LDAP + Entra valid                            | login page offers both methods              |
| 04 | Startup: neither provider usable   | both invalid/disabled                         | manager degraded/unavailable                 |
| 05 | LDAP browser success               | valid credentials + mapped role               | JWT cookie issued, redirect success         |
| 06 | LDAP browser bad credentials       | invalid password                              | login failure, no JWT                       |
| 07 | LDAP CSRF mismatch                 | stale/invalid CSRF token                      | safe failure, no auth                       |
| 08 | LDAP throttling                    | repeated failed attempts                      | throttled/lockout status                    |
| 09 | Entra start success                | valid provider + start allowed                | state stored, redirect to Microsoft         |
| 10 | Entra callback success             | valid callback + mapped role                  | JWT cookie issued, redirect success         |
| 11 | Entra callback state failure       | state/nonce/PKCE mismatch                     | SSO failure path                            |
| 12 | API token success                  | valid LDAP credentials                        | access_token returned                       |
| 13 | API token failure                  | invalid LDAP credentials                      | token not issued                            |
| 14 | Role mapping success               | external value matches configured role        | authenticated user with mapped roles        |
| 15 | Role mapping empty                 | auth succeeds, no role mapped                 | fallback or denial                          |
| 16 | Role dropped in strict mode        | mapped role undefined locally                 | role dropped, audit event                   |
| 17 | Fallback registration success      | empty mapping + valid fallback role           | authenticated with fallback role            |
| 18 | Fallback registration denied       | empty mapping + fallback disabled/invalid     | unauthorized-style denial                   |
| 19 | Authorization allow                | role grants resource/action                   | request allowed                             |
| 20 | Authorization deny                 | role lacks resource/action                    | request denied                              |
| 21 | Role filter active                 | matching DAG tags/env/resource prefix         | filtered role remains active                |
| 22 | Role filter non-match              | context supplied but filter does not match    | role ignored for that request               |
| 23 | Config reload success              | file changed, valid parse                     | providers/policy refreshed                  |
| 24 | Config reload failure after start  | invalid changed file                          | last-known-good config kept                 |
| 25 | Logout                             | explicit logout                               | cookies cleared, logged_out status          |
| 26 | Session expiry                     | JWT/cookie expired                            | expired status, reauthentication needed     |
| 27 | Multi-worker SSO with cookie state | non-shared auth-state backend                 | intermittent callback risk                  |
| 28 | Multi-worker Redis state           | shared backend configured                     | resilient SSO state handling                |
| 29 | Public role minimal fallback       | fallback=Public, minimal permissions          | low-privilege bootstrap only                |
| 30 | Public role overly broad fallback  | fallback=Public, broad permissions            | unintended access risk                      |
+----+------------------------------------+-----------------------------------------------+---------------------------------------------+
```

### 10. Scenario mini-matrices for the two most important edge cases

#### A. User has only ITIM `User` in the shipped sample

```text
+--------------------+------------------+------------------------+----------------------------------------------+
| strict_permissions | deny_if_no_roles | auth_user_registration | Outcome                                      |
+--------------------+------------------+------------------------+----------------------------------------------+
| true               | true             | false                  | denied                                       |
| true               | false            | false                  | denied                                       |
| false              | true             | false                  | denied                                       |
| false              | false            | false                  | denied                                       |
| true               | true             | true                   | fallback to Public                           |
| true               | false            | true                   | fallback to Public                           |
| false              | true             | true                   | fallback to Public                           |
| false              | false            | true                   | fallback to Public                           |
+--------------------+------------------+------------------------+----------------------------------------------+
```

#### B. User has no ITIM roles in the shipped sample

```text
+--------------------+------------------+------------------------+----------------------------------------------+
| strict_permissions | deny_if_no_roles | auth_user_registration | Outcome                                      |
+--------------------+------------------+------------------------+----------------------------------------------+
| true               | true             | false                  | denied                                       |
| true               | false            | false                  | denied                                       |
| false              | true             | false                  | denied                                       |
| false              | false            | false                  | denied                                       |
| true               | true             | true                   | fallback to Public                           |
| true               | false            | true                   | fallback to Public                           |
| false              | true             | true                   | fallback to Public                           |
| false              | false            | true                   | fallback to Public                           |
+--------------------+------------------+------------------------+----------------------------------------------+
```

### 11. Test strategy mental model

```text
For each deployment, verify at least:
    |
    +--> provider readiness
    +--> valid login path
    +--> invalid login path
    +--> empty-role path
    +--> fallback path
    +--> strict role-drop path
    +--> token issuance path
    +--> logout / expiry path
    +--> multi-worker state behavior if SSO is enabled
    +--> config reload success + failure behavior
```

A deployment that tests only “successful login” is not fully validating this plugin. The edge-case paths are where most security and operability issues surface.

---

## Performance and scalability

The current core plugin performance posture is shaped by three important design choices.

First, the import-facing boundary remains thin. Airflow imports a lightweight facade, while heavier provider, UI, and compatibility work is deferred to the composed runtime. That reduces plugin discovery cost and keeps import-time failure surfaces smaller.

Second, hot reload is throttled by `general.config_reload_seconds` and backed by last-known-good config semantics. That avoids reparsing the policy file on every code path while still making runtime configuration operationally adjustable. In plugin, security-sensitive reloads can also invalidate previously issued sessions on their next request through the `authz_epoch` revocation model, which is a safer operational compromise than waiting for long JWT expiry windows.

Third, the code is already structured for horizontal safety: auth-state storage, rate-limit state, and session-revocation state each have backend abstraction points, so single-process memory backends can be used for development while Redis-backed deployments can be used for multi-worker production.

### What plugin does well

#### Import-time restraint

The root package and Airflow compatibility layer use lazy imports to reduce startup side effects.

#### Compiled permission cache

`PermissionMatrix` caches compiled multi-role permission sets, which helps repeated checks during a request.

#### Reload throttling

`ConfigLoader` does not re-parse the file on every call. It checks based on `config_reload_seconds` and file `mtime`.

#### Last-known-good behavior

This is operationally more important than raw speed. It reduces cascading failures from transient config issues.

#### Optional Redis backends

Both rate-limit state and Entra transient auth-state can be moved to Redis for multi-worker resilience.

### What operators should keep in mind

- `memory` and `cookie` backends are simpler but less suitable for horizontally scaled or multi-worker SSO-heavy deployments.
- OAuth callback state is more sensitive to worker topology than plain LDAP login.
- Very broad role definitions increase the amount of permission expansion logged in debug mode.

---

## Comparison with the official FAB auth manager

### Context

The official FAB auth manager is the currently documented Airflow path for FAB-based user management. It is DB-backed and intended to preserve a backward-compatible user-management experience, while Airflow 3 itself defaults to the Simple auth manager unless FAB is explicitly installed and configured.

### Comparison matrix

| Dimension | Official FAB auth manager | plugin alternative plugin |
|---|---|---|
| Main identity source | Airflow/FAB DB-managed users and roles | external LDAP and Entra identities |
| Airflow 3 integration style | official provider auth manager | custom auth manager implementing Airflow’s pluggable interface |
| Browser auth | password auth by default; generic OAuth2/SSO patterns documented | LDAP form login and Entra browser SSO built directly into the plugin |
| Public API tokens | official token flow | supported via `/auth/token` and `/auth/token/cli`, LDAP credential based |
| Role source of truth | DB/FAB entities | `permissions.ini` + external group/claim mapping |
| Runtime config changes | normal provider/config workflows | hot-reloadable INI with last-known-good fallback |
| Role scoping by DAG tags/environments | not a core built-in concept in the official docs | optional `role_filters:<role>` sections |
| Enterprise login UX | official Airflow/FAB experience | custom status-rich login page with environment/support metadata |
| Built-in operator advisories | standard docs and logs | config advisories, version policy, compatibility doctor |
| Dependency on local role admin | higher | lower for day-to-day onboarding, because mapping is externalized |
| Best fit | standard Airflow/FAB administration patterns | enterprise external-ID + Git-managed policy patterns |

### Why choose this plugin

Choose plugin when your operating model is closer to:

- enterprise directory-driven access,
- Git-reviewed RBAC policy,
- lower dependence on manual local user admin,
- need for richer auth diagnostics and safer config reload behavior,
- desire to keep auth policy portable across environments.

### Why stay with the official FAB auth manager

Stay with the official FAB path when your priority is:

- strict adherence to the stock Airflow/FAB administration model,
- local UI/DB-centric user and role management,
- minimal custom auth logic,
- smaller divergence from upstream behavior.

### Trade-offs introduced by plugin

#### Advantages

- clearer separation of concerns,
- stronger fit for external identity governance,
- better operational visibility,
- deterministic file-based RBAC,
- richer login and troubleshooting surface.

#### Costs

- more moving parts than a simple stock setup,
- additional config surface area,
- more responsibility on maintainers to keep compatibility boundaries tested,
- enterprise-safe deployment requires understanding proxies, Redis options, and external identity semantics.

---

## Operational checklist

### Minimum LDAP-only deployment

- configure `[core] auth_manager`,
- provide a valid `permissions.ini`,
- set `enable_ldap=true`,
- set required LDAP values: URI, `username_dn_format`, `search_base`,
- define `[role:*]` sections,
- define `[role_mapping]`,
- keep `strict_permissions=true`,
- validate login UI and `/auth/token`.

### Minimum Entra deployment

- set `enable_entra_id=true`,
- provide tenant/client/secret,
- register callback URI: `/auth/oauth-authorized/azure`,
- set `general.trusted_proxies` correctly if behind a reverse proxy,
- decide on `auth_state_backend`,
- use Redis for enterprise multi-worker setups,
- define `[entra_role_mapping]`,
- validate callback flow and mapped roles.

### Recommended production hardening

- `allow_plaintext_secrets=false`
- `strict_permissions=true`
- `deny_if_no_roles=true`
- explicit `trusted_proxies`
- Redis-backed rate limit and auth state for multi-worker deployments
- HMAC integrity enabled for `permissions.ini`
- `cookie_secure=auto` or explicit secure deployment policy
- monitored audit log ingestion

---

## Troubleshooting

### Symptom: login page says authentication unavailable

Most likely causes:

- both providers are disabled,
- LDAP enabled but required keys are missing,
- Entra enabled but tenant/client/secret/scope/roles-claim config is invalid,
- optional provider dependencies failed to load.

Check:

- startup logs,
- config advisories,
- runtime capability report,
- whether the manager is in degraded mode.

### Symptom: valid LDAP credentials but access denied

Likely causes:

- LDAP authentication succeeded but no group mapped to a defined role,
- `strict_permissions=true` dropped undefined mapped roles,
- `deny_if_no_roles=true` denied fallback access.

Check:

- `auth.role_mapping.empty` audit event,
- `auth.role_mapping.dropped` audit event,
- `[role_mapping]` and `[role:*]` alignment.

### Symptom: Entra callback fails intermittently in multi-worker deployment

Likely causes:

- `auth_state_backend=cookie` or `memory` in a multi-worker topology,
- missing or incorrect `trusted_proxies`,
- callback host/scheme reconstruction mismatch.

Check:

- advisory for non-shared auth-state backend,
- proxy headers,
- callback diagnostic endpoint,
- Redis-backed auth state.

### Symptom: throttling looks inconsistent across workers

Likely cause:

- `rate_limit_backend=memory` with multiple workers.

Move to Redis.

### Symptom: login success, then bad redirect

Likely causes:

- unsafe or cross-origin `next` URL,
- forwarded host/proto not trusted,
- reverse proxy not included in `trusted_proxies`.

Check redirect sanitization behavior and proxy config.

---

## Known limits and explicit non-goals

The following are deliberate observations from plugin, not guesses:

- no custom DB manager is registered,
- no custom legacy Flask API endpoints are registered,
- no extra menu items are added,
- no extra Airflow CLI commands are exposed,
- token issuance is LDAP credential based rather than Entra browser-token based,
- SAML support is not evidenced in the inspected plugin source,
- the plugin assumes maintainers are comfortable owning a custom auth-manager boundary instead of staying fully on the stock FAB path.

---


## Glossary and vocabulary

This glossary defines the main terms used across the codebase and this README. The goal is to make the design readable for operators, maintainers, and contributors without assuming prior familiarity with every internal term.

| Term | Meaning in this plugin |
|---|---|
| **Airflow auth manager** | The pluggable authentication and authorization component selected through `[core] auth_manager` in Airflow 3.x. |
| **Facade** | A thin public entrypoint that exposes a stable import path while delegating real logic elsewhere. |
| **Composition root** | The place where the application graph is assembled. In plugin this is `entrypoints/auth_manager.py`. |
| **Provider** | A module that performs a specific authentication method, such as LDAP or Entra ID. |
| **External identity** | A normalized representation of a successfully authenticated upstream principal before final Airflow roles are assigned. |
| **Identity mapper** | The logic that converts provider outputs, such as LDAP groups or Entra claims, into internal Airflow role assignments. |
| **Role mapping** | The transformation from external group/claim values into named Airflow roles defined in `permissions.ini`. |
| **Strict permissions** | A mode where mapped roles that are not defined locally in `[role:*]` sections are dropped before the user is finalized. |
| **Fallback registration** | The behavior controlled by `auth_user_registration` and `auth_user_registration_role`, where an otherwise empty role mapping can still produce a user with a baseline role. |
| **Usable role** | A role that survives mapping and local validation strongly enough to participate in authorization. |
| **RBAC** | Role-based access control. In this plugin it is file-driven and evaluated by the internal policy engine rather than by ad hoc UI edits. |
| **Permission matrix** | The compiled set of effective permissions for one or more active roles. |
| **RbacPolicy** | The core authorization evaluator that decides whether an action on a resource is allowed. |
| **Vocabulary** | The normalized internal names for actions and resources, used so different upstream inputs can be compared consistently. |
| **Resource contract** | A rule or expectation for what a given role should imply for a given Airflow/FAB surface. |
| **Role filter** | A conditional constraint that keeps a role active only when runtime context, such as DAG tags or environments, matches configured criteria. |
| **Authorization context** | Extra request-time metadata used to refine access checks, such as DAG tags, environment labels, or a resource identifier. |
| **JWT** | The signed token used to represent an authenticated user after login for browser or API access. |
| **JWT cookie** | The browser cookie carrying authenticated session state derived from the issued JWT. |
| **Auth state backend** | The temporary storage backend used for Entra/OAuth browser flow state, such as cookie, memory, or Redis. |
| **Rate limiter backend** | The backend that stores authentication throttling state, either in-process or Redis-backed. |
| **PKCE** | Proof Key for Code Exchange. Used to harden OAuth browser flows against interception and code substitution. |
| **SameSite** | Browser cookie policy that constrains when cookies are sent across request contexts. |
| **Trusted proxies** | CIDR/IP values that determine whether forwarded headers are trusted for redirect and callback reconstruction. |
| **Last-known-good config** | The most recent successfully parsed configuration, preserved so a bad reload does not immediately break a running healthy auth layer. |
| **Advisory** | A non-fatal operator-facing warning about risky, inconsistent, or suboptimal configuration. |
| **Capability report** | A runtime-generated summary of what this plugin instance can currently do and which backends/providers are active. |
| **Version policy** | The plugin’s internal statement of tested or recommended Airflow, FAB, and Python baselines. |
| **Compatibility doctor** | The operator-facing diagnostic output that compares actual runtime posture with intended compatibility and RBAC expectations. |
| **Degraded mode** | A state where the plugin stays loaded but cannot fully operate because provider or config validation failed. |
| **Happy path** | The normal successful execution path from provider authentication through mapping to authorization. |
| **Edge case** | A non-default operational branch such as empty mapping, strict role drops, throttling, invalid callback state, or reload failure. |
| **Public role** | The fallback or minimal baseline role often used for low-privilege entry; its exact risk depends on what permissions are attached to `[role:Public]`. |
| **ITIM** | The external identity governance source referenced in the user’s deployment model; in this README it represents upstream enterprise group assignment feeding LDAP-based mapping. |
| **Entra** | Microsoft Entra ID, used here as the OAuth/OIDC-based SSO provider. |
| **Operator** | A deployment owner or support engineer responsible for running, diagnosing, and securing the plugin in production. |
| **Maintainer** | A developer responsible for evolving the plugin codebase, compatibility boundaries, and tests. |

### Quick terminology shortcuts used in the flows

```text
authentication
    -> proving who the user is

mapping
    -> converting external identity data into Airflow roles

authorization
    -> deciding what the authenticated user may do

fallback
    -> converting empty mapping into baseline access

strict mode
    -> dropping undefined mapped roles

steady state
    -> behavior after login, during normal authenticated requests
```


## FAQ

### Why was this plugin created instead of using only the official FAB auth manager?
This plugin is designed for environments where external identity systems are the true source of user access and where RBAC policy should be reviewable in Git. The design favors directory-driven onboarding, deterministic file-based permissions, richer diagnostics, and more explicit runtime security controls.

### Is this plugin intended to replace the official FAB auth manager everywhere?
No. It is an alternative for organizations whose operating model fits external identity mapping better than DB-centric local user administration. Teams that want the stock Airflow/FAB workflow may still prefer the official provider path.

### Does the plugin manage users mainly in the Airflow database?
No. The inspected plugin design centers on upstream identity plus file-driven role definitions and mappings. That is one of the main architectural differences from the traditional FAB model.

### Does successful LDAP or Entra authentication automatically mean Airflow access?
No. Upstream authentication proves identity, but Airflow access is only granted if usable internal roles remain after mapping and security filtering, or if fallback registration is explicitly enabled and valid.

### What is the single most security-sensitive part of the flow?
Role survival after mapping. That is where `strict_permissions`, local `[role:*]` definitions, and fallback registration combine to decide whether the user becomes an authenticated Airflow user at all.

### Is `deny_if_no_roles` a hard enforcement switch in the provided plugin files?
Not by itself. In the inspected plugin implementation it is present in config and appears in audit payloads, but it is not used as a distinct enforcement branch after mapping. The effective outcome is driven mainly by `strict_permissions`, `auth_user_registration`, and whether the fallback role exists locally.

### Can a user with no ITIM roles receive Admin access?
Not in the shipped sample if fallback is `Public` and `Public` remains minimal. But it becomes dangerous if `auth_user_registration_role` is changed to `Admin`, `Op`, or another broad role, or if `Public` is expanded too far.

### Can a user with only ITIM `User` receive Admin access?
Not in the shipped sample, because the `User` mapping line is commented and the fallback role is minimal `Public`. The risk changes only if mapping or fallback configuration is broadened.

### Why does the README talk so much about `Public`?
Because in this design the biggest accidental-access risk is not the happy path for correctly mapped users; it is what happens when mapping is empty and fallback registration still grants baseline access. The breadth of `Public` therefore becomes a real security boundary.

### What happens after the user is already authenticated?
The user is rebuilt from JWT claims on later requests and authorization is evaluated from the roles embedded in that authenticated context. The login-time switches are not re-evaluated from scratch on every request.

### Does upstream de-provisioning immediately revoke an already issued token?
Not necessarily. In the inspected plugin design, a valid JWT may remain usable until expiry or logout. Shorter token lifetimes matter if rapid de-provisioning is important.

### Why are Redis-backed backends recommended for enterprise multi-worker SSO?
Because transient OAuth state and throttling state must be consistently visible across workers. Cookie-only or process-local memory backends are simpler, but they are weaker in horizontally scaled or multi-worker deployments.

### Why is the login page treated as part of operations?
Because the plugin uses the UI to communicate actual runtime state: readiness, method availability, throttling, empty-role outcomes, reference IDs, and success/failure context. That makes support and incident triage easier.

### Is this plugin only for LDAP?
No. The plugin design supports LDAP username/password login and Entra browser SSO. It also supports LDAP-backed token issuance for API and CLI flows.

### Does plugin show evidence of SAML support?
No. The inspected plugin source does not show evidence of SAML support.

### Is `strict_permissions=true` always the best choice?
It is usually the safest enterprise default because it prevents undefined local roles from quietly surviving mapping. The trade-off is that config drift or typos can deny access more aggressively, so disciplined configuration management matters.

### When should `auth_user_registration=true` be used?
Only when the organization explicitly wants fallback behavior for otherwise unmapped users and has intentionally chosen a low-risk fallback role. It should not be treated as a harmless convenience toggle.

### What is the best secure baseline for production?
A strong baseline for the inspected plugin design is:
- `strict_permissions=true`
- `auth_user_registration=false`
- minimal `[role:Public]`
- `sensitive_debug_logging=false`
- short JWT lifetimes if fast de-provisioning matters
- Redis-backed shared state for multi-worker SSO deployments


## Contributing and repository collaboration

Contributions are welcome in this repository along with advancing this plugin as fully future proven solution for new Airflow versions
e.g.
- compatibility verification across future Airflow and FAB lines,
- tests for edge cases and degraded-mode behavior,
- provider hardening and diagnostics,
- documentation improvements,
- additional operational examples and CI validation.
- other auth methods
- plugin produced logs more debug/SIEM friendly and its future features / enhancements


## References

### Official Apache Airflow references

- [Auth manager — Airflow stable docs](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/auth-manager/index.html)
- [Simple auth manager — Airflow stable docs](https://airflow.apache.org/docs/apache-airflow/stable/core-concepts/auth-manager/simple/index.html)
- [Airflow 3 release notes](https://airflow.apache.org/docs/apache-airflow/stable/release_notes.html)
- [Upgrading to Airflow 3](https://airflow.apache.org/docs/apache-airflow/stable/installation/upgrading_to_airflow3.html)

### Official FAB auth-manager references

- [FAB provider package docs](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/index.html)
- [FAB auth manager overview](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/index.html)
- [FAB webserver authentication](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/webserver-authentication.html)
- [FAB API authentication](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/api-authentication.html)
- [FAB token generation](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/token.html)
- [FAB SSO integration](https://airflow.apache.org/docs/apache-airflow-providers-fab/stable/auth-manager/sso.html)

Where comparisons mention the official FAB auth manager, those points are based on the current Apache Airflow documentation linked above rather than assumption.

---

## GitHub topics and tags

<p align="left">
  <img src="https://img.shields.io/badge/topic-apache--airflow-017CEE?style=flat-square" alt="apache-airflow">
  <img src="https://img.shields.io/badge/topic-auth--manager-1F6FEB?style=flat-square" alt="auth-manager">
  <img src="https://img.shields.io/badge/topic-rbac-6F42C1?style=flat-square" alt="rbac">
  <img src="https://img.shields.io/badge/topic-ldap-2E8B57?style=flat-square" alt="ldap">
  <img src="https://img.shields.io/badge/topic-entra--id-0078D4?style=flat-square" alt="entra-id">
  <img src="https://img.shields.io/badge/topic-oidc-0F766E?style=flat-square" alt="oidc">
  <img src="https://img.shields.io/badge/topic-jwt-BB2A2A?style=flat-square" alt="jwt">
  <img src="https://img.shields.io/badge/topic-fastapi-009688?style=flat-square" alt="fastapi">
  <img src="https://img.shields.io/badge/topic-enterprise--security-4B5563?style=flat-square" alt="enterprise-security">
  <img src="https://img.shields.io/badge/topic-permissions.ini-FF8C00?style=flat-square" alt="permissions.ini">
  <img src="https://img.shields.io/badge/topic-hot--reload-D97706?style=flat-square" alt="hot-reload">
  <img src="https://img.shields.io/badge/topic-airflow--plugin-2563EB?style=flat-square" alt="airflow-plugin">
</p>

