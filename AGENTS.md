# AGENTS.md

## Project Overview

`openwisp-radius` is the OpenWISP Django app for managing FreeRADIUS data, captive portal registration, accounting, social/SAML login, and related APIs.

Core code lives in `openwisp_radius/`:

- `base/` contains abstract models and core RADIUS behavior.
- `api/`, `registration.py`, `social/`, `saml/`, `counters/`, `radclient/`, and `integrations/` implement API, auth, captive portal, accounting, and integration behavior.
- `tasks.py`, `signals.py`, `receivers.py`, `private_storage/`, `templates/`, and `static/` provide background jobs, hooks, protected files, and UI.
- Tests live in `openwisp_radius/tests/` and `tests/`.

## Source of Truth

- Use `docs/developer/installation.rst` and `docs/developer/index.rst` for local setup, services, and baseline test commands.
- Use `.github/workflows/ci.yml` for CI-tested dependencies, QA/test commands, env vars, and supported Python/Django versions.
- Use GitHub issue/PR templates when asked to open issues or PRs.

If instructions conflict, repository config and CI workflows win first, official docs next, and this file is supplemental.

## Development Notes

- Keep changes focused. Avoid unrelated refactors and formatting churn.
- Preserve public APIs, migrations, swappable models, FreeRADIUS schema behavior, private storage behavior, and integration points unless explicitly required.
- Mark user-facing strings for translation with Django i18n helpers in Django code.
- Avoid unnecessary blank lines inside function and method bodies.
- Update docs when behavior, settings, public APIs, setup steps, or supported versions change.

## Testing and QA

- Add or update tests for every behavior change.
- For bug fixes, write the regression test first, run it against the unfixed code, confirm it fails for the expected reason, then implement the fix.
- Use targeted tests while iterating, then run the documented full test command before considering the change complete.
- Run `openwisp-qa-format` after editing when available.
- Run `./run-qa-checks` when present. Treat failures as blocking unless confirmed unrelated and reported.
- Prefer in-process tests so coverage tools can measure changed code.

## Django Notes

- Preserve tenant isolation and object-level permissions for organizations, users, RADIUS groups, accounting, payments, and captive portal data.
- Be careful with authentication, authorization, queryset filtering, serializers, registration flows, social/SAML flows, SMS verification, imports, counters, Celery tasks, and signals.
- When changing APIs, include tests for permissions, validation, filtering, pagination, and tenant boundaries.

## Security Notes

- Watch for cross-tenant data leaks, permission bypasses, insecure credentials, unsafe redirects, unsafe file paths, token/session issues, and secrets.
- Preserve validation around RADIUS credentials, accounting data, CSV imports, private storage, SAML/social login payloads, notification payloads, and URLs.
- Write comments and docstrings only when they explain why code is shaped a certain way. Put comments before the relevant code block instead of scattering them inside it.

## Troubleshooting

- If setup, QA, or tests fail, check docs first, then compare with CI. If commands diverge, follow CI.
