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

Follow the DRY principle: do not duplicate information or code across files.

If instructions conflict, repository config and CI workflows win first, official docs next, and this file is supplemental.

## Development Notes

- Preserve public APIs, migrations, swappable models, FreeRADIUS schema behavior, private storage behavior, and integration points unless explicitly required.
- Mark user-facing strings for translation with Django i18n helpers in Django code.
- Place imports at the top of the file. Only defer imports when necessary (e.g., Django model imports inside functions or methods where the app registry is not yet ready).
- Avoid unnecessary blank lines inside function and method bodies.
- Update docs when behavior, settings, public APIs, setup steps, or supported versions change.

## Testing and QA

- For bug fixes, write the regression test first, run it against the unfixed code, confirm it fails for the expected reason, then implement the fix.
- Prefer method decorators for context managers that apply to the entire test method and would otherwise create unnecessary nesting, unless decorator ordering conflicts or the context manager requires data unavailable when the method is defined.
- Use targeted tests while iterating, then run the documented full test command before considering the change complete.
- Run `openwisp-qa-format` after editing when available.
- Run `./run-qa-checks` when present. Treat failures as blocking unless confirmed unrelated and reported.
- Prefer in-process tests so coverage tools can measure changed code.

## Django Notes

- Preserve tenant isolation and object-level permissions for organizations, users, RADIUS groups, accounting, payments, and captive portal data.
- Be careful with authentication, authorization, queryset filtering, serializers, registration flows, social/SAML flows, SMS verification, imports, counters, Celery tasks, and signals.
- When changing APIs, include tests for permissions, validation, filtering, pagination, and tenant boundaries.
- Changes to swappable models, tenant isolation, authentication flows, or admin/REST authorization must be covered by both the default package suite and the `SAMPLE_APP=1` integration suite. Add a `tests/openwisp2` regression test when the affected feature has no existing sample-app analogue.
- When a Celery task, notification, cache invalidation, or other external side effect depends on database changes made in the current transaction, register it with `transaction.on_commit()` so it cannot run against uncommitted or rolled-back data. Do not defer work that must run before commit or is independent of the transaction. Test commit and rollback behavior, and account for Celery eager execution in tests versus asynchronous execution in production.

## Security Notes

- Watch for cross-tenant data leaks, permission bypasses, insecure credentials, unsafe redirects, unsafe file paths, token/session issues, and secrets.
- Preserve validation around RADIUS credentials, accounting data, CSV imports, private storage, SAML/social login payloads, notification payloads, and URLs.
- Write comments and docstrings only when they explain why code is shaped a certain way. Put comments before the relevant code block instead of scattering them inside it.

## Troubleshooting

- If setup, QA, or tests fail, check docs first, then compare with CI. If commands diverge, follow CI.

## Contributing Guidelines

- Before editing, inspect the relevant implementation, tests, documentation, and configuration. Follow existing repository patterns and do not invent behavior or requirements.
- Keep each contribution focused and change only the lines necessary for its goal. Do not include unrelated refactors, formatting churn, or generated and dependency-file changes unless explicitly required.
- Add or update focused tests for every behavior change. In repositories without a dedicated automated test suite, use the documented build and QA workflow as the equivalent behavior verification. For bug fixes, first reproduce the failure with a regression test when the repository's test setup allows it.
- Run the relevant targeted tests, builds, and documented QA checks, including `./run-qa-checks` when provided. Do not claim a change is complete when verification fails; report the failure or blocker.
- When requirements, intended behavior, or an unexpected failure are unclear, stop and seek clarification instead of making speculative changes.
- When starting work on a new issue, create a new branch from `master`. Use `issues/<issue-number>-<short-title>` for issue work; otherwise, use a short, descriptive branch name.
- Commit messages must be descriptive and use past tense. Past tense is a writing guideline that agents and contributors must follow; it is not checked automatically. For issue work, use an allowed prefix and a capitalized, past-tense subject ending with `#<issue-number>`, for example `[fix] Fixed perennial "modified" state #213`. Repeat the issue reference in the body with `Fixes`, `Closes`, `Resolves`, or `Related to` as appropriate. Use `openwisp-commit --check` to validate the structural commit convention and `cz -n cz_openwisp info` to view the allowed prefixes and message structure. If the repository's declared QA dependency predates these commands, install the development version with `pip install --upgrade "openwisp-utils[qa] @ https://github.com/openwisp/openwisp-utils/archive/refs/heads/master.tar.gz"` in the development environment.
- Add an explanatory commit body only for substantial changes, new features, or non-obvious bug fixes. The releaser automatically publishes the subject of `[feature]`, `[change]`, `[change!]`, `[deps]`, and `[fix]` commits, including scoped variants, in the changelog. Write those subjects in clear, user-friendly language suitable for release notes.
- Send new commits in response to review feedback instead of amending existing commits.
