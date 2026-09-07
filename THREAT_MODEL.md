# django-auditlog-v3 threat model

## Overview

A Django audit extension registers lifecycle, optional M2M and access signals; computes filtered changes; stores JSON audit entries and optional serialized model snapshots; and supplies contextual actor/correlation attribution and a restricted Django admin. Default persistence uses the LogEntry manager and host routing, not explicit routing to instance._state.db (auditlog/registry.py:61; auditlog/models.py:36; auditlog/models.py:77).

This snapshot packages a version 3 beta of django-auditlog. Registration, serialization, capture suppression and custom callbacks are trusted application choices. The extension can record explicit access events as well as changes, but neither kind of event proves that the caller authorized the operation. Middleware identity depends on the host authentication stack; database and log-reader policy depend on the host deployment.

| Component | Source |
| --- | --- |
| Signal registry and contextual capture | auditlog/registry.py:61; auditlog/context.py:15; auditlog/receivers.py:106 |
| Diffs, snapshots and persistence | auditlog/diff.py:108; auditlog/models.py:224 |
| Restricted admin and operator purge | auditlog/admin.py:38; auditlog/management/commands/auditlogflush.py:29 |
| Upstream-gated tag publication | .github/workflows/release.yml:3; .github/workflows/release.yml:48 |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Library embedded in Django | LogEntry manager | Registered model/access signal → LogEntry.objects.log_create → self.create → host router | Django default table auditlog_logentry, selected by host LogEntry manager/database routing | Database/admin/history readers and backups | Registry field/serialization options; Django permissions | auditlog/models.py:77; auditlog/models.py:383 |
| Library embedded in Django | Optional snapshot | register(serialize_data=False by default); explicit serialize_kwargs/serialize_auditlog_fields_only and mask_fields → Django serializer | LogEntry.serialized_data JSON; default disabled; enabled serialization fields controlled separately from changes | Same audit readers | Explicit serialization and mask options | auditlog/models.py:224; auditlog/registry.py:82 |
| GitHub Actions upstream release | Release upload | Tag push → upstream repository condition → dist build/check → upload action secret reference | https://jazzband.co/projects/django-auditlog/upload; secret reference JAZZBAND_RELEASE_KEY | Jazzband release service | Tag event, upstream repository gate, CI secret access | .github/workflows/release.yml:48 |
| Operator auditlogflush | History deletion | --yes or interactive y; optional --before-date → LogEntry manager queryset | All audit rows, or rows with timestamp date before supplied date, on host manager routing | Host audit database | Management command authority; prompt unless --yes | auditlog/management/commands/auditlogflush.py:29 |
| Operator auditlogmigratejson without --database | ORM JSON conversion | Pending-row check → default batch-size 500 (0 unbatched) → json.loads → bulk_update | Nonempty changes_text rows whose changes is NULL, on LogEntry manager routing; invalid JSON rows reported by ID | Audit database; operator stderr for invalid row IDs | Operator authority; pending-row filter and per-row JSON error handling | auditlog/management/commands/auditlogmigratejson.py:81; auditlog/management/commands/auditlogmigratejson.py:86 |
| Operator auditlogmigratejson --database postgres | Native JSON conversion | Pending-row existence check → selected engine → django.db.connection cursor | Full auditlog_logentry table on default connection: changes assigned changes_text cast to jsonb; no pending-row WHERE clause | Default-connection audit database | Operator DB authority; PostgreSQL conversion/transaction semantics; engine flag is not a DB alias | auditlog/management/commands/auditlogmigratejson.py:48; auditlog/management/commands/auditlogmigratejson.py:122 |

## Threat Model, Trust Boundaries, and Assumptions

**Protected assets.** JSON changes, optional serialized_data, object representation, additional_data, actor, remote_addr and correlation ID (auditlog/models.py:347; auditlog/models.py:362). Integrity and retention of audit history and release packages (auditlog/admin.py:38; .github/workflows/release.yml:42).

**Actors and starting authority.** A caller-facing user may influence captured data and headers without authority over settings, signal callbacks or database administration. A maintainer able to publish trusted source/tags occupies the package-supply boundary; CI secrets are not user-request inputs.

**Trust boundaries and owned controls.**

- Authenticated request.user is consumed, not authenticated by middleware. First X-Forwarded-For value determines remote address; correlation ID comes from configured request header or trusted callable/import path. ContextVar and signal dispatch IDs scope actor attribution (auditlog/middleware.py:17; auditlog/context.py:45; auditlog/cid.py:23; auditlog/cid.py:64).
- Registered models pass diffs into LogEntry.objects; pre_log callbacks can veto. check_disable gates create/update/delete and configured M2M handlers, while the access receiver lacks that decorator. Access signaling records access but does not grant access to an object (auditlog/receivers.py:11; auditlog/receivers.py:86; auditlog/receivers.py:106).
- serialize_data defaults false; enabling it invokes Django JSON serialization, optionally restricts to tracked fields, and masks only configured string fields. Diff masking replaces the first half of strings; additional_data/object_repr have separate consumers and require caller minimization (auditlog/registry.py:74; auditlog/models.py:224; auditlog/models.py:285; auditlog/diff.py:95).
- Admin forbids direct add/change/delete, with a cascade-delete exception; ORM and command access retain independent write authority. Host authentication, model visibility and history-reader authorization remain required (auditlog/admin.py:38).
- Tag release CI is gated to jazzband/django-auditlog, uses read-all permissions and sends built distributions to Jazzband using JAZZBAND_RELEASE_KEY. This copied workflow does not establish active release authority on another fork (.github/workflows/release.yml:3; .github/workflows/release.yml:8; .github/workflows/release.yml:48).
- Operator JSON conversion has separate consumers: the ORM path selects nonempty changes_text with changes NULL, parses JSON and bulk-updates in batches; --database selects an engine rather than a DB alias. If pending logs exist, native postgres uses django.db.connection to update the full auditlog_logentry table without the ORM selection predicate. mysql/oracle choices raise not implemented. Migration 0015 chooses direct field alteration or a two-step text/JSON split by AUDITLOG_TWO_STEP_MIGRATION (auditlog/management/commands/auditlogmigratejson.py:81; auditlog/management/commands/auditlogmigratejson.py:122; auditlog/migrations/0015_alter_logentry_changes.py:8).

**Security objectives.** Authorize historical data access independently from current-object access. Minimize each persisted channel and distinguish partial masking from complete removal. Keep actor context and correlation metadata distinct from access authorization; preserve intended capture and retention policies.

**Assumptions and unresolved controls.**

- Host routers determine effective database; concrete DB endpoint/credentials and app tenant model are absent.
- JSON migration and auditlogflush are operator workflows, not web APIs; auditlogflush permits --yes and optional before-date selection (auditlog/management/commands/auditlogflush.py:11).
- Host database routing, full read authorization, callback ownership, storage immutability and live publisher settings are unknown. JSON migration/flush behavior is an operator surface; no public command endpoint is established.

## Attack Surface, Mitigations, and Attacker Stories

These are prioritized hypotheses, not validated vulnerabilities. Each requires its stated caller, data and exposure prerequisites; ordinary use of authority already granted is not a new capability.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | An API/history reader receives sensitive old values or an optional complete snapshot beyond their object entitlement. | A host exposes LogEntry data without equivalent history authorization, or enables broader snapshot fields than intended. | Confidential historical model data disclosure. | Django admin permission framework, restricted admin mutations, explicit serialization opt-in and field options. | Authorize readers independently and review changes, snapshots, representation and additional_data separately. | auditlog/admin.py:38; auditlog/models.py:71; auditlog/models.py:224 |
| 2 | A partial mask is treated as full anonymization and the remaining value discloses useful sensitive information. | Configured masked fields contain data whose suffix is sensitive; a log reader lacks full-value entitlement. | Partial secret or personal-data exposure. | First-half string masking; optional field exclusion; snapshot masking only for strings. | Exclude values requiring full removal and document the actual masking contract. | auditlog/diff.py:95; auditlog/diff.py:186; auditlog/models.py:285 |
| 2 | A caller-supplied correlation ID/address is used as authority, or nested/concurrent integration misbinds actor context. | Downstream reliance on untrusted metadata, or demonstrated context misuse across real request/task paths. | Cross-request attribution or authorization errors in the integration. | Authenticated actor type check, ContextVar dispatch matching and context-managed signal disconnection. | Treat metadata as untrusted; preserve actor lifecycle and independently enforce access. | auditlog/middleware.py:17; auditlog/context.py:45; auditlog/cid.py:23 |
| 2 | A lower-trust change enters an approved release artifact or gains a publishing capability. | A real failure in tag/repository/build-secret controls; fork tag pushes alone do not satisfy the upstream repository gate. | Compromised downstream Python installations. | Pinned actions, read-all workflow permissions, repository condition and secret-backed Jazzband upload. | Protect release inputs and secret recipients; verify approved artifact provenance. | .github/workflows/release.yml:8; .github/workflows/release.yml:15; .github/workflows/release.yml:48 |
| 2 | An operator or automation expects native JSON conversion to affect only pending rows, but its actual consumer has broader selection. | Pending rows exist, postgres mode is chosen, and existing JSON/text states make the broader write materially different. | Unintended historical-data changes or conversion failure; actual DB semantics determine result. | Initial pending-row check; ORM path filters pending rows and handles invalid JSON individually. | Review exact target/selection and back up history; do not assume native and ORM migration equivalence. | auditlog/management/commands/auditlogmigratejson.py:48; auditlog/management/commands/auditlogmigratejson.py:81; auditlog/management/commands/auditlogmigratejson.py:122 |
| 3 | Capture veto/suppression or command deletion undermines a required immutable record. | The host grants those controls below the intended audit-administrator boundary. | Missing or deleted evidence. | Trusted pre_log callbacks; explicit suppression contexts; admin mutation restrictions and command confirmation/--yes. | Constrain capture configuration and deletion authority; define retention at storage level. | auditlog/receivers.py:11; auditlog/receivers.py:106; auditlog/management/commands/auditlogflush.py:11 |

## Severity Calibration (Critical, High, Medium, Low)

| Level | Repository-specific example | Counterexample or limiting prerequisite |
| --- | --- | --- |
| Critical | An established release compromise distributes executable code broadly, or a history endpoint exposes a demonstrably critical dataset. | Needs a lower-trust path across actual publication/data-access controls; maintainer intent is not an exploit. |
| High | An unauthorized user obtains another user’s confidential snapshot or sensitive historical values. | A partially masked value is not automatically high severity; its content and usefulness must be shown. |
| Medium | Attribution or retention failure materially breaks a supported security workflow. | Caller-chosen capture suppression and operator purge can be authorized behavior. |
| Low | Limited metadata leakage or local administrative inconvenience. | A correlation ID under user control is not an authenticated credential and is not itself a security defect. |

This model uses an independent source-backed architecture pass. Repository citations were checked against the supplied inventory and source lines; application code and external services were not executed. Source-established behavior is distinct from unverified deployment exposure. Revisit the model when the described input, storage, authorization or publication boundaries change.

Repository: github.com/mathspace/django-auditlog-v3
Version: 719b505afd54528eaa55a701e4fa523ec518350b
