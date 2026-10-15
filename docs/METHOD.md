# TenantScope: method and limits

## Policy and execution

Users have a tenant, active status, and member/admin/worker role. Document owners and same-tenant admins manage content and grants. Active same-tenant share recipients may read. Transfer changes ownership/tenant and clears grants; account disablement takes effect immediately. Exports must be reauthorized at execution using current content. Worker execution is a distinct operation.

`model.py` implements this policy in memory. `target.py` uses parameterized SQLite queries and independently written enforcement. A fresh temporary database is used for every run and removed afterward. The report includes logical final states and failure responses; it does not include the raw database or an external service trace. State divergence can produce subsequent failures after the initial defect; the minimizer preserves a specific first-failure fingerprint rather than assuming every row is an independent vulnerability.

## Input

Top-level fields are `mode` (`seeded` or `repaired`) and `scenario`. Scenario fields: `name`, `users` (1–32), `documents` (1–64), and `steps` (1–200). Users require `id`/`tenant` and may set `role`. Documents require `id`/`owner`/`content` (up to 4000 characters).

Steps require `actor` and `op`. Operations: `read`, `attachment`, `share`, `revoke`, `transfer`, `delete_document`, `update`, `delete_account`, `queue_export`, and `run_export`. Document operations specify `document`; share/revoke/transfer/delete_account specify `target`; update specifies `content`; queue_export/run_export specify `job`. See the complete runnable fixtures in `examples/`.

## Minimization and scope

The greedy reducer repeatedly tries deleting one step while preserving actor, operation, document, job, and failure reason. It performs at most 80 evaluations and reports whether its search budget was exhausted. This is not a globally shortest-witness proof. The independent oracle can still contain specification mistakes: add explicit policy expectations and review both implementations when extending it. Concurrent transactions, real authentication/session issuance, distributed queues, race scheduling, and external adapters are not implemented.
