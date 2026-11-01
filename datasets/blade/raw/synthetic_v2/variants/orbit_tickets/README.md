# orbit_tickets variants (data-v2)

Authorization-removed variants of the train-only fixture orbit_tickets (fastapi). authonly: in-handler authentication, authorization removed; extauth: authentication outside the handler (dependency/middleware/@PreAuthorize), no authorization; extguard: external authentication plus the original authorization check (control). authonly/extauth are manual_review_required by design. OpenAPI: original_export.
