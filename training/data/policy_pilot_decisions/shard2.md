# Blind pilot shard 2 direct evidence review

All 33 assigned records read individually, including recovered facts, effective security, and inferred schema. No prior labels read; no model API, network, or local-model execution. Confidence is subjective; all proposals await human review. Serialization below only records explicit authored decisions, not a rule classifier.

| pilot index | label | rationale |
|---:|---|---|
| 2 | manual_review_required | Azure identity-token authentication bootstrap is described, but its host eligibility conditions are external; anonymous security alone does not establish unrestricted access. |
| 5 | manual_review_required | Anonymization under an admin route suggests privilege, but the recovered summary never states an authorized role. |
| 8 | manual_review_required | The operation navigates a user favorites list; it does not say caller must own the list or that every list is public. |
| 11 | manual_review_required | Group pool photo navigation has no recovered visibility or caller authorization rule; group identity is not subscription evidence. |
| 14 | manual_review_required | Hook update has an admin path, but admin privilege prose applies only to optional Sudo authentication alternatives, not universally to this operation. |
| 17 | public | Both operation and response explicitly identify the returned character information as public. |
| 20 | role_required | The operation explicitly authorizes admins and editors to list device tags. |
| 23 | owner_match | The recipe retrieval explicitly returns 403 when someone else owns the recipe, establishing caller ownership independently of physical lookup availability. |
| 26 | manual_review_required | Crash-group listing has owner_name routing and API-token authentication but no rule equating that owner with the caller. |
| 29 | manual_review_required | Adding customers to categories specifies OAuth credentials and identifiers, but no caller role, customer ownership, or tenant restriction. |
| 32 | manual_review_required | Test mutation requires OAuth write permission; the scope does not establish a role or owner relationship for the selected test. |
| 35 | manual_review_required | Only a success description was recovered; author response fields do not prove who can modify the comment. |
| 38 | manual_review_required | Import behavior and overwrite semantics are documented, but caller authorization to the selected version is not. |
| 41 | manual_review_required | Player statistics and filters are described with API-key authentication; neither public authorization nor subscription tier is stated. |
| 44 | manual_review_required | Server tenant ownership is a response attribute; neither that attribute nor impersonation scope states caller-tenant equality for this read. |
| 47 | manual_review_required | The payment route requires a bearer API key, but does not define which payments that key may access. |
| 50 | manual_review_required | Memberships here are sports roster records; a subscription-key header alone does not identify a required consumer tier. |
| 53 | manual_review_required | OAuth client-credentials and activity-write scope establish permission vocabulary, not an owner, tenant, or application-role rule for patching activities. |
| 56 | manual_review_required | User deletion and API-key setup are documented, but no self-only or administrative deletion requirement is stated. |
| 59 | manual_review_required | Administrative access is required for the returned admin URL, not explicitly for this project-information endpoint; creator and organization fields are descriptive. |
| 62 | manual_review_required | Japanese documentation identifies script-tag update and account ID; OAuth write permission does not establish caller-account equality. |
| 65 | manual_review_required | Account-role identifier and token authentication are present, but editing authorization is unspecified; manager booleans describe data. |
| 68 | manual_review_required | Address attachment identifies its customer and ignores body IDs, but does not require that the caller be that customer or tenant. |
| 71 | manual_review_required | User connection logs accept me or all; the documentation does not define who may select another user or all users. |
| 74 | manual_review_required | The operation combines account-admin/account-owner permission with Pro-or-higher eligibility and setting-specific plan restrictions; one of seven labels would discard a material conjunct. |
| 77 | manual_review_required | Competitor data requires an API key; premium in the path is not an explicit subscription-tier requirement. |
| 80 | manual_review_required | The bulk-annotation description explains resource identifiers and upload format, but no caller repository privilege or workspace relationship. |
| 83 | tenant_match | Application listing is explicitly within the requesting account, and AccountSid identifies the account that created those resources; this supports account-boundary matching without inventing DB mappings. |
| 86 | manual_review_required | A forbidden response states provider eligibility is checked, but the eligibility condition is not specified as ownership, tenant equality, role, or subscription. |
| 89 | manual_review_required | The collaborator OAuth scope and blue-access description do not define an application role or relation between caller and business group. |
| 92 | manual_review_required | JWT authentication and generic forbidden errors do not establish which app-localization records the caller may read. |
| 95 | manual_review_required | Mark-unread behavior and generic unauthorized/forbidden responses provide no ownership or other concrete authorization condition. |
| 98 | manual_review_required | Available-for-you rate plans imply entitlement filtering, but ownership or tenant matching is not stated; closed-user-group rates are examples of product conditions, not a universal endpoint membership requirement. |
