"""Serialize individually authored blind-review decisions; not a classifier."""
import json
from pathlib import Path
from training.data.assemble_policy_pilot import validate

P=Path(__file__).parent
rows={r['pilot_index']:r for r in map(json.loads,(P/'blind_input.jsonl').read_text(encoding='utf-8').splitlines())}
# index, label, confidence, status, evidence strength, rationale, fact indexes, object param, roles
authored=[
(2,'manual_review_required',.55,'ambiguous','explicit','Azure identity-token authentication bootstrap is described, but its host eligibility conditions are external; anonymous security alone does not establish unrestricted access.',[1,8],None,[]),
(5,'manual_review_required',.42,'insufficient_evidence','heuristic_only','Anonymization under an admin route suggests privilege, but the recovered summary never states an authorized role.',[0],None,[]),
(8,'manual_review_required',.44,'insufficient_evidence','heuristic_only','The operation navigates a user favorites list; it does not say caller must own the list or that every list is public.',[0],None,[]),
(11,'manual_review_required',.44,'insufficient_evidence','heuristic_only','Group pool photo navigation has no recovered visibility or caller authorization rule; group identity is not subscription evidence.',[0],None,[]),
(14,'manual_review_required',.51,'insufficient_evidence','heuristic_only','Hook update has an admin path, but admin privilege prose applies only to optional Sudo authentication alternatives, not universally to this operation.',[0,6],None,[]),
(17,'public',.95,'supported','explicit','Both operation and response explicitly identify the returned character information as public.',[0,5],None,[]),
(20,'role_required',.98,'supported','explicit','The operation explicitly authorizes admins and editors to list device tags.',[1],None,['admin','editor']),
(23,'owner_match',.98,'supported','explicit','The recipe retrieval explicitly returns 403 when someone else owns the recipe, establishing caller ownership independently of physical lookup availability.',[0,1],'id',[]),
(26,'manual_review_required',.45,'insufficient_evidence','heuristic_only','Crash-group listing has owner_name routing and API-token authentication but no rule equating that owner with the caller.',[0,5],None,[]),
(29,'manual_review_required',.46,'insufficient_evidence','heuristic_only','Adding customers to categories specifies OAuth credentials and identifiers, but no caller role, customer ownership, or tenant restriction.',[0,1,2],None,[]),
(32,'manual_review_required',.52,'insufficient_evidence','heuristic_only','Test mutation requires OAuth write permission; the scope does not establish a role or owner relationship for the selected test.',[0,26],None,[]),
(35,'manual_review_required',.30,'insufficient_evidence','absent','Only a success description was recovered; author response fields do not prove who can modify the comment.',[0],None,[]),
(38,'manual_review_required',.44,'insufficient_evidence','heuristic_only','Import behavior and overwrite semantics are documented, but caller authorization to the selected version is not.',[1],None,[]),
(41,'manual_review_required',.48,'insufficient_evidence','absent','Player statistics and filters are described with API-key authentication; neither public authorization nor subscription tier is stated.',[1],None,[]),
(44,'manual_review_required',.53,'insufficient_evidence','heuristic_only','Server tenant ownership is a response attribute; neither that attribute nor impersonation scope states caller-tenant equality for this read.',[0,38,40],None,[]),
(47,'manual_review_required',.53,'insufficient_evidence','heuristic_only','The payment route requires a bearer API key, but does not define which payments that key may access.',[1,36],None,[]),
(50,'manual_review_required',.48,'insufficient_evidence','heuristic_only','Memberships here are sports roster records; a subscription-key header alone does not identify a required consumer tier.',[0,3],None,[]),
(53,'manual_review_required',.51,'insufficient_evidence','heuristic_only','OAuth client-credentials and activity-write scope establish permission vocabulary, not an owner, tenant, or application-role rule for patching activities.',[0,7,10],None,[]),
(56,'manual_review_required',.48,'insufficient_evidence','heuristic_only','User deletion and API-key setup are documented, but no self-only or administrative deletion requirement is stated.',[1,4],None,[]),
(59,'manual_review_required',.54,'insufficient_evidence','heuristic_only','Administrative access is required for the returned admin URL, not explicitly for this project-information endpoint; creator and organization fields are descriptive.',[1,5,8,15],None,[]),
(62,'manual_review_required',.49,'insufficient_evidence','heuristic_only','Japanese documentation identifies script-tag update and account ID; OAuth write permission does not establish caller-account equality.',[0,6,18],None,[]),
(65,'manual_review_required',.36,'insufficient_evidence','heuristic_only','Account-role identifier and token authentication are present, but editing authorization is unspecified; manager booleans describe data.',[0,1],None,[]),
(68,'manual_review_required',.48,'insufficient_evidence','heuristic_only','Address attachment identifies its customer and ignores body IDs, but does not require that the caller be that customer or tenant.',[0,1,2],None,[]),
(71,'manual_review_required',.50,'ambiguous','heuristic_only','User connection logs accept me or all; the documentation does not define who may select another user or all users.',[1,2,8],None,[]),
(74,'manual_review_required',.85,'ambiguous','explicit','The operation combines account-admin/account-owner permission with Pro-or-higher eligibility and setting-specific plan restrictions; one of seven labels would discard a material conjunct.',[1,61],None,[]),
(77,'manual_review_required',.49,'insufficient_evidence','heuristic_only','Competitor data requires an API key; premium in the path is not an explicit subscription-tier requirement.',[1,11],None,[]),
(80,'manual_review_required',.45,'insufficient_evidence','heuristic_only','The bulk-annotation description explains resource identifiers and upload format, but no caller repository privilege or workspace relationship.',[0,2],None,[]),
(83,'tenant_match',.87,'supported','corroborated','Application listing is explicitly within the requesting account, and AccountSid identifies the account that created those resources; this supports account-boundary matching without inventing DB mappings.',[1,2,7],'AccountSid',[]),
(86,'manual_review_required',.61,'ambiguous','explicit','A forbidden response states provider eligibility is checked, but the eligibility condition is not specified as ownership, tenant equality, role, or subscription.',[4],None,[]),
(89,'manual_review_required',.49,'insufficient_evidence','heuristic_only','The collaborator OAuth scope and blue-access description do not define an application role or relation between caller and business group.',[0,4],None,[]),
(92,'manual_review_required',.38,'insufficient_evidence','absent','JWT authentication and generic forbidden errors do not establish which app-localization records the caller may read.',[0,3,5],None,[]),
(95,'manual_review_required',.44,'insufficient_evidence','absent','Mark-unread behavior and generic unauthorized/forbidden responses provide no ownership or other concrete authorization condition.',[1,8,9],None,[]),
(98,'manual_review_required',.56,'ambiguous','heuristic_only','Available-for-you rate plans imply entitlement filtering, but ownership or tenant matching is not stated; closed-user-group rates are examples of product conditions, not a universal endpoint membership requirement.',[9],None,[]),
]
assert {x[0] for x in authored}==set(range(2,100,3))
out=[]
for index,label,confidence,status,strength,rationale,facts,param,roles in authored:
    r=rows[index]
    d=dict(id=r['id'],label=label,confidence=confidence,policy_status=status,evidence_strength=strength,rationale=rationale,object_param=param,owner_lookup=None,lookup_status='unresolved' if label in {'owner_match','tenant_match','owner_or_admin'} else 'not_applicable',lookup_reason='Physical database mapping is unverified; policy evidence is independent of lookup.' if param else 'No concrete object-policy lookup is asserted by this decision.',roles=roles,allowed_membership=[],evidence=[dict(pointer=r['enrichment']['facts'][f]['json_pointer'],quote=r['enrichment']['facts'][f]['text']) for f in facts])
    validate(r,d)
    out.append(d)
with (P/'shard2.jsonl').open('x',encoding='utf-8') as f:
    f.write(''.join(json.dumps(d,ensure_ascii=False)+'\n' for d in out))
audit=['# Blind pilot shard 2 direct evidence review','','All 33 assigned records read individually, including recovered facts, effective security, and inferred schema. No prior labels read; no model API, network, or local-model execution. Confidence is subjective; all proposals await human review. Serialization below only records explicit authored decisions, not a rule classifier.','','| pilot index | label | rationale |','|---:|---|---|']
for a in authored:audit.append(f'| {a[0]} | {a[1]} | {a[5]} |')
(P/'shard2.md').write_text('\n'.join(audit)+'\n',encoding='utf-8')
print('Validated and persisted',len(out),'individually authored decisions')
