"""Explicit individually authored pilot decisions, not a classifier."""
import json
from pathlib import Path
from training.data.assemble_policy_pilot import validate

BASE=Path('training/data/policy_pilot_decisions')
rows=[json.loads(x) for x in (BASE/'blind_input.jsonl').read_text(encoding='utf-8').splitlines()]
# Each tuple is a reviewed row, proposed label, confidence, status, evidence
# strength, rationale, and selected source fact indices. No unlisted default.
authored=[
(0,'manual_review_required',.50,'insufficient_evidence','heuristic_only',"Dealer listings and an Analyst Plan tag suggest a subscription gate, but recovered source prose does not define required subscription tiers or entitlement for this operation.",[1]),
(3,'manual_review_required',.55,'ambiguous','heuristic_only',"Published article listing and explicit empty security suggest public retrieval, but published content alone does not affirm unrestricted authorization. Require confirmation before assigning public.",[0,1]),
(6,'manual_review_required',.45,'insufficient_evidence','heuristic_only',"Admin path and tag suggest administrator access, but the recovered logout summary does not state a caller role requirement.",[0]),
(9,'manual_review_required',.50,'insufficient_evidence','heuristic_only',"Public tag suggests unrestricted reply information, but the recovered description only describes retrieval; author and can_edit response fields are not access policy.",[0]),
(12,'manual_review_required',.50,'insufficient_evidence','heuristic_only',"Public tag and photo-list navigation do not document access restrictions for private lists or prove unrestricted access; response owner is descriptive.",[0]),
(15,'manual_review_required',.55,'ambiguous','heuristic_only',"Admin search route suggests a role restriction. Admin privileges in the security description apply to optional sudo schemes, while other authentication alternatives exist; this is not explicit route-wide admin evidence.",[0,24]),
(18,'role_required',.98,'supported','explicit',"The operation explicitly permits project transfer only for admin; the project identifier does not turn an admin-only operation into ownership matching.",[0]),
(21,'owner_match',.99,'supported','explicit',"Updating a review reply explicitly requires the authenticated user to be its original poster. This establishes owner policy independently of the unresolved physical lookup.",[0]),
(24,'manual_review_required',.58,'ambiguous','explicit',"Update-specific authorization denial is documented, but neither update ownership nor team/profile delegation rules are defined. A user_id response field cannot resolve the policy.",[0,3]),
(27,'manual_review_required',.52,'insufficient_evidence','heuristic_only',"Open-house retrieval requires authentication and may require authorization; listing owner and agent fields describe real-estate parties rather than the caller's permission relationship.",[14,143]),
(30,'manual_review_required',.48,'insufficient_evidence','heuristic_only',"Creating a gist comment is described without an ownership, role, or visibility rule. Comment author and repository association fields do not establish who may comment.",[0,5,11]),
(33,'manual_review_required',.85,'ambiguous','explicit',"Caller must already participate in the conversation, and moderated conversations additionally restrict removal to moderators. Conversation membership is not a subscription tier, and the conditional participant/moderator policy is not represented by a single supported label.",[1,12]),
(36,'manual_review_required',.48,'insufficient_evidence','heuristic_only',"Retrieving the owner of an NFT does not require the requester to own it in the recovered description; NFT owner is the returned subject, not established caller authorization.",[3]),
(39,'manual_review_required',.50,'insufficient_evidence','heuristic_only',"Workspace retrieval uses AWS signature authentication and may deny access, but no account/workspace relationship or required IAM role is stated.",[0,24]),
(42,'manual_review_required',.45,'insufficient_evidence','heuristic_only',"Prediction against a project uses an API key, but project ID and model name describe resource selection without caller-to-project authorization evidence.",[0,1]),
(45,'manual_review_required',.45,'insufficient_evidence','heuristic_only',"A site is selected by ID and API-key failures are documented. Administration URLs and secret fields do not specify which caller may read the site.",[1,29]),
(48,'manual_review_required',.45,'insufficient_evidence','heuristic_only',"Project-scoped prediction is described without caller ownership, tenant equality, or role requirements; the project field alone cannot establish tenant_match.",[0,1]),
(51,'manual_review_required',.58,'ambiguous','heuristic_only',"Installer route and generic API-token association with an admin suggest privileges, but tokens can have reduced privileges and Basic Auth is an alternative. The operation does not explicitly require a particular role or tenant relationship.",[1,10,11]),
(54,'manual_review_required',.88,'ambiguous','explicit',"Public statuses are readable publicly while private statuses require a user token and authorization. This mixed visibility/ACL policy cannot be flattened to public or owner_match.",[121]),
(57,'manual_review_required',.55,'insufficient_evidence','heuristic_only',"Creation targets the supplied account and response calls it your Ably account, but the operation does not state a caller-account equality check or delegation rule. Account context alone is insufficient for tenant or owner policy.",[2,11,28]),
(60,'manual_review_required',.85,'ambiguous','explicit',"Collaborator listing supports private-link sharing keys and collaborator-sensitive fields. Score ACL and link capability access are not equivalent to ownership or paid membership.",[3,47,55]),
(63,'manual_review_required',.75,'ambiguous','explicit',"Consent information is returned for a TPP with delegated PSU/ASPSP authorization context. The source does not reduce consent-read permission to caller ownership, tenant equality, or a simple role.",[1,24,39]),
(66,'manual_review_required',.47,'insufficient_evidence','heuristic_only',"User and application keys authenticate a contact lookup, but relation account/user properties merely identify related entities and do not define contact visibility.",[1,2,3]),
(69,'manual_review_required',.45,'insufficient_evidence','heuristic_only',"Merchant order update names an account and merchant identifiers but does not specify the authenticated principal's required relation to that account or order.",[0,6]),
(72,'manual_review_required',.52,'insufficient_evidence','heuristic_only',"Account-party read uses OAuth and a client identifier, but PSU metadata and account owner references do not specify the consent or caller-account matching rule for this endpoint.",[1,10,29,32]),
(75,'manual_review_required',.53,'insufficient_evidence','heuristic_only',"Order is selected within an account supplied in the URL. The source does not assert that the caller owns that account or define delegated trading privileges.",[3]),
(78,'manual_review_required',.52,'insufficient_evidence','heuristic_only',"Employee pay-rate updates identify company and employee and declare forbidden responses, but no caller-company constraint or payroll administrator role is documented.",[1,29]),
(81,'manual_review_required',.60,'ambiguous','heuristic_only',"API-key-and-secret authentication is explicit, but the source does not state that the authenticated key must equal the path api_key or define cross-account secret-management privileges.",[1,13,25]),
(84,'manual_review_required',.48,'insufficient_evidence','heuristic_only',"Organization import status requires product-read scope. Scope permission and organization ID do not establish caller-to-organization tenant equality.",[0,4]),
(87,'manual_review_required',.48,'insufficient_evidence','absent',"Committee listing filters governmental jurisdictions and parent committees; these are data subjects, not caller tenants. No affirmative unrestricted-access or other authorization rule is recovered.",[0,1]),
(90,'manual_review_required',.48,'insufficient_evidence','heuristic_only',"Event retrieval documents authentication errors, while customer database timestamps and contract partner identifiers are descriptive. No owner, tenant or role gate is specified.",[0,1]),
(93,'owner_match',.95,'supported','explicit',"Deletion explicitly targets the currently authenticated user's own like. Ownership is of the implicit like, not of the media; no like-ID binding or physical lookup is available.",[1]),
(96,'manual_review_required',.48,'insufficient_evidence','absent',"Article fans retrieval describes returned voter IDs but no authorization condition. Neither a public URL nor voter IDs establish public or owner policy.",[1]),
(99,'manual_review_required',.62,'ambiguous','heuristic_only',"The resend-failed-notification operation has a description about returning account subscriptions/IPNs. This mismatch and lack of caller-account relation prevent a defensible ownership or tenant label.",[1,2]),
]
assert [x[0] for x in authored]==list(range(0,100,3))
output=[]
for i,label,confidence,status,strength,rationale,indices in authored:
    row=rows[i]
    obj=label in {'owner_match','owner_or_admin','tenant_match'}
    decision=dict(id=row['id'],label=label,confidence=confidence,rationale=rationale,
        policy_status=status,evidence_strength=strength,object_param='replyId' if i==21 else None,
        owner_lookup=None,lookup_status='unresolved' if obj else 'not_applicable',
        lookup_reason=('Reply poster policy is explicit, but response-derived pseudo-ERD does not verify a database lookup.' if i==21 else
            'Own like is selected implicitly by current user and media; media-id is not a like ID. No verified database mapping.' if i==93 else
            'No physical lookup is proposed for this non-object policy decision.'),
        roles=['admin'] if i==18 else [],allowed_membership=[],
        evidence=[{'pointer':row['enrichment']['facts'][j]['json_pointer'],'quote':row['enrichment']['facts'][j]['text']} for j in indices])
    validate(row,decision)
    output.append(decision)
with (BASE/'shard0.jsonl').open('x',encoding='utf-8') as handle:
    handle.write(''.join(json.dumps(d,ensure_ascii=False)+'\n' for d in output))
with (BASE/'shard0.md').open('x',encoding='utf-8') as handle:
    handle.write('# Shard 0 direct annotation audit\n\nReviewed all 34 assigned records from blind_input.jsonl, including recovered operation, parameter, response and security evidence and pseudo-ERD context. No old labels inspected; no API or model subprocess used. All proposals require human review. Source quotations and schema validated individually.\n\n')
    handle.write('| index | id | proposed label | rationale |\n|---:|---|---|---|\n')
    for entry,d in zip(authored,output):
        handle.write(f"| {entry[0]} | {d['id']} | {d['label']} | {d['rationale']} |\n")
print('Validated and wrote',len(output),'individual decisions')

