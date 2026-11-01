"""Serialize individually authored blind-review decisions; not a classifier."""
import json
from pathlib import Path
from training.data.assemble_policy_pilot import validate

BASE = Path('training/data/policy_pilot_decisions')
rows = [json.loads(s) for s in (BASE/'blind_input.jsonl').read_text(encoding='utf-8').splitlines()]
# index, label, confidence, status, strength, rationale, verbatim evidence,
# object parameter, required membership. Each tuple is an individual judgment.
authored = [
(1,'membership_required',.88,'supported','explicit','The valuation endpoint is explicitly Premium and date access depends on subscription tier; no object-owner check is described.','Premium. Simple Vehicle Market Report Over Arbitrary Locations and Vehicles.',None,['Premium']),
(4,'manual_review_required',.42,'insufficient_evidence','heuristic_only','Deleting a user under /admin suggests elevated privileges, but the recovered summary supplies no actual role restriction.','Delete a user',None,[]),
(7,'manual_review_required',.43,'insufficient_evidence','heuristic_only','Suspend-user naming and suspended_by response data do not establish which caller role may suspend users.','Suspend a user',None,[]),
(10,'manual_review_required',.40,'insufficient_evidence','absent','Discussion topic details and author/can_edit response fields do not establish access policy for this GET; missing security does not prove public.','Get information about a group discussion topic',None,[]),
(13,'manual_review_required',.40,'insufficient_evidence','absent','Photostream navigation description does not specify visibility or caller restrictions; owner response data alone cannot establish owner-only reads.','Returns next and previous photos for a photo in a photostream',None,[]),
(16,'manual_review_required',.53,'ambiguous','heuristic_only','The required admin.conversations:read OAuth permission is explicit, but no application role or channel relationship rule is supplied.','Authentication token. Requires scope: `admin.conversations:read`',None,[]),
(19,'membership_required',.94,'supported','explicit','The operation expressly excludes free-plan users and requires donation qualification, which is a membership condition rather than object ownership.','Feature not available on free plan, please donate to be able to use this feature.',None,['donation-qualified non-free plan']),
(22,'owner_match',.98,'supported','explicit','The operation explicitly returns 403 for recipes owned by someone else, establishing caller ownership independently of any physical DB lookup.','Returns 403 if the recipe is owned by someone else.','id',[]),
(25,'manual_review_required',.89,'ambiguous','explicit','Conversation participation is explicitly required, but arbitrary conversation membership is outside the subscription/qualification membership label and is not owner or tenant equality.','This operation can be only performed on behalf of a user who is already a member of the conversation.',None,[]),
(28,'manual_review_required',.76,'ambiguous','explicit','The read depends on whether the account owner hides their network; authentication and visibility conditions do not reduce to unconditional public or owner-only access.','Accounts which the given account is following, if network is not hidden by the account owner.',None,[]),
(31,'manual_review_required',.40,'insufficient_evidence','absent','The response user field and response ID identify data but the summary gives no caller-to-response authorization relation.','Get a single form response by id',None,[]),
(34,'manual_review_required',.48,'insufficient_evidence','heuristic_only','JWT authentication and a user-scoped email path are documented; neither says callers can update only their own emails or names an authorized role.','Update an email address',None,[]),
(37,'manual_review_required',.50,'ambiguous','heuristic_only','A gateway shared secret protects the management call, but this does not identify an application role or caller-organization equality check.','tyk gateway shared secret',None,[]),
(40,'manual_review_required',.44,'insufficient_evidence','absent','Basic/API-key authentication and generic insufficient-permissions errors do not specify the policy for a particular payment instrument.','Forbidden - insufficient permissions to process the request.',None,[]),
(43,'manual_review_required',.60,'ambiguous','heuristic_only','Token privileges can be admin-derived and Org/Site-scoped, with Basic Auth as an alternative; the import operation does not state a specific required role or target-org equality.','An API token ties to a Admin with equal or less privileges.',None,[]),
(46,'manual_review_required',.46,'insufficient_evidence','absent','Legal-entity associations and capability fields describe the entity being edited, not the API caller authorization for this PATCH.','Updates a legal entity.',None,[]),
(49,'manual_review_required',.42,'insufficient_evidence','absent','The organization directory response appears informational but its description does not affirm unrestricted access; no caller-tenant check is documented.','Returns organization with specific ID.',None,[]),
(52,'manual_review_required',.45,'insufficient_evidence','heuristic_only','Bearer authentication and organization_id response data do not establish tenant equality or an administrator role for updating an authentication provider.','Updates settings of an existing authentication provider.',None,[]),
(55,'manual_review_required',.43,'insufficient_evidence','heuristic_only','Organization/project nesting and createdBy/orgId fields suggest relationships, but the update description defines no caller authorization condition.','Updates information about a project.',None,[]),
(58,'manual_review_required',.45,'insufficient_evidence','heuristic_only','User and Application Keys authenticate the CRM request; a comment relation.user field does not prove the caller must be its author.','Return comment information',None,[]),
(61,'manual_review_required',.45,'insufficient_evidence','absent','Supported financial account containers and update restrictions are described, but ownership or delegated access is not specified.','The update account service is used to update manual and aggregated accounts.',None,[]),
(64,'manual_review_required',.90,'ambiguous','explicit','Read permission, collaboration and private-link sharing describe a document ACL. This is neither owner-only access nor an application role or subscription tier.','The currently authenticated user must have at least a read access to the document to use this API call.',None,[]),
(67,'manual_review_required',.88,'ambiguous','explicit','AIS consent enables delegated account access; an optional bearer security branch does not make it public, and consent is not caller-is-owner equality.','This then contains the consentId of the related AIS consent, which was performed prior to this payment initiation.',None,[]),
(70,'manual_review_required',.40,'insufficient_evidence','heuristic_only','The workgroup/project path scopes the tag listing, but no caller-workgroup authorization relation is given.','List Tags from Workgroup and Project.',None,[]),
(73,'manual_review_required',.59,'ambiguous','heuristic_only','Admin-derived API token privileges and alternate Basic Auth do not define whether this particular installer upload requires a role, an org grant or tenant equality.','An API token ties to a Admin with equal or less privileges.',None,[]),
(76,'manual_review_required',.41,'insufficient_evidence','heuristic_only','Project/location/API resource names identify the creation parent, but the recovered description contains no IAM role or caller-project authorization rule.','CreateApiVersion creates a specified version.',None,[]),
(79,'manual_review_required',.66,'ambiguous','heuristic_only','OAuth and personal-list wording suggest owner updates, but the explicit privacy rules govern who can see the list, not who may PUT it.','Only you can see the list.',None,[]),
(82,'owner_match',.97,'supported','explicit','The operation expressly limits write access to team owners, establishing object-relative ownership even though the backing ownership mapping is unavailable.','Only team owners have write access for this resource.','teamId',[]),
(85,'manual_review_required',.48,'insufficient_evidence','heuristic_only','An EVE character ID and read_skills OAuth scope are present, but this source does not establish that the token subject must own the requested character.','Return attributes of a character',None,[]),
(88,'manual_review_required',.75,'ambiguous','explicit','OAuth can authorize multiple entities and the header selects an authorized entity. This is a multi-entity grant, not demonstrated equality with a single caller tenant.','the OAuth token is valid for more than one entity',None,[]),
(91,'manual_review_required',.43,'insufficient_evidence','absent','API-key authentication and a document status ID are specified; no caller-owner, tenant or role restriction is described.','Retrieves the details of an existing document status.',None,[]),
(94,'manual_review_required',.62,'ambiguous','heuristic_only','A user token for sensitive account/API-key operations suggests self-service, but the text does not explicitly bind the supplied key/configuration to that caller.','A secret key used for sensitive operations on your account and API Keys.',None,[]),
(97,'manual_review_required',.43,'insufficient_evidence','absent','Deleting a device pin requires OAuth, but the operation describes no required enterprise role or ownership check; generic global scopes cannot supply one.','Deletes an individual device pin.',None,[]),
]
decisions=[]
for i,label,confidence,status,strength,rationale,quote,param,memberships in authored:
    row=rows[i]
    matches=[f for f in row['enrichment']['facts'] if quote in f['text']]
    assert matches, (i,quote)
    obj=label in {'owner_match','owner_or_admin','tenant_match'}
    decision=dict(id=row['id'],label=label,confidence=confidence,rationale=rationale,
        policy_status=status,evidence_strength=strength,object_param=param,owner_lookup=None,
        lookup_status='unresolved' if obj else 'not_applicable',
        lookup_reason=('Ownership policy is explicit but no independently verified physical table/key mapping exists.' if obj else 'No concrete object-equality policy is proposed; no physical lookup is asserted.'),
        roles=[],allowed_membership=memberships,
        evidence=[dict(pointer=matches[0]['json_pointer'],quote=quote)])
    validate(row,decision)
    decisions.append(decision)
assert [i for i,*_ in authored]==list(range(1,100,3))
(BASE/'shard1.jsonl').write_text(''.join(json.dumps(d,ensure_ascii=False)+'\n' for d in decisions),encoding='utf-8')
lines=['# Blind policy review shard 1','',
 '33 individually inspected records; no old labels, API calls, local model, or classification rules used. Confidence is uncalibrated. All proposals require human review.',
 'The Python companion only serializes the explicit authored table and checks source quotations. It does not infer labels.', '',
 '| id | proposed label | rationale |','|---|---|---|']
for d in decisions:
    lines.append('| '+d['id']+' | '+d['label']+' | '+d['rationale']+' |')
(BASE/'shard1.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print('Validated',len(decisions),'individually authored decisions')
