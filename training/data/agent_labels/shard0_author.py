"""Serialization only: each indexed decision below was authored after inspection."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BATCH3 = '''
270|manual_review_required|0.55|NFT URI lookup identifies chain content but provides no affirmative unrestricted-access statement; missing security remains unknown.
273|manual_review_required|0.55|Resending a failed notification is a mutation identified by notification_id without recipient-owner or role evidence.
276|manual_review_required|0.55|Joining a community adds the caller, but creatorId/creatorTenantId do not imply only the creator may join; scopes are permissions.
279|manual_review_required|0.55|Conversation creator and creator-tenant fields coexist, without evidence identifying who may update the group.
282|manual_review_required|0.55|Label-based conversation listing has read scopes and an envelope, not a verified caller-owner relationship.
285|manual_review_required|0.55|Conference details include creator and moderation flags, but neither membership requirements nor creator-only access is specified.
288|manual_review_required|0.55|Organization id and address properties are inferred response fields; a caller-tenant binding is not established.
291|manual_review_required|0.55|Organization-nested add-on-provider metadata has no organization key or caller authorization relation.
294|manual_review_required|0.55|Provider feature creation is organization-nested but name/type/value fields cannot resolve tenant authorization.
297|manual_review_required|0.55|Add-on plan is an inspected product object, not evidence of a required caller subscription tier or verified organization binding.
300|manual_review_required|0.55|Organization add-on SSO returns a macaroon and URL without a verified organization-to-caller relation.
303|manual_review_required|0.55|School response includes district but OAuth alone does not establish school/district tenant authorization.
306|manual_review_required|0.55|Guest update returns grants and username but does not state which caller may manage that guest or supply a verified owner binding.
309|manual_review_required|0.55|Contact organization_name is contact data rather than a verified tenant relation; basic authentication supplies no list ownership rule.
312|manual_review_required|0.55|OCR async-job status requires an API key but lacks job-owner or role authorization evidence.
315|manual_review_required|0.55|Company report has companyName in reportInfo, insufficient to verify companyId-to-caller tenant authorization.
318|manual_review_required|0.55|Company data-integrity status supplies metadata only, without a tenant lookup for companyId.
321|manual_review_required|0.55|Generating a company Excel report exposes job status but no verified company ownership relation.
324|manual_review_required|0.55|Company connection account categories contain accounting references, not an authenticated tenant binding.
327|manual_review_required|0.55|Company retention metrics return dimensions/measures without company or connection ownership lookup evidence.
330|manual_review_required|0.55|Win-probability game data requires an API key; no affirmative unrestricted-access or caller-tier rule is supplied.
333|manual_review_required|0.55|Player PPA team is a sports attribute, not tenant evidence, and API authentication does not define a policy label.
336|manual_review_required|0.55|Domain scheduled-task update has task id and script location without verified domain owner or role authorization.
339|manual_review_required|0.55|Config organization is embedded response data; product/config ownership and caller tenant linkage remain unverified.
342|manual_review_required|0.55|Setting-values organizationId is nested among product/environment metadata without a verified composite lookup binding.
345|manual_review_required|0.55|Environment organization/product embedding suggests tenancy but lacks a verified caller relation and lookup key.
348|manual_review_required|0.55|Setting creatorEmail describes authorship, while environment/setting authorization may differ and is unspecified.
351|public|0.76|This explicitly anonymous Azure authentication endpoint issues an access token; supplied evidence describes authentication bootstrap rather than existing-user object authorization.
354|manual_review_required|0.55|Certificate signing requires conjurAuth and account path, but certificate-only output cannot verify account ownership or an allowed role.
357|manual_review_required|0.55|Webhook user is an opaque relationship object, insufficient for a verified caller-to-subscription ownership lookup.
360|manual_review_required|0.55|API-key user and roles describe the key's subject, not the caller authorization necessary to inspect it.
363|manual_review_required|0.55|Document reprocessing supplies workflow state and opened_by, but no defined owner or permitted reviewer relation.
366|manual_review_required|0.55|Contribution user and allowsAnonymousContributions concern attribution/submission, not necessarily unrestricted retrieval of this contribution.
369|manual_review_required|0.55|Form-response user is an opaque object without a verified response owner or read-access condition.
372|manual_review_required|0.55|User bio retrieval does not state self-only or unrestricted access, and inferred id is not a verified owner lookup.
375|manual_review_required|0.55|My-abuses implies caller scoping, but data/total envelope supplies no object ownership lookup for the optional id filter.
378|manual_review_required|0.55|User response role is a subject attribute, not a caller-role requirement; self/admin access is not specified.
381|manual_review_required|0.55|Disabling two-factor uses a user route and currentPassword, but no verified subject binding or alternate administrator rule is supplied.
384|manual_review_required|0.55|Liveness here is a registration verification image, not an unrestricted health probe; owner authorization is absent.
387|manual_review_required|0.55|Registration summary mixes agency creator and personal data without establishing the caller's permitted owner or tenant relationship.
'''
BATCH2 = '''
180|manual_review_required|0.55|Recipe-image Poster.UserID describes authorship but does not establish owner-only image access or an unrestricted policy.
183|manual_review_required|0.55|Bank-account update exposes accountName rather than a verified caller-owner identifier, and security is unspecified.
186|manual_review_required|0.55|Cash-receipt customerId identifies a business counterparty without proving caller ownership or a verified lookup relation.
189|manual_review_required|0.55|Customer transaction listing identifies the customer in the route but returned transactions lack a caller ownership binding.
192|manual_review_required|0.55|Quotes contain companyId and customerOwnerId, leaving competing organization/customer relations unresolved without verified schema.
195|manual_review_required|0.55|Customer-address CustomerId suggests a relation, but Company is postal data and caller-to-customer authorization is unspecified.
198|manual_review_required|0.55|Address update contains CustomerId and company address fields without a verified caller identity or tenant binding.
201|manual_review_required|0.55|Customer address listing returns only a paging envelope, so customer-to-caller authorization cannot be resolved.
204|manual_review_required|0.55|Order-list shopId and order-state filters appear in a paging endpoint without an evidenced owner, role, or public policy.
207|manual_review_required|0.55|Document listing uses an API key and partner filters, while the paginated response lacks ownership evidence.
210|manual_review_required|0.55|Proforma conversion includes organization billing details rather than a verified tenant identifier for authorization.
213|manual_review_required|0.55|Partner update exposes bank/contact fields and id but no relation to the authenticated caller or tenant.
216|manual_review_required|0.55|Commit-comment user is a flattened object; repository scope and workspace path do not prove comment ownership or tenant lookup.
219|manual_review_required|0.55|Commit property update is workspace-nested but only _attributes is supplied, leaving authorization and lookup unresolved.
222|manual_review_required|0.55|Report annotations return paging fields without workspace ownership binding or an explicit public rule.
225|manual_review_required|0.55|Annotation update provides uuid and report nesting but no verified workspace-to-caller authorization relation.
228|manual_review_required|0.55|Issue component retrieval has issue OAuth scope and workspace nesting, neither of which defines an application role or tenant lookup.
231|manual_review_required|0.55|Stop route details require an API key; response transit references do not establish a public or caller-specific policy.
234|manual_review_required|0.55|Private-registry image inspection includes container User configuration, which is not evidence of image owner authorization.
237|manual_review_required|0.55|Collaboration exemption includes user and enterprise objects, but OAuth alone does not specify who may inspect exemptions.
240|manual_review_required|0.55|Collection-item listing has OAuth authentication and pagination only, without collection ownership evidence.
243|manual_review_required|0.55|Device-pin deletion returns error fields; neither device ownership nor an administrator requirement is documented.
246|manual_review_required|0.55|Company notification listing exposes subjectId but no verified company-to-caller tenant relation.
249|manual_review_required|0.55|Order creation returns owner and subjectId, but their relation to the authenticated caller is undefined and unverified.
252|manual_review_required|0.55|Guarded video delivery requires an Account Playback token; Playback is a permission rather than an application membership tier.
255|manual_review_required|0.55|Related-message listing has basic authentication and recipient data without an authenticated sender/owner relationship.
258|manual_review_required|0.55|Clan reward state is identified by groupId, but membership authorization and unrestricted access are both unspecified.
261|manual_review_required|0.55|Character activity history contains account/character identifiers but no evidence that access is owner-only or unrestricted.
264|manual_review_required|0.55|Call recording lookup exposes campaignId and callId without a caller owner or tenant relationship.
267|manual_review_required|0.55|Token balance lookup describes chain data but supplies no affirmative unrestricted-access rule; absent security is unknown.
'''
rows = [json.loads(x) for x in (ROOT/'datasets/blade/processed/apisguru_filtered.jsonl').read_text(encoding='utf-8').splitlines()]

def persist(text):
    target = Path(__file__).with_name('shard0.jsonl')
    old = [json.loads(x) for x in target.read_text(encoding='utf-8').splitlines()] if target.exists() else []
    seen = {x['id'] for x in old}
    for line in text.strip().splitlines():
        idx, label, confidence, reason = line.split('|', 3)
        row = rows[int(idx)]
        assert int(idx) % 3 == 0 and row['id'] not in seen
        old.append(dict(id=row['id'],label=label,confidence=float(confidence),rationale=reason,object_param=None,owner_lookup=None,roles=['admin'] if label=='role_required' else [],allowed_membership=['Analyst'] if label=='membership_required' else []))
        seen.add(row['id'])
    target.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in old),encoding='utf-8')

if __name__ == '__main__':
    persist('''
0|manual_review_required|0.55|Vault item creation uses ConnectToken, but items.vault has no verified vault-to-caller ownership binding.
3|manual_review_required|0.55|Push-device filters identify clients while the ERD is an error envelope; authentication does not establish device ownership.
6|manual_review_required|0.55|account_id and apps.accountId suggest account scoping, but account may be person or tenant and the inferred relation is unverified.
9|manual_review_required|0.55|Creating an application key requires bearer authentication; keys.appId does not identify an authorized caller or tenant.
12|manual_review_required|0.55|Reactor rule includes projectId among target configuration fields, so it cannot safely be treated as the rule tenant.
15|manual_review_required|0.55|IP geolocation includes api_key and descriptive organization fields; neither unrestricted access nor an application policy is specified.
18|manual_review_required|0.55|Payment-instrument listing has authenticated balance-account ID but only a pagination envelope, with no owner lookup.
21|manual_review_required|0.55|Legal-entity organization and individual are response alternatives rather than verified caller ownership relations.
24|manual_review_required|0.55|Payment-instrument balanceAccountId and shipping company fields do not establish an authenticated owner or tenant binding.
27|manual_review_required|0.55|Authorization-category update returns error fields only and supplies no security or role requirement.
30|manual_review_required|0.55|createdByUserID is a search filter over a paginated authorization-code result, not evidence that callers own returned records.
33|manual_review_required|0.55|OAuth protects monitor-type retrieval but the codeDescription/id schema supplies no ownership, role, or unrestricted-access evidence.
36|manual_review_required|0.55|workspaceId scopes alert-manager creation, but definition data/clientToken cannot resolve the caller tenant.
39|manual_review_required|0.55|Workspace logging creation uses HMAC; logGroupArn/clientToken fields do not verify workspace authorization.
42|manual_review_required|0.55|Rule-group creation is workspace-nested, but the response has no verified workspace lookup or caller claim relation.
45|manual_review_required|0.55|Updating a named workspace rule namespace has only data/clientToken and no verified tenant key.
48|manual_review_required|0.55|Event resource_id is a listing filter and the result is paginated; absent security does not establish public access.
51|manual_review_required|0.55|Image vulnerability retrieval supplies imageDigest without caller ownership or affirmative unrestricted-access evidence.
54|manual_review_required|0.55|DAG-run security is empty, but run configuration/state is an identified operational object with no explicit unrestricted authorization.
57|manual_review_required|0.55|City details require API authentication; geographical response fields alone do not establish an unrestricted or caller-based policy.
60|manual_review_required|0.55|Company settings expose company_id, but inferred flattened data does not verify company-to-caller tenant lookup.
63|manual_review_required|0.55|Updating company settings suggests tenant scope; settings.id and company_id are inferred properties without verified lookup binding.
66|manual_review_required|0.55|Company form-template retrieval contains a pagination envelope without template-to-company ownership columns.
69|manual_review_required|0.55|Live-stream PATCH requires bearer authentication; a public property describes stream visibility rather than update authorization.
72|manual_review_required|0.55|Cart-list API key and store_key filter do not specify a caller role, tier, or object ownership mapping.
75|manual_review_required|0.55|Attribute-group listing requires api_key and store_key together, but no authorization policy or owner lookup is supplied.
78|manual_review_required|0.55|Artifact metadata createdBy hints authorship, but artifactId/globalId/id relations and author authorization remain unverified.
81|manual_review_required|0.55|Versioned artifact metadata has createdBy but no verified artifact/version lookup or proof authors exclusively control it.
84|manual_review_required|0.55|Bill deletion returns an operation envelope; API-key authentication does not identify its owner or tenant.
87|manual_review_required|0.55|Customer deletion identifies a customer object but neither a caller-subject relation nor verified customer primary key is supplied.
90|manual_review_required|0.55|Invoice-item deletion supplies result identifiers without an invoice-to-caller ownership relationship.
93|manual_review_required|0.55|Invoice update returns id/downstream_id metadata without a verified owner or organization mapping.
96|manual_review_required|0.55|Project/location/API nesting suggests project scope, but version metadata lacks a verified tenant binding.
99|manual_review_required|0.55|Dealer details have seller contact fields and authorization authentication, without affirmative public or owner-only policy.
102|manual_review_required|0.55|Listing extra attributes require authentication but do not identify an owner, tenant, role, or membership condition.
105|manual_review_required|0.55|owner_name scopes app analytics, but operating-system counts cannot verify caller ownership of that app.
108|manual_review_required|0.55|App crash issue metadata lacks owner mapping despite owner_name in the route and APIToken authentication.
111|manual_review_required|0.55|Build distribution is owner/app-nested, but status/upload_id cannot establish a verified caller-to-app binding.
114|manual_review_required|0.55|Crash-group identifiers and counts lack an app-owner relationship despite owner_name in the route.
117|manual_review_required|0.55|Crash deletion returns app_id and deletion counts but no verified app-owner or caller role check.
120|manual_review_required|0.55|App localization update uses bearer authentication and flattened relationships without ownership or tenant evidence.
123|manual_review_required|0.55|Document $permissions is an opaque response field; JWT plus Project authentication does not reveal its actual ACL.
126|manual_review_required|0.55|File $permissions is opaque and no caller-to-file owner binding is shown for this update.
129|manual_review_required|0.55|Team-membership listing is team-nested but the memberships/sum envelope cannot resolve tenant or membership authorization.
132|manual_review_required|0.55|Entropy calculation is described as billed, but no concrete subscription tier or unrestricted-access evidence is supplied.
135|manual_review_required|0.55|Episode premium_status is a response attribute, not a specified caller subscription requirement; ownership is also unverified.
138|manual_review_required|0.55|Business-name update is individual-nested but lacks party ownership lookup or security evidence.
141|manual_review_required|0.55|Client registration/OAuth authentication alternatives do not establish the caller's ownership of client_id.
144|membership_required|0.73|Listings endpoint is explicitly tagged Analyst Plan Or Greater, identifying a subscription requirement rather than a dealer-owner relation.
147|manual_review_required|0.55|Broadcast listing uses an API key; flattened author and publication-rights fields do not establish authorization to the listed programmes.
150|manual_review_required|0.55|Programme feed contains flattened author and rights fields with API-key authentication but no verified caller policy.
153|manual_review_required|0.55|Programme-details pid selects content, while author and publication-rights metadata provide no verified access binding.
156|manual_review_required|0.55|Schedule search has API-key authentication and extensive flattened content metadata, not a verified owner or public authorization rule.
159|manual_review_required|0.55|Brand-franchise retrieval contains flattened author metadata without a verified brand ownership or unrestricted-access rule.
162|manual_review_required|0.55|Account harvest request is account-nested but its ERD contains errors only, so owner-versus-tenant authorization is unresolved.
165|manual_review_required|0.55|Order harvest identifies account and order but supplies only errors, without a verified ownership lookup.
168|manual_review_required|0.55|Merchant-order-info mutation has account/order route identifiers but no usable ownership schema or authorization requirement.
171|manual_review_required|0.55|User connection-log listing identifies id_user but the connectionlogs/total envelope does not verify caller-subject authorization.
174|manual_review_required|0.55|Review response mixes ID, ReviewID and poster UserID; flattened authorship does not prove private owner-only read access.
177|manual_review_required|0.55|Posting a reply to reviewId exposes reply UserID, which is not proof the caller must own the parent review.
''')
