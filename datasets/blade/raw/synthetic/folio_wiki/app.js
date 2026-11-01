const express = require("express");
const swaggerJsdoc = require("swagger-jsdoc");
const fs = require("fs");
const app = express();
const principals = {"alice": {"id": "alice", "tenant_id": "north", "role": "user", "plan": "premium"}, "bob": {"id": "bob", "tenant_id": "south", "role": "user", "plan": "free"}, "admin": {"id": "root", "tenant_id": "north", "role": "admin", "plan": "premium"}};
const objects = {"1":{id:"1",owner_id:"alice",tenant_id:"north",value:"fixture secret"},"2":{id:"2",owner_id:"bob",tenant_id:"south",value:"other secret"}};
/**
 * @openapi
 * /fixtures/folio_wiki/pages/catalogue/current/{item_id}:
 *   get:
 *     description: Intentionally anonymous reference catalogue.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/catalogue/current/:item_id", function folio_wiki_catalogue_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/catalogue/archive/{item_id}:
 *   get:
 *     description: Intentionally anonymous reference catalogue.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/catalogue/archive/:item_id", function folio_wiki_catalogue_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/drafts/current/{item_id}:
 *   get:
 *     description: Only the record owner may read it.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/drafts/current/:item_id", function folio_wiki_drafts_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["id"] !== obj["owner_id"]) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/drafts/archive/{item_id}:
 *   get:
 *     description: Only the record owner may read it.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/drafts/archive/:item_id", function folio_wiki_drafts_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/shared/current/{item_id}:
 *   get:
 *     description: The record owner or an administrator may read it.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/shared/current/:item_id", function folio_wiki_shared_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["id"] !== obj["owner_id"] && principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/shared/archive/{item_id}:
 *   get:
 *     description: The record owner or an administrator may read it.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/shared/archive/:item_id", function folio_wiki_shared_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/workspace/current/{item_id}:
 *   get:
 *     description: Caller and record must share a tenant.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/workspace/current/:item_id", function folio_wiki_workspace_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["tenant_id"] !== obj["tenant_id"]) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/workspace/archive/{item_id}:
 *   get:
 *     description: Caller and record must share a tenant.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/workspace/archive/:item_id", function folio_wiki_workspace_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/audit/current/{item_id}:
 *   get:
 *     description: Only administrators may read this operational resource.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/audit/current/:item_id", function folio_wiki_audit_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/audit/archive/{item_id}:
 *   get:
 *     description: Only administrators may read this operational resource.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/audit/archive/:item_id", function folio_wiki_audit_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/subscription/current/{item_id}:
 *   get:
 *     description: A premium plan is required.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/subscription/current/:item_id", function folio_wiki_subscription_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["plan"] !== "premium") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/subscription/archive/{item_id}:
 *   get:
 *     description: A premium plan is required.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/subscription/archive/:item_id", function folio_wiki_subscription_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/disputed/current/{item_id}:
 *   get:
 *     description: Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/disputed/current/:item_id", function folio_wiki_disputed_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (true) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/folio_wiki/pages/disputed/archive/{item_id}:
 *   get:
 *     description: Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.
 *     parameters:
 *       - in: path
 *         name: item_id
 *         required: true
 *         schema: {type: string}
 *     responses:
 *       200:
 *         description: Fixture record
 */
app.get("/fixtures/folio_wiki/pages/disputed/archive/:item_id", function folio_wiki_disputed_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (true) return res.sendStatus(403);
  return res.json(obj);
});
const spec = swaggerJsdoc({definition:{openapi:"3.0.3",info:{title:"folio_wiki",version:"1.0.0"}},apis:[__filename]});
if (process.argv.includes("--export")) fs.writeFileSync("openapi.json",JSON.stringify(spec,null,2));
else { app.get("/openapi.json",(req,res)=>res.json(spec)); app.listen(8080,"0.0.0.0"); }
