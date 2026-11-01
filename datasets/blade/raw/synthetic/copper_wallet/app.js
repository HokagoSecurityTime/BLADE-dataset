const express = require("express");
const swaggerJsdoc = require("swagger-jsdoc");
const fs = require("fs");
const app = express();
const principals = {"alice": {"id": "alice", "tenant_id": "north", "role": "user", "plan": "premium"}, "bob": {"id": "bob", "tenant_id": "south", "role": "user", "plan": "free"}, "admin": {"id": "root", "tenant_id": "north", "role": "admin", "plan": "premium"}};
const objects = {"1":{id:"1",owner_id:"alice",tenant_id:"north",value:"fixture secret"},"2":{id:"2",owner_id:"bob",tenant_id:"south",value:"other secret"}};
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/catalogue/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/catalogue/current/:item_id", function copper_wallet_catalogue_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/catalogue/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/catalogue/archive/:item_id", function copper_wallet_catalogue_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/drafts/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/drafts/current/:item_id", function copper_wallet_drafts_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["id"] !== obj["owner_id"]) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/drafts/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/drafts/archive/:item_id", function copper_wallet_drafts_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/shared/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/shared/current/:item_id", function copper_wallet_shared_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["id"] !== obj["owner_id"] && principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/shared/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/shared/archive/:item_id", function copper_wallet_shared_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/workspace/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/workspace/current/:item_id", function copper_wallet_workspace_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["tenant_id"] !== obj["tenant_id"]) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/workspace/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/workspace/archive/:item_id", function copper_wallet_workspace_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/audit/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/audit/current/:item_id", function copper_wallet_audit_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/audit/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/audit/archive/:item_id", function copper_wallet_audit_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/subscription/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/subscription/current/:item_id", function copper_wallet_subscription_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (principal["plan"] !== "premium") return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/subscription/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/subscription/archive/:item_id", function copper_wallet_subscription_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Deliberate fixture: object authorization check omitted.
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/disputed/current/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/disputed/current/:item_id", function copper_wallet_disputed_0(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (true) return res.sendStatus(403);
  return res.json(obj);
});
/**
 * @openapi
 * /fixtures/copper_wallet/transfers/disputed/archive/{item_id}:
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
app.get("/fixtures/copper_wallet/transfers/disputed/archive/:item_id", function copper_wallet_disputed_1(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  if (true) return res.sendStatus(403);
  return res.json(obj);
});
const spec = swaggerJsdoc({definition:{openapi:"3.0.3",info:{title:"copper_wallet",version:"1.0.0"}},apis:[__filename]});
if (process.argv.includes("--export")) fs.writeFileSync("openapi.json",JSON.stringify(spec,null,2));
else { app.get("/openapi.json",(req,res)=>res.json(spec)); app.listen(8080,"0.0.0.0"); }
