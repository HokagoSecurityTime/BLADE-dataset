const express = require("express");
const app = express();
const principals = {"alice":{"id":"alice","tenant_id":"north","role":"user","plan":"premium"},"bob":{"id":"bob","tenant_id":"south","role":"user","plan":"free"},"admin":{"id":"root","tenant_id":"north","role":"admin","plan":"premium"}};
const objects = {"1":{id:"1",owner_id:"alice",tenant_id:"north",value:"fixture secret"},"2":{id:"2",owner_id:"bob",tenant_id:"south",value:"other secret"}};
function requireAuth(req, res, next) {
  // Middleware: authentication only (401). No authorization.
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  req.principal = principal;
  next();
}

app.get("/fixtures/copper_wallet/transfers/drafts/authonly/:item_id", function copper_wallet_drafts_authonly(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Variant: object authorization check removed.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/drafts/extauth/:item_id", requireAuth, function copper_wallet_drafts_extauth(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  // Variant: authentication via middleware only; no authorization check.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/drafts/extguard/:item_id", requireAuth, function copper_wallet_drafts_extguard(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  if (principal["id"] !== obj["owner_id"]) return res.sendStatus(403);
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/shared/authonly/:item_id", function copper_wallet_shared_authonly(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Variant: object authorization check removed.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/shared/extauth/:item_id", requireAuth, function copper_wallet_shared_extauth(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  // Variant: authentication via middleware only; no authorization check.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/shared/extguard/:item_id", requireAuth, function copper_wallet_shared_extguard(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  if (principal["id"] !== obj["owner_id"] && principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/workspace/authonly/:item_id", function copper_wallet_workspace_authonly(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Variant: object authorization check removed.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/workspace/extauth/:item_id", requireAuth, function copper_wallet_workspace_extauth(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  // Variant: authentication via middleware only; no authorization check.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/workspace/extguard/:item_id", requireAuth, function copper_wallet_workspace_extguard(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  if (principal["tenant_id"] !== obj["tenant_id"]) return res.sendStatus(403);
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/audit/authonly/:item_id", function copper_wallet_audit_authonly(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];
  if (!principal) return res.sendStatus(401);
  // Variant: object authorization check removed.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/audit/extauth/:item_id", requireAuth, function copper_wallet_audit_extauth(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  // Variant: authentication via middleware only; no authorization check.
  return res.json(obj);
});
app.get("/fixtures/copper_wallet/transfers/audit/extguard/:item_id", requireAuth, function copper_wallet_audit_extguard(req,res) {
  const obj = objects[req.params.item_id];
  if (!obj) return res.sendStatus(404);
  const principal = req.principal;
  if (principal["role"] !== "admin") return res.sendStatus(403);
  return res.json(obj);
});
app.listen(8080, "0.0.0.0");
