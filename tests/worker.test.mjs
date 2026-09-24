import fs from "node:fs/promises";
import assert from "node:assert/strict";

const source = await fs.readFile(new URL("../worker_六账户骨架版.js", import.meta.url), "utf8");
const moduleUrl = "data:text/javascript;charset=utf-8," + encodeURIComponent(source);
const mod = await import(moduleUrl);
const worker = mod.default;

class MockKV {
  constructor() { this.store = new Map(); }
  async get(key) { return this.store.has(key) ? this.store.get(key) : null; }
  async put(key, value) { this.store.set(key, String(value)); }
  async delete(key) { this.store.delete(key); }
}

const kv = new MockKV();
const env = { KV: kv };

async function call(path, options = {}) {
  const request = new Request("https://test.example" + path, options);
  return worker.fetch(request, env);
}

async function jsonResponse(response) {
  const text = await response.text();
  return { status: response.status, body: JSON.parse(text) };
}

const ipText = [
  "172.64.229.0:443",
  "172.64.229.1:8443",
  "104.16.1.1:2053"
].join("\n");

console.log("1. GET /api/nodes 初始状态");
{
  const r = await call("/api/nodes");
  const d = await jsonResponse(r);
  assert.equal(r.status, 200);
  assert.deepEqual(d.body, { success: true, nodes: [] });
}

console.log("2. POST /api/nodes 保存原始 IP 文本");
{
  const r = await call("/api/nodes", {
    method: "POST",
    headers: { "Content-Type": "text/plain; charset=utf-8" },
    body: ipText
  });
  const d = await jsonResponse(r);
  assert.equal(r.status, 200);
  assert.equal(d.body.success, true);
  assert.deepEqual(d.body.nodes, ipText.split("\n"));
}

console.log("3. GET /admin/ADD.txt 验证 KV 实际写入内容");
{
  const r = await call("/admin/ADD.txt");
  assert.equal(r.status, 200);
  assert.equal(await r.text(), ipText);
}

console.log("4. GET /api/nodes 验证读取结果");
{
  const r = await call("/api/nodes");
  const d = await jsonResponse(r);
  assert.equal(r.status, 200);
  assert.deepEqual(d.body.nodes, ipText.split("\n"));
}

console.log("5. GET /sub 验证订阅输出");
{
  const r = await call("/sub");
  assert.equal(r.status, 200);
  assert.equal(await r.text(), ipText + "\n");
}

console.log("6. DELETE /api/nodes 验证删除");
{
  const target = encodeURIComponent("172.64.229.1:8443");
  const r = await call("/api/nodes?node=" + target, { method: "DELETE" });
  const d = await jsonResponse(r);
  assert.equal(r.status, 200);
  assert.equal(d.body.success, true);
  assert.deepEqual(d.body.nodes, [
    "172.64.229.0:443",
    "104.16.1.1:2053"
  ]);
}

console.log("7. 再次读取 ADD.txt 验证删除后的最终内容");
{
  const r = await call("/admin/ADD.txt");
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "172.64.229.0:443\n104.16.1.1:2053");
}

console.log("8. GET /health");
{
  const r = await call("/health");
  const d = await jsonResponse(r);
  assert.equal(r.status, 200);
  assert.equal(d.body.ok, true);
}

console.log("");
console.log("PASS: Worker IP 保存/读取/订阅/删除测试全部通过。");
