// Cloudflare Worker：六账户额度 + IP:端口保存 + 订阅
// KV 绑定：KV
// Secret：CF_ACCOUNTS_JSON=[{"id":"ACCOUNT_ID","token":"TOKEN"},...共6个]
// 可选：CF_DAILY_LIMIT=100000

import { connect } from "cloudflare:sockets";

const KEY = "ADD.txt";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (request.method === "GET" && (path === "/" || path === "/admin")) {
        return page();
      }

      if (path === "/admin/ADD.txt") {
        if (request.method === "POST") {
          const text = await request.text();
          await env.KV.put(KEY, text);
          return json({ success: true, message: "自定义IP已保存" });
        }
        if (request.method === "GET") {
          const text = await env.KV.get(KEY) || "";
          return new Response(text, {
            headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
          });
        }
      }

      if (path === "/api/nodes") {
        if (request.method === "GET") return json({ success: true, nodes: await getNodes(env) });

        if (request.method === "POST") {
          const type = (request.headers.get("content-type") || "").toLowerCase();

          if (type.includes("application/json")) {
            const body = await request.json();
            const ips = String(body.ips || body.ip || "").trim();
            const port = String(body.port || "").trim();
            if (!ips) throw new Error("IP列表不能为空");

            const text = ips.split(/\r?\n|[,，]+/)
              .map(x => x.trim()).filter(Boolean)
              .map(x => x.includes(":") || !port ? x : x + ":" + port)
              .join("\n");

            await env.KV.put(KEY, text);
          } else {
            await env.KV.put(KEY, await request.text());
          }

          return json({ success: true, message: "自定义IP已保存", nodes: await getNodes(env) });
        }

        if (request.method === "DELETE") {
          const target = (url.searchParams.get("node") || "").trim();
          const list = (await getNodes(env)).filter(x => x !== target);
          await env.KV.put(KEY, list.join("\n"));
          return json({ success: true, nodes: list });
        }
      }

      if (path === "/sub" && request.method === "GET") {
        const links = await buildVLESSSubscription(env, url);
        return new Response(links.join("\n") + (links.length ? "\n" : ""), {
          headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
        });
      }

      // 最小 VLESS + TLS + WS 入站：只处理 TCP
      if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        const uuid = await getSubscriptionUserID(env);
        return await handleVLESSWebSocket(request, uuid);
      }

      if (path === "/api/usage" && request.method === "GET") {
        return json(await usage(env));
      }

      if (path === "/health" && request.method === "GET") {
        return json({ ok: true });
      }

      return new Response("Not Found", { status: 404 });
    } catch (e) {
      return json({ success: false, error: e?.message || String(e) }, 500);
    }
  }
};

async function getSubscriptionUserID(env) {
  const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  try { if (env.KV) { const raw = await env.KV.get("config.json"); if (raw) { const cfg = JSON.parse(raw); if (cfg?.UUID && uuidRegex.test(String(cfg.UUID))) return String(cfg.UUID).toLowerCase(); } } } catch (_) {}
  const envUUID = env.UUID || env.uuid;
  if (envUUID && uuidRegex.test(String(envUUID))) return String(envUUID).toLowerCase();
  const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid || "";
  const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
  const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
  const userID = [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
  try { if (env.KV) await env.KV.put("config.json", JSON.stringify({ UUID: userID, PATH: "/", HOST: "" }, null, 2)); } catch (_) {}
  return userID;
}

function getNodeHost(env, url) {
  const raw = env.HOST ? String(env.HOST).split(/[,，\s]+/).filter(Boolean)[0] : url.hostname;
  return String(raw).toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
}

function getNodePath(env) {
  const raw = env.PATH ? String(env.PATH) : '/';
  return raw.startsWith('/') ? raw : '/' + raw;
}

function buildVLESSLink(ipPort, uuid, host, path) {
  const value = String(ipPort).trim();
  let address = value;
  let port = '443';
  const m = value.match(/^\[([^\]]+)\]:(\d+)$/) || value.match(/^([^:]+):(\d+)$/);
  if (m) {
    address = m[1];
    port = m[2];
  }
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', 'tls');
  params.set('sni', host);
  params.set('fp', 'chrome');
  params.set('alpn', 'http/1.1');
  params.set('type', 'ws');
  params.set('host', host);
  params.set('path', path);
  return `vless://${uuid}@${address}:${port}?${params.toString()}#${encodeURIComponent(value)}`;
}

async function buildVLESSSubscription(env, url) {
  const list = await getNodes(env);
  const uuid = await getSubscriptionUserID(env);
  const host = getNodeHost(env, url);
  const path = getNodePath(env);
  return list.map(x => buildVLESSLink(x, uuid, host, path));
}

async function MD5MD5(text) {
  const data = new TextEncoder().encode(String(text));
  const first = await crypto.subtle.digest('MD5', data);
  const firstHex = Array.from(new Uint8Array(first)).map(x => x.toString(16).padStart(2, '0')).join('');
  const second = await crypto.subtle.digest('MD5', new TextEncoder().encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(second)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function getNodes(env) {
  if (!env.KV) throw new Error("KV绑定不存在，请确认绑定名称为 KV");
  const text = await env.KV.get(KEY) || "";
  return text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function page() {
  return new Response(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>自定义优选</title>
<style>
body{font-family:Arial,"Microsoft YaHei",sans-serif;max-width:900px;margin:40px auto;padding:20px;background:#f5f6f8}
.box{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 10px #ddd}
textarea{width:100%;height:360px;box-sizing:border-box;font:14px monospace;padding:12px}
button{padding:9px 18px;margin:10px 8px 0 0;cursor:pointer}
#msg{margin-top:10px}
</style>
</head>
<body>
<div class="box">
<h2>自定义优选</h2>
<p>一行一个 IP:端口，例如 172.64.229.0:443</p>
<textarea id="ips" placeholder="172.64.229.0:443"></textarea><br>
<button onclick="save()">保存</button>
<a href="/sub" target="_blank"><button type="button">订阅接口</button></a>
<div id="msg" style="display:none"></div>
</div>
<script>
const el=document.getElementById("ips"),msg=document.getElementById("msg");
let msgTimer,lastSaved="";
function showMsg(text,ms=2000){
  clearTimeout(msgTimer);
  msg.textContent=text;
  msg.style.display="block";
  msgTimer=setTimeout(()=>{msg.style.display="none";msg.textContent=""},ms);
}
el.addEventListener("input",()=>{msg.style.display="none";clearTimeout(msgTimer)});
async function load(){
  try{
    const r=await fetch("/admin/ADD.txt?_="+Date.now());
    if(!r.ok)throw Error("读取失败");
    lastSaved=await r.text();
    el.value=lastSaved;
  }catch(e){}
}
async function save(){
  const text=el.value;
  if(!text.trim()){showMsg("IP列表不能为空");return}
  if(text===lastSaved)return;
  try{
    const r=await fetch("/admin/ADD.txt",{method:"POST",body:text});
    const d=await r.json();
    if(!r.ok||!d.success)throw Error(d.error||"保存失败");
    lastSaved=text;
    showMsg("保存成功");
  }catch(e){showMsg("保存失败："+e.message)}
}
load();
</script>
</body>
</html>`,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}});
}

function getAccounts(env) {
  if (!env.CF_ACCOUNTS_JSON) throw new Error("未配置 CF_ACCOUNTS_JSON");
  const accounts = JSON.parse(env.CF_ACCOUNTS_JSON);
  if (!Array.isArray(accounts) || accounts.length !== 6) {
    throw new Error("CF_ACCOUNTS_JSON 必须配置6个账户");
  }
  accounts.forEach((a,i) => {
    if (!a?.id || !a?.token) throw new Error(`第${i+1}个账户缺少id或token`);
  });
  return accounts;
}

async function usage(env) {
  const accounts = getAccounts(env);
  const limit = Number(env.CF_DAILY_LIMIT || 100000);
  if (!Number.isFinite(limit) || limit <= 0) throw new Error("CF_DAILY_LIMIT 无效");

  const end = new Date();
  const start = new Date(end);
  start.setUTCHours(0,0,0,0);

  const result = await Promise.all(accounts.map((a,i) => accountUsage(a,i+1,start,end,limit)));
  const used = result.reduce((n,a) => n + a.used, 0);

  return {
    success: true,
    accountCount: 6,
    dailyLimitPerAccount: limit,
    totalLimit: limit * 6,
    totalUsed: used,
    totalRemaining: Math.max(0, limit * 6 - used),
    accounts: result
  };
}

async function accountUsage(account,index,start,end,limit) {
  const query = `query($id:String!,$s:String!,$e:String!){
    viewer{accounts(filter:{accountTag:$id}){
      workersInvocationsAdaptive(
        limit:10000,
        filter:{datetime_geq:$s,datetime_leq:$e}
      ){sum{requests}}
    }}
  }`;

  const r = await fetch("https://api.cloudflare.com/client/v4/graphql",{
    method:"POST",
    headers:{
      "Authorization":"Bearer " + account.token,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      query,
      variables:{id:account.id,s:start.toISOString(),e:end.toISOString()}
    })
  });

  if (!r.ok) throw new Error(`账户${index}查询失败 HTTP ${r.status}`);
  const data = await r.json();
  if (data.errors?.length) throw new Error(`账户${index}查询失败：${data.errors[0].message}`);

  const rows = data?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
  const used = rows.reduce((n,x) => n + Number(x?.sum?.requests || 0), 0);

  return {
    index,
    id: String(account.id).slice(0,4) + "..." + String(account.id).slice(-4),
    used,
    remaining: Math.max(0, limit - used)
  };
}


async function handleVLESSWebSocket(request, uuid) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  // WebSocket 代理场景允许半关闭，避免运行时在一侧 EOF 时过早关闭另一侧。
  server.accept({ allowHalfOpen: true });
  server.binaryType = "arraybuffer";

  let remote = null;
  let remoteWriter = null;
  let remoteReader = null;
  let closed = false;
  let parsed = null;
  let headerBuffer = new Uint8Array(0);
  let connecting = null;

  const toBytes = data => {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || 0);
  };

  const safeClose = () => {
    if (closed) return;
    closed = true;
    try { remoteReader?.releaseLock(); } catch (_) {}
    remoteReader = null;
    try { remoteWriter?.releaseLock(); } catch (_) {}
    remoteWriter = null;
    try { remote?.close?.(); } catch (_) {}
    try {
      if (server.readyState === WebSocket.OPEN || server.readyState === WebSocket.CLOSING) {
        server.close();
      }
    } catch (_) {}
  };

  const wsSend = async data => {
    if (closed || server.readyState !== WebSocket.OPEN) return false;
    try {
      const payload = toBytes(data);
      if (payload.byteLength) server.send(payload);
      return true;
    } catch (e) {
      console.error("[VLESS WS] send failed:", e?.message || e);
      safeClose();
      return false;
    }
  };

  const waitOpened = async socket => {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("TCP connect timeout")), 10000)
      )
    ]);
  };

  const pumpRemoteToWS = async () => {
    if (!remote) return;
    try {
      remoteReader = remote.readable.getReader();
      while (!closed) {
        const { value, done } = await remoteReader.read();
        if (done) break;
        if (value?.byteLength) {
          if (!(await wsSend(value))) break;
        }
      }
    } catch (e) {
      if (!closed) console.error("[VLESS WS] remote read failed:", e?.message || e);
    } finally {
      try { remoteReader?.releaseLock(); } catch (_) {}
      remoteReader = null;
      if (!closed) safeClose();
    }
  };

  const connectRemote = async first => {
    if (connecting) return connecting;

    connecting = (async () => {
      try {
        remote = connect({
          hostname: first.host,
          port: first.port
        });

        await waitOpened(remote);

        if (closed) return;

        remoteWriter = remote.writable.getWriter();

        // VLESS response header = version + addons length.
        await wsSend(new Uint8Array([first.version, 0]));

        if (first.payload?.byteLength) {
          await remoteWriter.write(first.payload);
        }

        // Remote -> WebSocket must run independently of the client message handler.
        pumpRemoteToWS().catch(() => safeClose());
      } catch (e) {
        console.error("[VLESS WS] TCP connect failed:", first.host + ":" + first.port, e?.message || e);
        safeClose();
        throw e;
      } finally {
        connecting = null;
      }
    })();

    return connecting;
  };

  const consume = async data => {
    if (closed) return;

    const chunk = toBytes(data);
    if (!chunk.byteLength) return;

    // First WebSocket message(s): accumulate until the complete VLESS header exists.
    if (!parsed) {
      headerBuffer = mergeBytes(headerBuffer, chunk);

      const candidate = parseVLESSHeader(headerBuffer, uuid);

      if (!candidate) {
        // Do not close merely because one WebSocket frame contains only part of
        // the VLESS header. Give fragmented frames room to arrive.
        if (headerBuffer.byteLength < 4096) return;
        console.error("[VLESS WS] invalid/oversized VLESS header");
        safeClose();
        return;
      }

      parsed = candidate;
      headerBuffer = new Uint8Array(0);

      await connectRemote(parsed);
      return;
    }

    try {
      if (!remoteWriter) {
        if (!remote) throw new Error("remote socket unavailable");
        remoteWriter = remote.writable.getWriter();
      }
      await remoteWriter.write(chunk);
    } catch (e) {
      console.error("[VLESS WS] client -> remote failed:", e?.message || e);
      safeClose();
    }
  };

  // Keep event-driven WS handling, matching the original Worker architecture.
  server.addEventListener("message", event => {
    consume(event.data).catch(e => {
      console.error("[VLESS WS] message handling failed:", e?.message || e);
      safeClose();
    });
  });

  server.addEventListener("close", () => {
    safeClose();
  });

  server.addEventListener("error", event => {
    console.error("[VLESS WS] websocket error:", event?.error || event);
    safeClose();
  });

  // Support Xray/v2rayN WebSocket early-data. Literal "binary" is a
  // WebSocket subprotocol, not VLESS payload, so ignore it.
  const early = request.headers.get("sec-websocket-protocol") || "";
  if (early && early !== "binary") {
    try {
      const raw = early.replace(/-/g, "+").replace(/_/g, "/");
      const padded = raw + "=".repeat((4 - raw.length % 4) % 4);
      const bin = atob(padded);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      await consume(bytes);
    } catch (e) {
      console.error("[VLESS WS] early-data decode failed:", e?.message || e);
      safeClose();
    }
  }

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}
function mergeBytes(a, b) {
  const x = a instanceof Uint8Array ? a : new Uint8Array(a || 0);
  const y = b instanceof Uint8Array ? b : new Uint8Array(b || 0);
  const out = new Uint8Array(x.byteLength + y.byteLength);
  out.set(x, 0);
  out.set(y, x.byteLength);
  return out;
}

function parseVLESSHeader(data, expectedUUID) {
  if (!(data instanceof Uint8Array)) data = new Uint8Array(data || 0);
  if (data.length < 24 || data[0] !== 1) return null;

  const hex = String(expectedUUID).replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(hex)) return null;

  for (let i = 0; i < 16; i++) {
    if (data[1 + i] !== parseInt(hex.slice(i * 2, i * 2 + 2), 16)) return null;
  }

  const optLen = data[17];
  let p = 18 + optLen;
  if (p + 4 > data.length) return null;

  const cmd = data[p++];
  if (cmd !== 1 && cmd !== 2) return null;

  const port = (data[p] << 8) | data[p + 1];
  p += 2;

  const atype = data[p++];
  let host = "";

  if (atype === 1) {
    if (p + 4 > data.length) return null;
    host = Array.from(data.slice(p, p + 4)).join(".");
    p += 4;
  } else if (atype === 2) {
    if (p >= data.length) return null;
    const len = data[p++];
    if (p + len > data.length) return null;
    host = new TextDecoder().decode(data.slice(p, p + len));
    p += len;
  } else if (atype === 3) {
    if (p + 16 > data.length) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((data[p + i] << 8) | data[p + i + 1]).toString(16));
    }
    host = parts.join(":");
    p += 16;
  } else {
    return null;
  }

  if (!host || !port) return null;

  return {
    version: data[0],
    host,
    port,
    payload: data.slice(p)
  };
}
