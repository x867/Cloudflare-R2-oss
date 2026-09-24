import { connect } from "cloudflare:sockets";

// Cloudflare Worker：六账户额度 + IP:端口保存 + 订阅
// KV 绑定：KV
// Secret：CF_ACCOUNTS_JSON=[{"id":"ACCOUNT_ID","token":"TOKEN"},...共6个]
// 可选：CF_DAILY_LIMIT=100000

const KEY = "ADD.txt";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
      if (upgrade === "websocket") {
        const userID = await getSubscriptionUserID(env);
        return handleWebSocket(request, ctx, userID);
      }

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

      if (path === "/api/sub-token" && request.method === "GET") {
        const userID = await getSubscriptionUserID(env);
        const token = await MD5MD5(url.hostname + userID);
        return json({ success: true, token });
      }

      if (path === "/sub" && request.method === "GET") {
        return subscription(request, env, url);
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

async function getNodes(env) {
  if (!env.KV) throw new Error("KV绑定不存在，请确认绑定名称为 KV");
  const text = await env.KV.get(KEY) || "";
  return text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
}

async function MD5MD5(text) {
  const data = new TextEncoder().encode(String(text));
  const first = await crypto.subtle.digest("MD5", data);
  const firstHex = Array.from(new Uint8Array(first)).map(x => x.toString(16).padStart(2, "0")).join("");
  const second = await crypto.subtle.digest("MD5", new TextEncoder().encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(second)).map(x => x.toString(16).padStart(2, "0")).join("").toLowerCase();
}

function validUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ""));
}

async function getSubscriptionUserID(env) {
  const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid || "";
  const secretKey = env.KEY || "勿动此默认密钥，有需求请自行通过添加变量KEY进行修改";
  const envUUID = env.UUID || env.uuid;
  if (validUUID(envUUID)) return String(envUUID).toLowerCase();

  const userIDMD5 = await MD5MD5(adminPassword + secretKey);
  return [
    userIDMD5.slice(0, 8),
    userIDMD5.slice(8, 12),
    "4" + userIDMD5.slice(13, 16),
    "8" + userIDMD5.slice(17, 20),
    userIDMD5.slice(20)
  ].join("-");
}

function parseNode(node) {
  const raw = String(node || "").trim();
  if (!raw) return null;

  const hash = raw.indexOf("#");
  const base = hash >= 0 ? raw.slice(0, hash) : raw;
  const remark = hash >= 0 ? decodeURIComponent(raw.slice(hash + 1)) : "";

  let address = base;
  let port = "443";

  if (base.startsWith("[")) {
    const end = base.indexOf("]");
    if (end < 0) return null;
    address = base.slice(0, end + 1);
    if (base.slice(end + 1, end + 2) === ":") {
      port = base.slice(end + 2) || "443";
    }
  } else {
    const colon = base.lastIndexOf(":");
    if (colon > 0 && /^\d+$/.test(base.slice(colon + 1))) {
      address = base.slice(0, colon);
      port = base.slice(colon + 1);
    }
  }

  if (!address || !/^\d{1,5}$/.test(port)) return null;
  return { address, port, remark: remark || address };
}

async function subscription(request, env, url) {
  const userID = await getSubscriptionUserID(env);
  const subscriptionToken = await MD5MD5(url.hostname + userID);
  const suppliedToken = url.searchParams.get("token");

  if (suppliedToken && suppliedToken !== subscriptionToken) {
    return new Response("订阅TOKEN无效", {
      status: 403,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  if (!suppliedToken) {
    return new Response("缺少订阅TOKEN", {
      status: 403,
      headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const isBase64 = url.searchParams.has("b64") || url.searchParams.has("base64") || url.searchParams.get("target") === "base64";

  // 直接读取原版 Worker 留在同一个 KV 里的 config.json。
  // 这样订阅会沿用原版的 HOST、PATH、协议类型、Fingerprint 等关键参数，
  // 不再强制写死成“Worker 域名 + VLESS/WS + /”。
  let config = {};
  try {
    const saved = await env.KV.get("config.json");
    if (saved) config = JSON.parse(saved);
  } catch (e) {
    config = {};
  }

  // 与原版 Worker 保持一致：HOST 取环境变量或当前请求 hostname，
  // 不使用 config.json 里可能残留的旧 HOST。节点 IP 是连接地址，HOST 同时作为 TLS SNI/WS Host。
  const hostList = String(env.HOST || url.hostname)
    .split(/[,\\n\\r]+/)
    .map(h => h.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase())
    .filter(Boolean);
  const host = hostList[0] || url.hostname;

  // 当前 Worker 服务端实际实现的是 VLESS over WebSocket。
  // 订阅先严格使用同一协议，避免旧 config.json 中的 grpc/xhttp/ECH/0-RTT
  // 生成出服务端尚未实现的节点。
  const protocol = "vless";
  const transport = "ws";

  let pathValue = String(env.PATH || config.PATH || "/").trim();
  if (!pathValue.startsWith("/")) pathValue = "/" + pathValue;
  pathValue = pathValue.replace(/\/+$/, "") || "/";
  const fingerprint = String(config.Fingerprint || "chrome");
  const insecure = config.跳过证书验证 ? "&insecure=1&allowInsecure=1" : "";
  const list = await getNodes(env);

  const links = list.map(node => {
    const item = parseNode(node);
    if (!item) return null;

    const remark = encodeURIComponent(item.remark);
    const uuid = userID;

    if (protocol === "ss") {
      const method = String(config?.SS?.加密方式 || "aes-128-gcm");
      const tls = config?.SS?.TLS !== false;
      const pluginPath = pathValue;
      const plugin = "v2" + encodeURIComponent(
        "ray-plugin;mode=websocket;host=" + host +
        ";path=" + pluginPath +
        (tls ? ";tls" : "")
      );
      return "ss://" +
        btoa(method + ":" + uuid) +
        "@" + item.address + ":" + item.port +
        "?plugin=" + plugin + "#" + remark;
    }

    const nodePath = pathValue;

    // 固定为当前服务端已经实现的 VLESS/TLS/WebSocket。
    // 优选 IP 只作为连接地址；Host/SNI 使用 Worker 域名。
    return "vless://" + uuid + "@" + item.address + ":" + item.port +
      "?encryption=none&security=tls&type=ws" +
      "&host=" + encodeURIComponent(host) +
      "&sni=" + encodeURIComponent(host) +
      "&alpn=http%2F1.1" +
      "&fp=" + encodeURIComponent(fingerprint) +
      "&path=" + encodeURIComponent(nodePath) +
      insecure +
      "#" + remark;
  }).filter(Boolean);

  let content = links.join("\n");
  if (content) content += "\n";

  if (isBase64) {
    content = btoa(unescape(encodeURIComponent(content)));
  }

  const headers = {
    "Content-Type": "text/plain; charset=utf-8",
    "Profile-Update-Interval": String(config?.优选订阅生成?.SUBUpdateTime || 6),
    "Profile-web-page-url": url.protocol + "//" + url.host + "/admin",
    "Subscription-Userinfo": "upload=0; download=0; total=0; expire=4102329600",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
  };

  if (!ua.includes("mozilla")) {
    headers["Content-Disposition"] = "attachment; filename*=utf-8''subscription.txt";
  }

  return new Response(content, { headers });
}

function handleWebSocket(request, ctx, uuid) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  server.accept({ allowHalfOpen: true });
  server.binaryType = "arraybuffer";

  let remoteSocket = null;
  let remoteWriter = null;
  let closed = false;

  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { remoteWriter?.releaseLock(); } catch {}
    remoteWriter = null;
    try { remoteSocket?.close(); } catch {}
    remoteSocket = null;
    try { server.close(); } catch {}
  };

  const earlyData = decodeEarlyData(request.headers.get("sec-websocket-protocol") || "");
  const inputQueue = [];
  let inputWaiter = null;
  let inputClosed = false;

  const pushInput = data => {
    if (inputClosed) return;
    if (inputWaiter) {
      const resolve = inputWaiter;
      inputWaiter = null;
      resolve({ done: false, value: data });
    } else inputQueue.push(data);
  };

  const closeInput = () => {
    inputClosed = true;
    if (inputWaiter) {
      const resolve = inputWaiter;
      inputWaiter = null;
      resolve({ done: true });
    }
  };

  const nextInput = () => {
    if (inputQueue.length) return Promise.resolve({ done: false, value: inputQueue.shift() });
    if (inputClosed) return Promise.resolve({ done: true });
    return new Promise(resolve => { inputWaiter = resolve; });
  };

  if (earlyData) pushInput(earlyData);

  server.addEventListener("message", event => {
    try { pushInput(toUint8Array(event.data)); }
    catch { closeInput(); closeAll(); }
  });
  server.addEventListener("close", () => { closeInput(); closeAll(); });
  server.addEventListener("error", () => { closeInput(); closeAll(); });

  const pipePromise = (async () => {
    try {
      const first = await nextInput();
      if (first.done) return;

      const requestInfo = parseVLESS(first.value, uuid);
      if (requestInfo.error || requestInfo.command !== 1) {
        throw new Error(requestInfo.error || "Only VLESS TCP is supported");
      }

      remoteSocket = connect(
        { hostname: requestInfo.hostname, port: requestInfo.port },
        { allowHalfOpen: true }
      );
      await remoteSocket.opened;
      remoteWriter = remoteSocket.writable.getWriter();

      if (server.readyState === WebSocket.OPEN) {
        await sendWS(server, new Uint8Array([requestInfo.version, 0]));
      }

      if (requestInfo.rawData.byteLength) {
        await remoteWriter.write(requestInfo.rawData);
      }

      const remoteReader = remoteSocket.readable.getReader();
      const remoteToWebSocket = (async () => {
        try {
          while (!closed) {
            const { done, value } = await remoteReader.read();
            if (done) break;
            if (value?.byteLength && server.readyState === WebSocket.OPEN) {
              await sendWS(server, value);
            }
          }
        } finally {
          try { remoteReader.releaseLock(); } catch {}
        }
      })();

      while (true) {
        const item = await nextInput();
        if (item.done || !remoteWriter) break;
        if (item.value?.byteLength) await remoteWriter.write(item.value);
      }

      try { await remoteToWebSocket; } catch {}
    } catch {
      closeAll();
    } finally {
      try { remoteWriter?.releaseLock(); } catch {}
      remoteWriter = null;
      try { remoteSocket?.close(); } catch {}
      remoteSocket = null;
      closeInput();
      closeAll();
    }
  })();

  ctx.waitUntil(pipePromise);
  return new Response(null, { status: 101, webSocket: client });
}

async function sendWS(webSocket, data) {
  const result = webSocket.send(data);
  if (result && typeof result.then === "function") await result;
}

function parseVLESS(buffer, expectedUUID) {
  const data = toUint8Array(buffer);
  if (data.byteLength < 24) return { error: "Invalid VLESS request" };

  const version = data[0];
  const requestUUID = formatUUID(data.subarray(1, 17));
  if (requestUUID !== expectedUUID) return { error: "Invalid UUID" };

  const optionLength = data[17];
  const commandIndex = 18 + optionLength;
  if (data.byteLength < commandIndex + 1) return { error: "Invalid VLESS options" };

  const command = data[commandIndex];
  if (command !== 1 && command !== 2 && command !== 3) return { error: "Invalid VLESS command" };

  const portIndex = commandIndex + 1;
  if (data.byteLength < portIndex + 3) return { error: "Invalid VLESS address" };

  const port = (data[portIndex] << 8) | data[portIndex + 1];
  const addressType = data[portIndex + 2];
  let cursor = portIndex + 3;
  let hostname = "";

  if (addressType === 1) {
    if (data.byteLength < cursor + 4) return { error: "Invalid IPv4 address" };
    hostname = Array.from(data.subarray(cursor, cursor + 4)).join(".");
    cursor += 4;
  } else if (addressType === 2) {
    if (data.byteLength < cursor + 1) return { error: "Invalid domain length" };
    const length = data[cursor++];
    if (data.byteLength < cursor + length) return { error: "Invalid domain" };
    hostname = new TextDecoder().decode(data.subarray(cursor, cursor + length));
    cursor += length;
  } else if (addressType === 3) {
    if (data.byteLength < cursor + 16) return { error: "Invalid IPv6 address" };
    const view = new DataView(data.buffer, data.byteOffset + cursor, 16);
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(view.getUint16(i * 2).toString(16));
    hostname = parts.join(":");
    cursor += 16;
  } else {
    return { error: "Unsupported address type" };
  }

  if (!hostname || port < 1 || port > 65535) return { error: "Invalid destination" };
  return { error: null, version, command, hostname, port, rawData: data.slice(cursor) };
}

function formatUUID(bytes) {
  const hex = Array.from(bytes).map(byte => byte.toString(16).padStart(2, "0")).join("");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join("-");
}

function toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof Blob) throw new TypeError("Blob WebSocket frames are not supported");
  return new Uint8Array(data || 0);
}

function decodeEarlyData(value) {
  if (!value) return null;
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
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
<div id="msg" style="display:none"></div>
<hr>
<h3>订阅</h3>
<div style="display:flex;gap:8px;flex-wrap:wrap">
  <select id="subType">
    <option value="">VLESS 文本</option>
    <option value="?base64=1">Base64</option>
  </select>
  <button onclick="copySub()">复制订阅地址</button>
  <a id="subLink" href="/sub" target="_blank" style="padding:9px 18px">打开订阅</a>
</div>
<div id="subMsg" style="display:none;margin-top:10px"></div>
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
let subToken="";
function showSubMsg(text){
  const m=document.getElementById("subMsg");
  m.textContent=text;
  m.style.display="block";
  setTimeout(()=>m.style.display="none",2000);
}
async function getSubToken(){
  if(subToken)return subToken;
  try{
    const r=await fetch("/api/sub-token?_="+Date.now());
    const d=await r.json();
    if(!r.ok||!d.success)throw Error(d.error||"获取TOKEN失败");
    subToken=d.token;
    return subToken;
  }catch(e){
    showSubMsg("获取订阅TOKEN失败："+e.message);
    return "";
  }
}
function subURL(){
  const q=document.getElementById("subType").value;
  const sep=q ? "&" : "?";
  return location.origin+"/sub"+q+sep+"token="+encodeURIComponent(subToken);
}
async function copySub(){
  if(!await getSubToken())return;
  const u=subURL();
  try{
    await navigator.clipboard.writeText(u);
    showSubMsg("订阅地址已复制");
  }catch(e){
    prompt("复制订阅地址：",u);
  }
}
async function updateSubLink(){
  if(!await getSubToken())return;
  document.getElementById("subLink").href=subURL();
}
document.getElementById("subType").addEventListener("change",updateSubLink);
updateSubLink();
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
