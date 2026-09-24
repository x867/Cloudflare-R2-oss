// Cloudflare Worker：六账户额度 + IP:端口保存 + 订阅
// KV 绑定：KV
// Secret：CF_ACCOUNTS_JSON=[{"id":"ACCOUNT_ID","token":"TOKEN"},...共6个]
// 可选：CF_DAILY_LIMIT=100000

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

function getUUID(env) {
  const uuid = String(env.UUID || env.uuid || "").trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error("未配置有效 UUID，请设置 Worker 环境变量 UUID");
  }
  return uuid;
}

async function md5md5(text) {
  const encoder = new TextEncoder();
  const first = await crypto.subtle.digest("MD5", encoder.encode(text));
  const firstHex = Array.from(new Uint8Array(first)).map(x => x.toString(16).padStart(2, "0")).join("");
  const second = await crypto.subtle.digest("MD5", encoder.encode(firstHex.slice(7, 27)));
  return Array.from(new Uint8Array(second)).map(x => x.toString(16).padStart(2, "0")).join("").toLowerCase();
}

function makeVLESS(uuid, node, host) {
  let address = node;
  let port = "443";
  let remark = node;
  const m = node.match(/^(\[[0-9a-fA-F:]+\]|[\\d.]+|[a-zA-Z0-9.-]+)(?::(\\d+))?(?:#(.+))?$/);
  if (!m) return null;
  address = m[1];
  port = m[2] || "443";
  remark = m[3] || address;
  const path = "/";
  return `vless://${uuid}@${address}:${port}?encryption=none&security=tls&type=ws&host=${encodeURIComponent(host)}&sni=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`;
}

async function subscription(request, env, url) {
  const uuid = getUUID(env);
  const token = await md5md5(url.hostname + uuid);
  const supplied = url.searchParams.get("token");
  if (supplied && supplied !== token) {
    return new Response("订阅TOKEN无效", { status: 403, headers: { "Cache-Control": "no-store" } });
  }
  const list = await getNodes(env);
  const links = list.map(node => makeVLESS(uuid, node, url.hostname)).filter(Boolean);
  let content = links.join("\n") + (links.length ? "\n" : "");
  const wantBase64 = url.searchParams.has("b64") || url.searchParams.has("base64") || url.searchParams.get("target") === "base64";
  if (wantBase64) content = btoa(unescape(encodeURIComponent(content)));
  return new Response(content, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo": "upload=0; download=0; total=0; expire=4102329600"
    }
  });
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
async function copySub(){
  const q=document.getElementById("subType").value;
  const u=location.origin+"/sub"+q;
  try{
    await navigator.clipboard.writeText(u);
    const m=document.getElementById("subMsg");
    m.textContent="订阅地址已复制";
    m.style.display="block";
    setTimeout(()=>m.style.display="none",2000);
  }catch(e){
    prompt("复制订阅地址：",u);
  }
}
function updateSubLink(){
  const q=document.getElementById("subType").value;
  document.getElementById("subLink").href="/sub"+q;
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
