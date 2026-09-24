// Cloudflare 6-Account Quota + IP:Port + Subscription - skeleton v0.1
// KV binding: KV
// Secret: CF_ACCOUNTS_JSON = [{"id":"ACCOUNT_ID","token":"TOKEN"}, ... six accounts]
// Optional: CF_DAILY_LIMIT = "100000"

const NODES_KEY = "nodes.json";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (request.method === "GET" && path === "/") return page();
      if (request.method === "GET" && path === "/api/usage") return json(await usage(env));
      if (request.method === "GET" && path === "/api/nodes") return json(await nodes(env));
      if (request.method === "POST" && path === "/api/nodes") return json(await addNode(request, env));
      if (request.method === "DELETE" && path === "/api/nodes") return json(await deleteNode(request, env));
      if (request.method === "GET" && path === "/sub") {
        const list = (await nodes(env)).nodes;
        return new Response(list.map(x => `${x.ip}:${x.port}`).join("\n") + (list.length ? "\n" : ""), {
          headers: {"Content-Type":"text/plain; charset=utf-8"}
        });
      }
      if (request.method === "GET" && path === "/health") return json({ok:true, version:"0.1"});
      return new Response("Not Found", {status:404});
    } catch (e) {
      return json({success:false,error:e?.message || String(e)},500);
    }
  }
};

function json(x,status=200){
  return new Response(JSON.stringify(x,null,2),{
    status,
    headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"}
  });
}

async function nodes(env){
  let list=[];
  const raw=await env.KV.get(NODES_KEY);
  if(raw){try{list=JSON.parse(raw)}catch{}}
  if(!Array.isArray(list)) list=[];
  return {success:true,nodes:list};
}

async function addNode(request,env){
  const b=await request.json().catch(()=>({}));
  const port=String(b.port??"").trim();
  const raw=String(b.ips??b.ip??"");
  const ips=[...new Set(raw.split(/[\\n,，]+/).map(x=>x.trim()).filter(Boolean))];
  if(!ips.length) throw new Error("IP列表不能为空");
  if(!port) throw new Error("端口不能为空");
  if(!/^\\d+$/.test(port)||Number(port)<1||Number(port)>65535) throw new Error("端口必须是1-65535，但不会锁死为固定端口");
  const list=(await nodes(env)).nodes;
  for(const ip of ips){
    if(!list.some(x=>x.ip===ip&&String(x.port)===port)) list.push({ip,port});
  }
  await env.KV.put(NODES_KEY,JSON.stringify(list));
  return {success:true,added:ips.length,nodes:list};
}

async function deleteNode(request,env){
  const u=new URL(request.url),ip=u.searchParams.get("ip")||"",port=Number(u.searchParams.get("port"));
  const list=(await nodes(env)).nodes.filter(x=>!(x.ip===ip&&x.port===port));
  await env.KV.put(NODES_KEY,JSON.stringify(list));
  return {success:true,nodes:list};
}

function accounts(env){
  if(!env.CF_ACCOUNTS_JSON) throw new Error("未配置 CF_ACCOUNTS_JSON");
  let a;
  try{a=JSON.parse(env.CF_ACCOUNTS_JSON)}catch{throw new Error("CF_ACCOUNTS_JSON 不是有效JSON")}
  if(!Array.isArray(a)||a.length!==6) throw new Error("CF_ACCOUNTS_JSON 必须正好配置6个账户");
  a.forEach((x,i)=>{if(!x?.id||!x?.token) throw new Error(`第${i+1}个账户缺少id或token`)});
  return a;
}

async function usage(env){
  const list=accounts(env);
  const limit=Number(env.CF_DAILY_LIMIT||100000);
  if(!Number.isFinite(limit)||limit<=0) throw new Error("CF_DAILY_LIMIT 必须是正数");
  const now=new Date(),start=new Date(now);
  start.setUTCHours(0,0,0,0);

  const result=await Promise.all(list.map((a,i)=>accountUsage(a,i+1,start,now,limit)));
  const used=result.reduce((n,x)=>n+x.used,0);
  const total=limit*6;
  return {
    success:true,updatedAt:now.toISOString(),accountCount:6,
    dailyLimitPerAccount:limit,totalLimit:total,totalUsed:used,
    totalRemaining:Math.max(0,total-used),accounts:result
  };
}

async function accountUsage(a,index,start,now,limit){
  const query=`query($id:String!,$s:String!,$e:String!){
    viewer{accounts(filter:{accountTag:$id}){
      workersInvocationsAdaptive(
        limit:10000,
        filter:{datetime_geq:$s,datetime_leq:$e}
      ){sum{requests}}
    }}
  }`;

  const r=await fetch("https://api.cloudflare.com/client/v4/graphql",{
    method:"POST",
    headers:{
      "Authorization":`Bearer ${a.token}`,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({
      query,
      variables:{id:a.id,s:start.toISOString(),e:now.toISOString()}
    })
  });

  if(!r.ok) throw new Error(`账户${index}查询失败 HTTP ${r.status}`);
  const d=await r.json();
  if(d.errors?.length) throw new Error(`账户${index}查询失败：${d.errors[0].message}`);

  const rows=d?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive||[];
  const used=rows.reduce((n,x)=>n+Number(x?.sum?.requests||0),0);

  return {
    index,
    idMasked:String(a.id).slice(0,4)+"..."+String(a.id).slice(-4),
    used,
    remaining:Math.max(0,limit-used)
  };
}

function page(){
  return new Response(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>六账户额度 + IP/端口</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:900px;margin:30px auto;padding:0 16px;background:#f6f7f9;color:#222}
.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:18px;margin:14px 0}
h1{font-size:24px}button{padding:8px 14px;cursor:pointer}input,textarea{padding:10px;margin-right:8px;box-sizing:border-box}
textarea{width:100%;min-height:180px;resize:vertical;margin:8px 0 12px}
input{width:220px}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #eee;padding:8px;text-align:left}
.hint{color:#666;font-size:14px;margin:6px 0 12px}
</style>
</head>
<body>
<h1>六账户额度 + IP/端口</h1>

<div class="card">
<h2>六账户额度</h2>
<div id="usage">读取中...</div>
<button onclick="loadUsage()">刷新额度</button>
</div>

<div class="card">
<h2>IP列表 + 端口</h2>
<div class="hint">IP 一行一个，也支持逗号分隔；端口由你自己填写，不锁死固定端口。</div>
<form id="f">
<textarea id="ips" placeholder="例如：
1.2.3.4
5.6.7.8
8.8.8.8" required></textarea>
<input id="port" placeholder="端口，例如 443" inputmode="numeric" required>
<button>批量保存</button>
</form>
</div>

<div class="card">
<h2>节点列表</h2>
<div id="nodes">读取中...</div>
</div>

<div class="card">
<h2>订阅</h2>
<a id="sub" target="_blank"></a>
</div>

<script>
async function loadUsage(){
  const box=document.getElementById("usage");
  try{
    const d=await fetch("/api/usage").then(r=>r.json());
    if(!d.success) throw new Error(d.error||"读取失败");
    let h="<p>总额度："+d.totalLimit+"　已用："+d.totalUsed+"　剩余："+d.totalRemaining+"</p>";
    h+="<table><tr><th>账户</th><th>已用</th><th>剩余</th></tr>";
    for(const x of d.accounts) h+="<tr><td>#"+x.index+" "+x.idMasked+"</td><td>"+x.used+"</td><td>"+x.remaining+"</td></tr>";
    h+="</table>";
    box.innerHTML=h;
  }catch(e){box.textContent="错误："+e.message}
}
async function loadNodes(){
  const box=document.getElementById("nodes");
  try{
    const d=await fetch("/api/nodes").then(r=>r.json());
    if(!d.nodes.length){box.textContent="暂无节点";return}
    box.innerHTML=d.nodes.map(x=>"<div>"+x.ip+":"+x.port+
      ' <button onclick="delNode('+JSON.stringify(x.ip)+','+x.port+')">删除</button></div>').join("");
  }catch(e){box.textContent="错误："+e.message}
}
async function delNode(ip,p){
  await fetch("/api/nodes?ip="+encodeURIComponent(ip)+"&port="+p,{method:"DELETE"});
  loadNodes();
}
document.getElementById("f").onsubmit=async e=>{
  e.preventDefault();
  const r=await fetch("/api/nodes",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      ips:document.getElementById("ips").value,
      port:document.getElementById("port").value
    })});
  const d=await r.json();
  if(!d.success){alert(d.error||"保存失败");return;}
  alert("已保存 "+d.added+" 个IP");
  document.getElementById("f").reset();
  loadNodes();
};
const sub=new URL("/sub",location.href);
document.getElementById("sub").href=sub;
document.getElementById("sub").textContent=sub;
loadUsage();
loadNodes();
</script>
</body>
</html>`,{headers:{"Content-Type":"text/html; charset=utf-8"}});
}
