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
      if (request.method === "POST" && path === "/api/nodes") {
        const contentType=(request.headers.get("content-type")||"").toLowerCase();
        if(contentType.includes("application/json")){
          const b=await request.json().catch(()=>({}));
          const lines=String(b.ips??b.ip??"").trim();
          const port=String(b.port??"").trim();
          if(!lines) throw new Error("IP列表不能为空");
          if(!port) throw new Error("端口不能为空");
          const ips=lines.split(/\r?\n|[,，]+/).map(x=>x.trim()).filter(Boolean);
          const value=ips.map(ip=>ip.includes(":")?ip:ip+":"+port).join("\n");
          const fake=new Request(request.url,{method:"POST",body:value});
          return json(await addNode(fake,env));
        }
        return json(await addNode(request,env));
      }
      if (request.method === "DELETE" && path === "/api/nodes") return json(await deleteNode(request, env));
      if (request.method === "POST" && path === "/admin/ADD.txt") {
        return json(await addNode(request, env));
      }
      if (request.method === "GET" && path === "/admin/ADD.txt") {
        const raw=await env.KV.get("ADD.txt") || "";
        return new Response(raw,{headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"}});
      }
      if (request.method === "GET" && path === "/sub") {
        const list = (await nodes(env)).nodes;
        return new Response(list.join("\n") + (list.length ? "\n" : ""), {
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
  if(!env.KV) throw new Error("KV绑定不存在，请确认绑定名称为 KV");
  const raw=await env.KV.get("ADD.txt") || "";
  const list=raw.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  return {success:true,nodes:list};
}

async function addNode(request,env){
  if(!env.KV) throw new Error("KV绑定不存在，请确认绑定名称为 KV");

  // 与原文件保持一致：直接保存文本到 KV 的 ADD.txt。
  const text=await request.text();
  const value=String(text||"").trim();

  if(!value) throw new Error("IP列表不能为空");

  await env.KV.put("ADD.txt",value);

  return {
    success:true,
    message:"自定义IP已保存",
    nodes:value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)
  };
}

async function deleteNode(request,env){
  if(!env.KV) throw new Error("KV绑定不存在，请确认绑定名称为 KV");

  const u=new URL(request.url);
  const target=(u.searchParams.get("node")||"").trim();
  const raw=await env.KV.get("ADD.txt") || "";

  const list=raw.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  const next=list.filter(x=>x!==target);

  await env.KV.put("ADD.txt",next.join("\n"));
  return {success:true,nodes:next};
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
  return new Response(\`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>自定义优选</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;
  min-height:100vh;
  background:#f5f7fa;
  color:#303133;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Arial,sans-serif;
}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 40px}
h1{font-size:24px;font-weight:600;margin:0 0 18px}
.card{
  background:#fff;border:1px solid #ebeef5;border-radius:8px;
  box-shadow:0 2px 12px rgba(0,0,0,.04);padding:20px;margin-bottom:18px
}
h2{font-size:20px;font-weight:500;margin:0 0 14px}
.editor{
  display:flex;width:100%;height:360px;border:1px solid #dcdfe6;
  border-radius:6px;overflow:hidden;background:#fff
}
.lines{
  width:48px;flex:0 0 48px;padding:10px 8px 10px 0;
  background:#f7f8fa;color:#a8abb2;text-align:right;font:14px/22px Consolas,Monaco,monospace;
  user-select:none;overflow:hidden
}
#ips{
  flex:1;border:0;outline:0;resize:none;padding:10px 12px;
  margin:0;color:#303133;background:#fff;
  font:14px/22px Consolas,Monaco,"Microsoft YaHei",monospace;
  white-space:pre;overflow:auto
}
#ips::placeholder{color:#c0c4cc}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}
button{
  min-width:88px;height:36px;padding:0 18px;border:1px solid #dcdfe6;
  border-radius:4px;background:#fff;color:#606266;cursor:pointer;font-size:14px
}
button:hover{border-color:#409eff;color:#409eff}
.primary{background:#409eff;border-color:#409eff;color:#fff}
.primary:hover{background:#66b1ff;border-color:#66b1ff;color:#fff}
.danger{color:#f56c6c}
.hint{font-size:13px;color:#909399;margin-top:10px}
#usage{line-height:1.8}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{border-bottom:1px solid #ebeef5;padding:9px;text-align:left;font-size:14px}
#nodes{max-height:240px;overflow:auto}
.node-row{padding:7px 0;border-bottom:1px solid #f0f0f0;font-family:Consolas,monospace}
.node-row button{min-width:auto;height:30px;padding:0 10px;margin-left:8px}
.subbox{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.subbox input{flex:1;min-width:260px;height:36px;border:1px solid #dcdfe6;border-radius:4px;padding:0 10px;color:#606266}
.small{font-size:12px;color:#909399}
</style>
</head>
<body>
<div class="wrap">

  <div class="card">
    <h1>自定义优选</h1>

    <div class="editor">
      <div id="lines" class="lines">1</div>
      <textarea id="ips" spellcheck="false" placeholder="172.64.229.0:443
172.64.229.1:443
172.64.229.2:443
172.64.229.3:443"></textarea>
    </div>

    <div class="actions">
      <button type="button" class="primary" onclick="startOptimize()">开始优选</button>
      <button type="button" onclick="showSubscription()">订阅接口</button>
      <button type="button" onclick="chainProxy()">链式代理</button>
      <button type="button" class="danger" onclick="cancelEdit()">取消</button>
      <button type="button" class="primary" onclick="saveIPs()">保存</button>
    </div>
    <div class="hint">一行一个完整节点，格式为 IP:端口。端口不锁死，按你填写的端口保存到原来的 ADD.txt。</div>
  </div>

  <div class="card">
    <h2>六账户额度</h2>
    <div id="usage">读取中...</div>
    <div class="actions"><button type="button" onclick="loadUsage()">刷新额度</button></div>
  </div>

  <div class="card">
    <h2>已保存 IP</h2>
    <div id="nodes">读取中...</div>
  </div>

</div>

<script>
let lastSaved = "";

function updateLines(){
  const ta=document.getElementById("ips");
  const count=Math.max(1,ta.value.split("\\n").length);
  document.getElementById("lines").textContent=
    Array.from({length:count},(_,i)=>i+1).join("\\n");
  document.getElementById("lines").scrollTop=ta.scrollTop;
}
document.getElementById("ips").addEventListener("input",updateLines);
document.getElementById("ips").addEventListener("scroll",()=>{
  document.getElementById("lines").scrollTop=document.getElementById("ips").scrollTop;
});

async function loadIPs(){
  const r=await fetch("/admin/ADD.txt",{cache:"no-store"});
  if(!r.ok) throw new Error("读取IP列表失败");
  lastSaved=await r.text();
  document.getElementById("ips").value=lastSaved;
  updateLines();
}

async function saveIPs(){
  const value=document.getElementById("ips").value.trim();
  if(!value){alert("IP列表不能为空");return;}
  try{
    const r=await fetch("/admin/ADD.txt",{
      method:"POST",
      headers:{"Content-Type":"text/plain;charset=utf-8"},
      body:value
    });
    const d=await r.json();
    if(!r.ok||!d.success) throw new Error(d.error||"保存失败");
    lastSaved=value;
    await loadNodes();
    alert("保存成功");
  }catch(e){alert("保存失败："+e.message);}
}

function cancelEdit(){
  document.getElementById("ips").value=lastSaved;
  updateLines();
}

function showSubscription(){
  const u=new URL("/sub",location.href).href;
  window.open(u,"_blank");
}

function startOptimize(){
  alert("骨架版暂未接入优选扫描，当前按钮保留原界面；IP列表保存功能已接入 ADD.txt。");
}

function chainProxy(){
  alert("骨架版暂未接入链式代理，当前按钮保留原界面。");
}

async function loadNodes(){
  const box=document.getElementById("nodes");
  try{
    const r=await fetch("/admin/ADD.txt",{cache:"no-store"});
    const text=await r.text();
    const list=text.split(/\\r?\\n/).map(x=>x.trim()).filter(Boolean);
    box._nodes=list;
    if(!list.length){box.textContent="暂无保存的IP";return;}
    box.innerHTML=list.map((x,i)=>
      "<div class='node-row'>"+escapeHtml(x)+
      " <button type='button' onclick='delNode("+i+")'>删除</button></div>"
    ).join("");
  }catch(e){box.textContent="错误："+e.message;}
}

function escapeHtml(s){
  return String(s).replace(/[&<>\"']/g,ch=>({
    "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
  }[ch]));
}

async function delNode(index){
  const list=document.getElementById("nodes")._nodes||[];
  const target=list[index];
  if(!target)return;
  try{
    const r=await fetch("/api/nodes?node="+encodeURIComponent(target),{method:"DELETE"});
    const d=await r.json();
    if(!r.ok||!d.success)throw new Error(d.error||"删除失败");
    await loadIPs();
    await loadNodes();
  }catch(e){alert("删除失败："+e.message);}
}

async function loadUsage(){
  const box=document.getElementById("usage");
  try{
    const d=await fetch("/api/usage",{cache:"no-store"}).then(r=>r.json());
    if(!d.success) throw new Error(d.error||"读取失败");
    let h="<p>总额度："+d.totalLimit+"　已用："+d.totalUsed+"　剩余："+d.totalRemaining+"</p>";
    h+="<table><tr><th>账户</th><th>已用</th><th>剩余</th></tr>";
    for(const x of d.accounts)
      h+="<tr><td>#"+x.index+" "+x.idMasked+"</td><td>"+x.used+"</td><td>"+x.remaining+"</td></tr>";
    h+="</table>";
    box.innerHTML=h;
  }catch(e){box.textContent="错误："+e.message;}
}

(async()=>{
  try{await loadIPs();}catch(e){document.getElementById("ips").value="";updateLines();}
  loadNodes();
  loadUsage();
})();
</script>
</body>
</html>\`,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}});
}

