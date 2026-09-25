import { connect } from "cloudflare:sockets";

function log(...args) {
  console.log(...args);
}

function toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

function dataLength(data) {
  return data == null ? 0 : toUint8Array(data).byteLength;
}

function closeSocket(socket) {
  try {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING)) {
      socket.close();
    }
  } catch {}
}

function formatIdentifier(arr, offset = 0) {
  const hex = [...arr.slice(offset, offset + 16)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return (
    hex.slice(0, 8) + "-" +
    hex.slice(8, 12) + "-" +
    hex.slice(12, 16) + "-" +
    hex.slice(16, 20) + "-" +
    hex.slice(20)
  );
}

function parseVLESSRequest(chunk, token) {
  if (chunk.byteLength < 24) return { hasError: true, message: "Invalid data" };

  const version = new Uint8Array(chunk.slice(0, 1));
  const uuid = formatIdentifier(new Uint8Array(chunk.slice(1, 17)));

  if (uuid !== token) return { hasError: true, message: "Invalid uuid" };

  const optLen = new Uint8Array(chunk.slice(17, 18))[0];
  const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];

  let isUDP = false;
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: "Invalid command" };
  }

  const portIdx = 19 + optLen;
  const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
  let addrIdx = portIdx + 2;
  let addrLen = 0;
  let addrValIdx = addrIdx + 1;
  let hostname = "";

  const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];

  switch (addressType) {
    case 1:
      addrLen = 4;
      hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join(".");
      break;
    case 2:
      addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0];
      addrValIdx += 1;
      hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
      break;
    case 3:
      addrLen = 16;
      const ipv6 = [];
      const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
      for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
      hostname = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: `Invalid address type: ${addressType}` };
  }

  if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };

  return {
    hasError: false,
    addressType,
    port,
    hostname,
    isUDP,
    rawIndex: addrValIdx + addrLen,
    version
  };
}

async function forwardTCP(host, port, rawData, ws, responseHeader, wrapper) {
  log("[TCP] connect start", host, port, "firstDataBytes", dataLength(rawData));

  const connectDirect = async data => {
    const socket = connect({ hostname: host, port });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error("连接超时")), 1000))
    ]);

    log("[TCP] connect opened", host, port);

    if (dataLength(data) > 0) {
      const writer = socket.writable.getWriter();
      try {
        await writer.write(toUint8Array(data));
      } finally {
        writer.releaseLock();
      }
    }
    return socket;
  };

  const connectRemote = async sendFirst => {
    if (wrapper.connectingPromise) return wrapper.connectingPromise;

    wrapper.connectingPromise = (async () => {
      const socket = await connectDirect(sendFirst ? rawData : null);
      wrapper.socket = socket;

      socket.closed.catch(() => {}).finally(() => closeSocket(ws));

      await connectStreams(socket, ws, responseHeader, async () => {
        await connectRemote(false);
      });
    })();

    try {
      await wrapper.connectingPromise;
    } finally {
      wrapper.connectingPromise = null;
    }
  };

  wrapper.retryConnect = () => connectRemote(false);

  try {
    await connectRemote(true);
  } catch (error) {
    log("[TCP转发]", host, port, error?.message || error);
    closeSocket(ws);
  }
}

async function connectStreams(remoteSocket, ws, responseHeader, retry) {
  let headerSent = false;
  try {
    const reader = remoteSocket.readable.getReader();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!value) continue;

        const data = toUint8Array(value);
        if (!headerSent) {
          headerSent = true;
          const merged = new Uint8Array(responseHeader.byteLength + data.byteLength);
          merged.set(responseHeader, 0);
          merged.set(data, responseHeader.byteLength);
          ws.send(merged);
        } else {
          ws.send(data);
        }
      }
    } finally {
      reader.releaseLock();
    }
  } catch (error) {
    log("[TCP读取]", error?.message || error);
    try {
      if (retry) await retry();
    } catch {}
  }
}

async function handleWebSocket(request, uuid) {
  const requestId = crypto.randomUUID();
  log("[WS]", requestId, "received", request.url);

  const [clientSocket, serverSocket] = Object.values(new WebSocketPair());
  serverSocket.accept();
  log("[WS]", requestId, "accepted");
  serverSocket.binaryType = "arraybuffer";

  const wrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null
  };

  let parsed = false;
  let closed = false;

  const readable = new ReadableStream({
    start(controller) {
      const push = data => {
        if (closed) return;
        log("[WS]", requestId, "message", dataLength(data), "bytes");
        try {
          controller.enqueue(data);
        } catch {
          closed = true;
        }
      };

      serverSocket.addEventListener("message", event => push(event.data));
      serverSocket.addEventListener("close", event => {
        log("[WS]", requestId, "closed", event?.code, event?.reason || "");
        closed = true;
        try { controller.close(); } catch {}
        closeSocket(serverSocket);
      });
      serverSocket.addEventListener("error", event => {
        log("[WS]", requestId, "error", event?.message || "websocket error");
        closeSocket(serverSocket);
      });

      const earlyData = request.headers.get("sec-websocket-protocol");
      if (earlyData) {
        try {
          const raw = atob(earlyData.replace(/-/g, "+").replace(/_/g, "/"));
          const bytes = new Uint8Array(raw.length);
          for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
          push(bytes.buffer);
        } catch {}
      }
    },
    cancel() {
      closed = true;
      closeSocket(serverSocket);
    }
  });

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (!parsed) {
        log("[VLESS]", requestId, "first packet", dataLength(chunk), "bytes");
        const result = parseVLESSRequest(chunk, uuid);

        if (result.hasError) {
          log("[VLESS]", requestId, "parse failed", result.message);
          throw new Error(result.message);
        }

        log("[VLESS]", requestId, "parsed", result.hostname, result.port, "udp", result.isUDP);
        parsed = true;

        if (result.isUDP) {
          log("[VLESS]", requestId, "UDP rejected");
          throw new Error("UDP is not supported");
        }

        const responseHeader = new Uint8Array([result.version[0], 0]);
        const rawData = chunk.slice(result.rawIndex);

        log("[VLESS]", requestId, "forward start", result.hostname, result.port);
        await forwardTCP(
          result.hostname,
          result.port,
          rawData,
          serverSocket,
          responseHeader,
          wrapper
        );
        log("[VLESS]", requestId, "forward finished");
      } else if (wrapper.socket) {
        const writer = wrapper.socket.writable.getWriter();
        try {
          await writer.write(toUint8Array(chunk));
        } finally {
          writer.releaseLock();
        }
      }
    },
    close() {
      closeSocket(serverSocket);
    },
    abort() {
      closeSocket(serverSocket);
    }
  })).catch(error => {
    log("[WebSocket]", requestId, "pipeline error", error?.message || error);
    closeSocket(serverSocket);
  });

  return new Response(null, {
    status: 101,
    webSocket: clientSocket
  });
}

async function MD5MD5(text) {
  const encoder = new TextEncoder();

  const first = await crypto.subtle.digest("MD5", encoder.encode(text));
  const firstHex = [...new Uint8Array(first)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const second = await crypto.subtle.digest(
    "MD5",
    encoder.encode(firstHex.slice(7, 27))
  );

  return [...new Uint8Array(second)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("")
    .toLowerCase();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const host = (env.HOST || "x.x83870.workers.dev")
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split(":")[0];

    /*
     * UUID：只根据账号身份 + KEY 自动生成。
     * 不再读取 env.UUID / env.uuid，避免 Cloudflare 中旧 UUID 覆盖新生成值。
     * SNI/Host 仍独立使用当前 Worker 域名。
     */
    const 管理员密码 =
      env.ADMIN ||
      env.admin ||
      env.PASSWORD ||
      env.password ||
      env.pswd ||
      env.TOKEN ||
      env.KEY ||
      "";

    const 加密秘钥 =
      env.KEY ||
      "勿动此默认密钥，有需求请自行通过添加变量KEY进行修改";

    const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);

    const uuid = [
      userIDMD5.slice(0, 8),
      userIDMD5.slice(8, 12),
      "4" + userIDMD5.slice(13, 16),
      "8" + userIDMD5.slice(17, 20),
      userIDMD5.slice(20)
    ].join("-");

    const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();

    if (upgrade === "websocket") {
      log("[FETCH] websocket upgrade", request.url);
      return handleWebSocket(request, uuid);
    }

    if (url.pathname === "/health") {
      return Response.json({ ok: true });
    }

    if (url.pathname === "/sub") {
      const targetIP = env.IP || "172.64.229.0";
      const path = String(env.PATH || "/").startsWith("/")
        ? String(env.PATH || "/")
        : "/" + String(env.PATH || "/");

      const query = new URLSearchParams();
      query.set("encryption", "none");
      query.set("security", "tls");
      query.set("sni", host);
      query.set("fp", "chrome");
      query.set("alpn", "http/1.1");
      query.set("type", "ws");
      query.set("host", host);
      query.set("path", path);

      const link =
        `vless://${uuid}@${targetIP}:443?` +
        query.toString() +
        `#${encodeURIComponent(targetIP)}`;

      return new Response(link, {
        headers: { "content-type": "text/plain;charset=utf-8" }
      });
    }

    if (url.pathname === "/" || url.pathname === "/admin") {
      const targetIP = env.IP || "172.64.229.0";
      const path = String(env.PATH || "/").startsWith("/")
        ? String(env.PATH || "/")
        : "/" + String(env.PATH || "/");

      const query = new URLSearchParams();
      query.set("encryption", "none");
      query.set("security", "tls");
      query.set("sni", host);
      query.set("fp", "chrome");
      query.set("alpn", "http/1.1");
      query.set("type", "ws");
      query.set("host", host);
      query.set("path", path);

      const link =
        `vless://${uuid}@${targetIP}:443?` +
        query.toString() +
        `#${encodeURIComponent(targetIP)}`;

      const html = `<!doctype html>
<meta charset="utf-8">
<title>VLESS</title>
<h3>VLESS 单节点配置</h3>
<textarea id="config" style="width:100%;height:120px" readonly>${link}</textarea>
<br><br>
<button onclick="copyConfig()">复制配置</button>
<div id="msg"></div>
<script>
function copyConfig(){
  const v=document.getElementById("config").value;
  navigator.clipboard?.writeText(v).then(()=>{
    document.getElementById("msg").textContent="已复制";
  }).catch(()=>{
    document.getElementById("config").select();
    document.getElementById("msg").textContent="请手动复制";
  });
}
</script>`;

      return new Response(html, {
        headers: { "content-type": "text/html;charset=utf-8" }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};