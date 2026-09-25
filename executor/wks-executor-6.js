import { connect } from "cloudflare:sockets";

/**
 * EdgeTunnel Executor 6
 * 用途：部署在 Cloudflare 账户6，仅负责 VLESS + WebSocket -> TCP 双向转发。
 *
 * UUID 机制与账户1 EdgeTunnel 保持一致：
 *   1. 如果设置 UUID 环境变量且格式正确，优先使用 UUID。
 *   2. 如果没有 UUID，则使用 ADMIN/PASSWORD/TOKEN/KEY 等与账户1相同的密码来源，
 *      按账户1 wks.txt 的 MD5 规则生成 userID。
 *
 * 可选：
 *   EXECUTOR_SECRET = 额外的 HTTP Header 密钥；设置后客户端必须带
 *   X-Executor-Secret: <value>
 *
 * 注意：
 *   这是第一阶段测试版，只验证“账户6 Worker 能直接承载 VLESS WS 流量”。
 *   不包含管理后台、扫描、订阅、Usage。
 */

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "GET" && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      const secret = String(env.EXECUTOR_SECRET || "");
      if (secret && request.headers.get("X-Executor-Secret") !== secret) {
        return new Response("Forbidden", { status: 403 });
      }

      const uuid = await getExecutorUUID(env);
      if (!uuid) {
        return new Response("Executor UUID could not be derived. Configure UUID or the same password/KEY variables used by account 1.", { status: 500 });
      }

      return handleWebSocket(request, uuid);
    }

    if (url.pathname === "/health" || url.pathname === "/") {
      return new Response("EdgeTunnel Executor 6 OK", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" }
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

function isUUID(value) {
  return uuidRegex.test(value);
}

async function getExecutorUUID(env) {
  const configured = String(env.UUID || env.uuid || "").trim().toLowerCase();
  if (isUUID(configured)) return configured;

  // 与账户1 wks.txt 的管理员密码来源保持一致。
  const adminPassword =
    env.ADMIN || env.admin || env.PASSWORD || env.password ||
    env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;

  if (!adminPassword) return null;

  const secret = env.KEY || "勿动此默认密钥，有需求请自行通过添加变量KEY进行修改";
  const userIDMD5 = await md5Hex(String(adminPassword) + String(secret));

  // 与账户1完全相同的 UUID 拼接规则。
  return [
    userIDMD5.slice(0, 8),
    userIDMD5.slice(8, 12),
    "4" + userIDMD5.slice(13, 16),
    "8" + userIDMD5.slice(17, 20),
    userIDMD5.slice(20)
  ].join("-").toLowerCase();
}

async function md5Hex(value) {
  const encoder = new TextEncoder();

  // 与账户1 wks.txt 的 MD5MD5() 完全一致：
  // 第一次 MD5 -> 取十六进制字符串第 7~26 位 -> 第二次 MD5。
  const firstDigest = await crypto.subtle.digest("MD5", encoder.encode(value));
  const firstHex = Array.from(new Uint8Array(firstDigest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const secondInput = firstHex.slice(7, 27);
  const secondDigest = await crypto.subtle.digest("MD5", encoder.encode(secondInput));

  return Array.from(new Uint8Array(secondDigest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toLowerCase();
}

function uuidBytes(uuid) {
  const hex = uuid.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function decodeBase64Url(value) {
  if (!value) return null;
  try {
    let s = value.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

async function handleWebSocket(request, expectedUUID) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  server.accept();
  server.binaryType = "arraybuffer";

  const state = {
    buffer: new Uint8Array(0),
    socket: null,
    writer: null,
    closed: false,
    initialized: false
  };

  const closeAll = () => {
    if (state.closed) return;
    state.closed = true;
    try { state.writer?.releaseLock(); } catch {}
    state.writer = null;
    try { state.socket?.close(); } catch {}
    state.socket = null;
    try { server.close(); } catch {}
  };

  const early = request.headers.get("Sec-WebSocket-Protocol");
  if (early) {
    const first = decodeBase64Url(early.split(",")[0].trim());
    if (first && first.length) {
      try {
        await processData(first, state, server, expectedUUID);
      } catch {
        closeAll();
      }
    }
  }

  server.addEventListener("message", async event => {
    if (state.closed) return;
    try {
      const data = event.data instanceof ArrayBuffer
        ? new Uint8Array(event.data)
        : typeof event.data === "string"
          ? textEncoder.encode(event.data)
          : new Uint8Array(await event.data.arrayBuffer());
      await processData(data, state, server, expectedUUID);
    } catch {
      closeAll();
    }
  });

  server.addEventListener("close", closeAll);
  server.addEventListener("error", closeAll);

  return new Response(null, {
    status: 101,
    webSocket: client
  });
}

async function processData(data, state, ws, expectedUUID) {
  if (!data?.length || state.closed) return;

  if (!state.initialized) {
    state.buffer = concat(state.buffer, data);

    const parsed = parseVLESSHeader(state.buffer, expectedUUID);
    if (!parsed) {
      if (state.buffer.length > 64 * 1024) throw new Error("VLESS header too large");
      return;
    }

    state.initialized = true;
    state.buffer = parsed.remaining;

    const socket = await connectTarget(parsed.host, parsed.port);
    state.socket = socket;
    state.writer = socket.writable.getWriter();

    ws.send(new Uint8Array([parsed.version, 0, 0]));

    if (state.buffer.length) {
      await state.writer.write(state.buffer);
      state.buffer = new Uint8Array(0);
    }

    readRemote(socket, ws, state).catch(() => {
      try { ws.close(); } catch {}
    });

    return;
  }

  if (state.writer) {
    await state.writer.write(data);
  }
}

function parseVLESSHeader(data, expectedUUID) {
  if (data.length < 24) return null;

  const uuid = uuidBytes(expectedUUID);
  if (!equalBytes(data.subarray(1, 17), uuid)) {
    throw new Error("UUID mismatch");
  }

  const version = data[0];
  const addonsLength = data[17];
  const commandOffset = 18 + addonsLength;

  if (data.length < commandOffset + 4) return null;

  const command = data[commandOffset];
  if (command !== 1) {
    throw new Error("Only VLESS TCP command is supported by Executor 6");
  }

  const port = (data[commandOffset + 1] << 8) | data[commandOffset + 2];
  const addressType = data[commandOffset + 3];
  let p = commandOffset + 4;
  let host = "";

  if (addressType === 1) {
    if (data.length < p + 4) return null;
    host = Array.from(data.subarray(p, p + 4)).join(".");
    p += 4;
  } else if (addressType === 2) {
    if (data.length < p + 1) return null;
    const len = data[p++];
    if (data.length < p + len) return null;
    host = textDecoder.decode(data.subarray(p, p + len));
    p += len;
  } else if (addressType === 3) {
    if (data.length < p + 16) return null;
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((data[p + i] << 8) | data[p + i + 1]).toString(16));
    }
    host = parts.join(":");
    p += 16;
  } else {
    throw new Error("Unsupported VLESS address type");
  }

  return {
    version,
    host,
    port,
    remaining: data.subarray(p)
  };
}

async function connectTarget(host, port) {
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Invalid target");
  }

  if (typeof connect !== "function") {
    throw new Error("Cloudflare TCP connect API is unavailable");
  }

  return await connect({ hostname: host, port });
}

async function readRemote(socket, ws, state) {
  const reader = socket.readable.getReader();
  try {
    while (!state.closed) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value?.length) ws.send(value);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
    if (!state.closed) {
      state.closed = true;
      try { ws.close(); } catch {}
      try { socket.close(); } catch {}
    }
  }
}
