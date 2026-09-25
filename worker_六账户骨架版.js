import { connect } from "cloudflare:sockets";

/* =========================
   基础工具
========================= */

function log(...args) {
  console.log(...args);
}

function toUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(
      data.buffer,
      data.byteOffset,
      data.byteLength
    );
  }
  return new Uint8Array(data);
}

function dataLength(data) {
  return data == null ? 0 : toUint8Array(data).byteLength;
}

function closeSocket(socket) {
  try {
    if (
      socket &&
      (socket.readyState === WebSocket.OPEN ||
        socket.readyState === WebSocket.CLOSING)
    ) {
      socket.close();
    }
  } catch {}
}

function formatIdentifier(arr, offset = 0) {
  const hex = [...arr.slice(offset, offset + 16)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return (
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20)
  );
}

/* =========================
   VLESS 请求解析
========================= */

function parseVLESSRequest(chunk, token) {
  if (chunk.byteLength < 24) {
    return {
      hasError: true,
      message: "Invalid data"
    };
  }

  const version = new Uint8Array(
    chunk.slice(0, 1)
  );

  const uuid = formatIdentifier(
    new Uint8Array(chunk.slice(1, 17))
  );

  if (uuid !== token) {
    return {
      hasError: true,
      message: "Invalid uuid"
    };
  }

  const optLen = new Uint8Array(
    chunk.slice(17, 18)
  )[0];

  const cmd = new Uint8Array(
    chunk.slice(18 + optLen, 19 + optLen)
  )[0];

  let isUDP = false;

  if (cmd === 1) {
    // TCP
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: "Invalid command"
    };
  }

  const portIdx = 19 + optLen;

  const port = new DataView(
    chunk.slice(portIdx, portIdx + 2)
  ).getUint16(0);

  let addrIdx = portIdx + 2;
  let addrLen = 0;

  let addrValIdx = addrIdx + 1;
  let hostname = "";

  const addressType = new Uint8Array(
    chunk.slice(addrIdx, addrValIdx)
  )[0];

  switch (addressType) {

    case 1:
      // IPv4
      addrLen = 4;

      hostname = new Uint8Array(
        chunk.slice(
          addrValIdx,
          addrValIdx + addrLen
        )
      ).join(".");

      break;

    case 2:
      // Domain
      addrLen = new Uint8Array(
        chunk.slice(
          addrValIdx,
          addrValIdx + 1
        )
      )[0];

      addrValIdx += 1;

      hostname = new TextDecoder().decode(
        chunk.slice(
          addrValIdx,
          addrValIdx + addrLen
        )
      );

      break;

    case 3:
      // IPv6
      addrLen = 16;

      const ipv6 = [];

      const ipv6View = new DataView(
        chunk.slice(
          addrValIdx,
          addrValIdx + addrLen
        )
      );

      for (let i = 0; i < 8; i++) {
        ipv6.push(
          ipv6View
            .getUint16(i * 2)
            .toString(16)
        );
      }

      hostname = ipv6.join(":");

      break;

    default:
      return {
        hasError: true,
        message:
          `Invalid address type: ${addressType}`
      };
  }

  if (!hostname) {
    return {
      hasError: true,
      message:
        `Invalid address: ${addressType}`
    };
  }

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

/* =========================
   TCP 连接
========================= */

async function forwardTCP(
  host,
  port,
  rawData,
  ws,
  responseHeader,
  wrapper
) {

  const connectDirect = async data => {

    const socket = connect({
      hostname: host,
      port
    });

    await Promise.race([
      socket.opened,

      new Promise((_, reject) => {
        setTimeout(
          () => reject(
            new Error("连接超时")
          ),
          1000
        );
      })
    ]);

    if (dataLength(data) > 0) {

      const writer =
        socket.writable.getWriter();

      try {
        await writer.write(
          toUint8Array(data)
        );
      } finally {
        writer.releaseLock();
      }
    }

    return socket;
  };

  const connectRemote = async sendFirst => {

    if (wrapper.connectingPromise) {
      return wrapper.connectingPromise;
    }

    wrapper.connectingPromise =
      (async () => {

        const socket =
          await connectDirect(
            sendFirst ? rawData : null
          );

        wrapper.socket = socket;

        socket.closed
          .catch(() => {})
          .finally(() => {
            closeSocket(ws);
          });

        await connectStreams(
          socket,
          ws,
          responseHeader,
          async () => {
            await connectRemote(false);
          }
        );

      })();

    try {
      await wrapper.connectingPromise;
    } finally {
      wrapper.connectingPromise = null;
    }
  };

  wrapper.retryConnect =
    () => connectRemote(false);

  try {

    await connectRemote(true);

  } catch (error) {

    log(
      "[TCP转发]",
      host,
      port,
      error?.message || error
    );

    closeSocket(ws);
  }
}

/* =========================
   TCP → WebSocket
========================= */

async function connectStreams(
  remoteSocket,
  ws,
  responseHeader,
  retry
) {

  let headerSent = false;

  try {

    const reader =
      remoteSocket.readable.getReader();

    try {

      while (true) {

        const {
          value,
          done
        } = await reader.read();

        if (done) break;

        if (!value) continue;

        const data =
          toUint8Array(value);

        if (!headerSent) {

          headerSent = true;

          const merged =
            new Uint8Array(
              responseHeader.byteLength +
              data.byteLength
            );

          merged.set(
            responseHeader,
            0
          );

          merged.set(
            data,
            responseHeader.byteLength
          );

          ws.send(merged);

        } else {

          ws.send(data);
        }
      }

    } finally {

      reader.releaseLock();
    }

  } catch (error) {

    log(
      "[TCP读取]",
      error?.message || error
    );

    try {
      if (retry) {
        await retry();
      }
    } catch {}
  }
}

/* =========================
   WebSocket / VLESS
========================= */

async function handleWebSocket(
  request,
  uuid
) {

  const [
    clientSocket,
    serverSocket
  ] = Object.values(
    new WebSocketPair()
  );

  serverSocket.accept();

  serverSocket.binaryType =
    "arraybuffer";

  const wrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null
  };

  let parsed = false;
  let closed = false;

  const readable =
    new ReadableStream({

      start(controller) {

        const push = data => {

          if (closed) return;

          try {
            controller.enqueue(data);
          } catch {
            closed = true;
          }
        };

        serverSocket.addEventListener(
          "message",
          event => {
            push(event.data);
          }
        );

        serverSocket.addEventListener(
          "close",
          () => {

            closed = true;

            try {
              controller.close();
            } catch {}

            closeSocket(
              serverSocket
            );
          }
        );

        serverSocket.addEventListener(
          "error",
          () => {
            closeSocket(
              serverSocket
            );
          }
        );

        /* 0-RTT */
        const earlyData =
          request.headers.get(
            "sec-websocket-protocol"
          );

        if (earlyData) {

          try {

            const raw =
              atob(
                earlyData
                  .replace(/-/g, "+")
                  .replace(/_/g, "/")
              );

            const bytes =
              new Uint8Array(
                raw.length
              );

            for (
              let i = 0;
              i < raw.length;
              i++
            ) {
              bytes[i] =
                raw.charCodeAt(i);
            }

            push(bytes.buffer);

          } catch {}
        }
      },

      cancel() {

        closed = true;

        closeSocket(
          serverSocket
        );
      }
    });

  readable.pipeTo(
    new WritableStream({

      async write(chunk) {

        if (!parsed) {

          const result =
            parseVLESSRequest(
              chunk,
              uuid
            );

          if (result.hasError) {
            throw new Error(
              result.message
            );
          }

          parsed = true;

          if (result.isUDP) {
            throw new Error(
              "UDP is not supported"
            );
          }

          const responseHeader =
            new Uint8Array([
              result.version[0],
              0
            ]);

          const rawData =
            chunk.slice(
              result.rawIndex
            );

          await forwardTCP(
            result.hostname,
            result.port,
            rawData,
            serverSocket,
            responseHeader,
            wrapper
          );

        } else if (
          wrapper.socket
        ) {

          const writer =
            wrapper.socket
              .writable
              .getWriter();

          try {

            await writer.write(
              toUint8Array(chunk)
            );

          } finally {

            writer.releaseLock();
          }
        }
      },

      close() {
        closeSocket(
          serverSocket
        );
      },

      abort() {
        closeSocket(
          serverSocket
        );
      }
    })
  ).catch(error => {

    log(
      "[WebSocket]",
      error?.message || error
    );

    closeSocket(
      serverSocket
    );
  });

  return new Response(
    null,
    {
      status: 101,
      webSocket: clientSocket
    }
  );
}

/* =========================
   MD5
   与原版 MD5MD5 保持一致
========================= */

async function MD5MD5(text) {

  const encoder =
    new TextEncoder();

  const first =
    await crypto.subtle.digest(
      "MD5",
      encoder.encode(text)
    );

  const firstHex =
    [...new Uint8Array(first)]
      .map(
        byte =>
          byte
            .toString(16)
            .padStart(2, "0")
      )
      .join("");

  const second =
    await crypto.subtle.digest(
      "MD5",
      encoder.encode(
        firstHex.slice(7, 27)
      )
    );

  return [...new Uint8Array(second)]
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("")
    .toLowerCase();
}

/* =========================
   Worker
========================= */

export default {

  async fetch(request, env) {

    const url =
      new URL(request.url);

    const host =
      (
        env.HOST ||
        url.hostname
      )
        .replace(/^https?:\/\//, "")
        .split("/")[0]
        .split(":")[0];

    /* UUID */
    let uuid =
      env.UUID ||
      env.uuid;

    /* 如果没有环境变量，
       尝试读取原版 config.json */
    if (!uuid && env.KV) {

      try {

        const config =
          JSON.parse(
            await env.KV.get(
              "config.json"
            ) || "{}"
          );

        uuid =
          config.UUID ||
          config.uuid;

      } catch {}
    }

    uuid =
      (
        uuid ||
        "00000000-0000-4000-8000-000000000000"
      ).toLowerCase();

    /* =====================
       VLESS WS
    ===================== */

    if (
      (
        request.headers.get(
          "Upgrade"
        ) || ""
      ).toLowerCase() ===
      "websocket"
    ) {

      return handleWebSocket(
        request,
        uuid
      );
    }

    /* =====================
       Health
    ===================== */

    if (
      url.pathname ===
      "/health"
    ) {

      return Response.json({
        ok: true
      });
    }

    /* =====================
       IP 保存
    ===================== */

    if (
      url.pathname ===
      "/admin/ADD.txt"
    ) {

      if (
        request.method ===
        "GET"
      ) {

        return new Response(
          await env.KV.get(
            "ADD.txt"
          ) || ""
        );
      }

      if (
        request.method ===
        "POST"
      ) {

        const text =
          await request.text();

        if (!text.trim()) {

          return Response.json(
            {
              success: false,
              error:
                "IP列表不能为空"
            },
            {
              status: 400
            }
          );
        }

        await env.KV.put(
          "ADD.txt",
          text
        );

        return Response.json({
          success: true
        });
      }
    }

    /* =====================
       订阅
    ===================== */

    if (
      url.pathname ===
      "/sub"
    ) {

      const token =
        await MD5MD5(
          host + uuid
        );

      if (
        url.searchParams.get(
          "token"
        ) !== token
      ) {

        return new Response(
          "Unauthorized",
          {
            status: 401
          }
        );
      }

      const ips =
        await env.KV.get(
          "ADD.txt"
        ) || "";

      const path =
        String(env.PATH || "/").startsWith("/")
          ? String(env.PATH || "/")
          : "/" + String(env.PATH || "/");

      const links =
        String(ips)
          .split(/[,，\s]+/)
          .map(ip => ip.trim())
          .filter(Boolean)
          .map(item => {

            let address = item;
            let remark = "";

            const hash = item.indexOf("#");
            if (hash >= 0) {
              address = item.slice(0, hash);
              try {
                remark = decodeURIComponent(item.slice(hash + 1));
              } catch {
                remark = item.slice(hash + 1);
              }
            }

            let ip = address;
            let port = "443";

            const match =
              address.match(/^\[([^\]]+)\]:(\d+)$/) ||
              address.match(/^([^:]+):(\d+)$/);

            if (match) {
              ip = match[1];
              port = match[2];
            }

            const query = new URLSearchParams();
            query.set("encryption", "none");
            query.set("security", "tls");
            query.set("sni", host);
            query.set("fp", "chrome");
            query.set("alpn", "http/1.1");
            query.set("type", "ws");
            query.set("host", host);
            query.set("path", path);

            return (
              `vless://${uuid}@${ip}:${port}?` +
              query.toString() +
              `#${encodeURIComponent(remark || ip + ":" + port)}`
            );
          });

      const body =
        links.join("\n");

      return new Response(
        btoa(
          unescape(
            encodeURIComponent(body)
          )
        ),
        {
          headers: {
            "content-type":
              "text/plain;charset=utf-8"
          }
        }
      );
    }

    /* =====================
       IP 管理页面
    ===================== */

    if (
      url.pathname === "/" ||
      url.pathname === "/admin"
    ) {

      const ips =
        await env.KV.get(
          "ADD.txt"
        ) || "";

      const token =
        await MD5MD5(
          host + uuid
        );

      const html = `<!doctype html>
<meta charset="utf-8">
<title>VLESS</title>

<textarea
 id="ips"
 style="width:100%;height:300px"
 placeholder="每行一个IP"
>${ips}</textarea>

<br>

<button onclick="save()">
保存IP
</button>

<button onclick="makeSub()">
生成订阅
</button>

<input
 id="sub"
 style="width:70%"
 readonly
>

<div id="msg"></div>

<script>

const el =
document.getElementById("ips");

const msg =
document.getElementById("msg");

let lastSaved = el.value;

async function save(){

  const text = el.value;

  if(!text.trim()){
    msg.textContent =
      "IP列表不能为空";
    return;
  }

  if(text === lastSaved){
    return;
  }

  try{

    const r =
      await fetch(
        "/admin/ADD.txt",
        {
          method:"POST",
          body:text
        }
      );

    const d =
      await r.json();

    if(
      !r.ok ||
      !d.success
    ){
      throw Error(
        d.error ||
        "保存失败"
      );
    }

    lastSaved = text;

    msg.textContent =
      "保存成功";

  }catch(e){

    msg.textContent =
      "保存失败：" +
      e.message;
  }
}

function makeSub(){

  const u =
    location.origin +
    "/sub?token=${token}";

  document.getElementById(
    "sub"
  ).value = u;

  navigator.clipboard
    ?.writeText(u)
    .catch(()=>{});

  msg.textContent =
    "订阅地址已生成";
}

</script>`;

      return new Response(
        html,
        {
          headers: {
            "content-type":
              "text/html;charset=utf-8"
          }
        }
      );
    }

    return new Response(
      "Not Found",
      {
        status: 404
      }
    );
  }
};