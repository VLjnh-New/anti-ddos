// Tiny backend so you can immediately test the proxy without setting up a real upstream.
import http from "node:http";
import { logger } from "./logger.js";

export function startDemoBackend(port: number) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><meta charset="utf-8">
<title>Demo Backend</title>
<style>body{font-family:system-ui;background:#fafafa;color:#222;
margin:0;min-height:100vh;display:grid;place-items:center}
.box{background:#fff;border:1px solid #e5e5e5;padding:30px 40px;
border-radius:14px;box-shadow:0 4px 18px rgba(0,0,0,.05);max-width:520px}
h1{margin:0 0 8px;font-size:20px}p{color:#666}
code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:13px}</style>
<div class="box">
<h1>🟢 Demo backend hoạt động</h1>
<p>Yêu cầu này đã đi qua <strong>Mini Shield</strong> rồi tới đây.</p>
<p>Bạn truy cập: <code>${req.url}</code></p>
<p style="font-size:12px;color:#999">User-Agent: ${(req.headers["user-agent"]||"").slice(0,80)}</p>
</div>`);
  });
  server.listen(port, "127.0.0.1", () => {
    logger.info(`🟢 Demo backend chạy trên http://127.0.0.1:${port}`);
  });
}
