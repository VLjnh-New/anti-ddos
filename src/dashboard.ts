// Web dashboard: real-time stats, recent attacks, ban management.
// Two modes:
//   • startDashboard(cfg)  — own http.Server on cfg.dashboard.port
//   • buildDashboardApp(cfg, basePath) + attachDashboardWS(server, wsPath)
//     — mount inside another http server (combined-port hosting like Render)
import express from "express";
import http from "node:http";
import { WebSocketServer } from "ws";
import type { Config } from "./config.js";
import { state } from "./state.js";
import { logger } from "./logger.js";
import { dashboardHTML } from "./dashboardHtml.js";

function basicAuth(user: string, pass: string): express.RequestHandler {
  return (req, res, next) => {
    if (!user) return next();
    const hdr = req.headers.authorization || "";
    if (!hdr.startsWith("Basic ")) {
      res.set("WWW-Authenticate", 'Basic realm="Mini Shield"');
      return res.status(401).send("Unauthorized");
    }
    const [u, p] = Buffer.from(hdr.slice(6), "base64").toString().split(":");
    if (u !== user || p !== pass) {
      res.set("WWW-Authenticate", 'Basic realm="Mini Shield"');
      return res.status(401).send("Unauthorized");
    }
    next();
  };
}

export function buildDashboardApp(cfg: Config, basePath = ""): express.Application {
  const app = express();
  app.use(basicAuth(cfg.dashboard.username, cfg.dashboard.password));
  app.use(express.json());

  app.get("/", (_req, res) => {
    res.type("html").send(dashboardHTML(basePath));
  });

  app.get("/api/stats", (_req, res) => {
    res.json({
      ...state.stats,
      uptimeSec: Math.floor((Date.now() - state.stats.startedAt) / 1000),
      bannedCount: state.bannedIps.size,
      history: state.history,
    });
  });

  app.get("/api/recent", (_req, res) => {
    res.json(state.recent);
  });

  app.get("/api/banned", (_req, res) => {
    const list = [...state.bannedIps.entries()].map(([ip, e]) => ({
      ip,
      reason: e.reason,
      until: e.until,
      remainingSec: Math.max(0, Math.floor((e.until - Date.now()) / 1000)),
    }));
    res.json(list);
  });

  app.post("/api/unban", (req, res) => {
    const ip = String(req.body?.ip || "");
    if (!ip) return res.status(400).json({ ok: false, error: "missing ip" });
    state.unban(ip);
    logger.info(`Đã gỡ ban: ${ip}`);
    res.json({ ok: true });
  });

  app.post("/api/ban", (req, res) => {
    const ip = String(req.body?.ip || "");
    const minutes = Number(req.body?.minutes || 10);
    if (!ip) return res.status(400).json({ ok: false, error: "missing ip" });
    state.ban(ip, minutes * 60_000, "Thủ công từ dashboard");
    logger.info(`Đã ban thủ công: ${ip} (${minutes} phút)`);
    res.json({ ok: true });
  });

  app.get("/api/health", (_req, res) => res.json({ ok: true }));

  return app;
}

// Attach WebSocket broadcaster to an existing http.Server at the given path.
// Returns a cleanup function (rarely used; kept simple).
export function attachDashboardWS(server: http.Server, wsPath: string) {
  const wss = new WebSocketServer({ server, path: wsPath });

  state.on("attack", (ev) => {
    const msg = JSON.stringify({ type: "attack", data: ev });
    for (const c of wss.clients) {
      if (c.readyState === c.OPEN) c.send(msg);
    }
  });

  setInterval(() => {
    if (wss.clients.size === 0) return;
    const snapshot = JSON.stringify({
      type: "stats",
      data: {
        ...state.stats,
        uptimeSec: Math.floor((Date.now() - state.stats.startedAt) / 1000),
        bannedCount: state.bannedIps.size,
        history: state.history,
      },
    });
    for (const c of wss.clients) {
      if (c.readyState === c.OPEN) c.send(snapshot);
    }
  }, 1000);

  return wss;
}

// Standalone mode: own http server bound to its own port.
export function startDashboard(cfg: Config) {
  const app = buildDashboardApp(cfg, "");
  const server = http.createServer(app);
  attachDashboardWS(server, "/ws");
  server.listen(cfg.dashboard.port, "0.0.0.0", () => {
    logger.info(`📊 Dashboard: http://0.0.0.0:${cfg.dashboard.port}`);
  });
}
