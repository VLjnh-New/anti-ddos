// Mini Shield — Entry point
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, type Config } from "./config.js";
import { logger, setLogLevel } from "./logger.js";
import { startProxy } from "./proxy.js";
import { startDashboard, buildDashboardApp } from "./dashboard.js";
import { startStatsTicker } from "./state.js";
import { startDemoBackend } from "./demoBackend.js";

function parseArgs(): { config: string } {
  const args = process.argv.slice(2);
  let cfg = "config.yaml";
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === "-c" || args[i] === "--config") && args[i + 1]) {
      cfg = args[++i];
    } else if (args[i] === "--help" || args[i] === "-h") {
      console.log("Mini Shield — Anti-DDoS reverse proxy");
      console.log("Usage: mini-shield [-c|--config <file>]");
      console.log("");
      console.log("Environment overrides:");
      console.log("  PORT                  Combined mode: dashboard + proxy on same port");
      console.log("  PROXY_UPSTREAM        Override upstream URL");
      console.log("  DASHBOARD_USERNAME    Basic-auth user for dashboard");
      console.log("  DASHBOARD_PASSWORD    Basic-auth password for dashboard");
      console.log("  DASHBOARD_BASE_PATH   URL prefix in combined mode (default /__shield)");
      process.exit(0);
    }
  }
  return { config: cfg };
}

function banner() {
  console.log(`
  ╔══════════════════════════════════════╗
  ║         🛡️  MINI SHIELD v1.0         ║
  ║   Lightweight L7 Anti-DDoS · WAF    ║
  ╚══════════════════════════════════════╝
`);
}

// Apply environment-variable overrides. Useful for one-click hosting
// (Render, Fly.io, Railway, Heroku) where you can't edit YAML easily.
function applyEnvOverrides(cfg: Config): { combined: boolean; basePath: string } {
  const envPort = process.env.PORT ? Number(process.env.PORT) : NaN;
  const upstream = process.env.PROXY_UPSTREAM;
  const dashUser = process.env.DASHBOARD_USERNAME;
  const dashPass = process.env.DASHBOARD_PASSWORD;
  const basePath = (process.env.DASHBOARD_BASE_PATH ?? "/__shield").replace(/\/$/, "");

  if (upstream) {
    cfg.proxy.upstream = upstream;
    // If user provided a real upstream, we don't need the demo backend.
    cfg.demoBackend.enabled = false;
    logger.info(`Upstream từ env: ${upstream}`);
  }
  if (dashUser !== undefined) cfg.dashboard.username = dashUser;
  if (dashPass !== undefined) cfg.dashboard.password = dashPass;

  // PORT env → combined mode (single externally-exposed port).
  if (Number.isFinite(envPort) && envPort > 0) {
    cfg.proxy.port = envPort;
    cfg.dashboard.port = envPort;
    logger.info(`Phát hiện PORT=${envPort} → chạy chung 1 cổng (chế độ hosted)`);
    return { combined: true, basePath };
  }

  // Manual combined mode: same port set in YAML.
  if (cfg.proxy.port === cfg.dashboard.port) {
    return { combined: true, basePath };
  }

  return { combined: false, basePath };
}

async function main() {
  banner();
  const { config: configPath } = parseArgs();
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  void __dirname;
  const resolved = path.isAbsolute(configPath)
    ? configPath
    : path.resolve(process.cwd(), configPath);

  let cfg: Config;
  try {
    cfg = loadConfig(resolved);
    logger.info(`Đã nạp cấu hình: ${resolved}`);
  } catch (e: any) {
    console.error("Không nạp được cấu hình:", e.message);
    process.exit(1);
  }

  setLogLevel(cfg.logging.level);

  const { combined, basePath } = applyEnvOverrides(cfg);

  if (cfg.demoBackend.enabled) {
    startDemoBackend(cfg.demoBackend.port);
  }

  startStatsTicker();

  if (combined) {
    // One http server handles both dashboard (at basePath) and proxy (everything else).
    const dashApp = buildDashboardApp(cfg, basePath);
    startProxy(cfg, { dashboardApp: dashApp, dashboardBasePath: basePath });
  } else {
    startDashboard(cfg);
    startProxy(cfg);
  }

  process.on("SIGINT", () => {
    logger.info("Đang dừng Mini Shield...");
    process.exit(0);
  });
}

main().catch((e) => {
  console.error("Lỗi nghiêm trọng:", e);
  process.exit(1);
});
