type Level = "debug" | "info" | "warn" | "error";
const order: Record<Level, number> = { debug: 0, info: 1, warn: 2, error: 3 };

let currentLevel: Level = "info";

export function setLogLevel(level: Level) {
  currentLevel = level;
}

function ts() {
  return new Date().toISOString().replace("T", " ").replace("Z", "");
}

function log(level: Level, color: string, ...args: unknown[]) {
  if (order[level] < order[currentLevel]) return;
  const tag = `\x1b[${color}m${level.toUpperCase()}\x1b[0m`;
  console.log(`[${ts()}] ${tag}`, ...args);
}

export const logger = {
  debug: (...a: unknown[]) => log("debug", "90", ...a),
  info:  (...a: unknown[]) => log("info",  "36", ...a),
  warn:  (...a: unknown[]) => log("warn",  "33", ...a),
  error: (...a: unknown[]) => log("error", "31", ...a),
};
