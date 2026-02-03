/// <reference path="./types.d.ts" />
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { execSync, spawn } from "node:child_process";

type LogLevel = "info" | "debug";

function timestamp() {
  return new Date().toISOString().slice(11, 23); // HH:MM:SS.mmm
}

function createLogger(level: LogLevel) {
  const debugEnabled = level === "debug";
  return {
    info: (...args: any[]) => console.log(...args),
    warn: (...args: any[]) => console.warn(...args),
    error: (...args: any[]) => console.error(...args),
    debug: (...args: any[]) => {
      if (debugEnabled) console.log(...args);
    },
    debugEnabled
  };
}

// Home Assistant add-on config is available at /data/options.json
type AddonOptions = {
  token: string;
  log_level: LogLevel;
};
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CONFIG_PATH = path.resolve(__dirname, "../config.yaml");

function getAddonVersion(): string {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf8");
    const match = raw.match(/^version\s*:\s*"?([^"\n]+)"?/m);
    if (match?.[1]) return match[1].trim();
  } catch {
    // ignore
  }
  return "0.0.0";
}

const ADDON_VERSION = getAddonVersion();

const API_BASE_URL = "https://api.test.ctechserver.de";
const EXTRA_ALLOWED_IPS = "172.21.0.0/16";
const WG_DIR = "/data/wireguard";
const WG_PRIVATE_KEY_FILE = path.join(WG_DIR, "client.key");
const WG_PUBLIC_KEY_FILE = path.join(WG_DIR, "client.pub");
const WG_CONFIG_FILE = path.join(WG_DIR, "ha-remote.conf");
const WG_INTERFACE = "ha-remote";

function readOptions(): AddonOptions {
  const raw = fs.readFileSync("/data/options.json", "utf8");
  const parsed = JSON.parse(raw);

  const token = String(parsed.token || "");
  const log_level = String(parsed.log_level || "info");

  if (!token || token.length < 10) throw new Error("token is missing/too short");

  if (log_level !== "info" && log_level !== "debug") throw new Error("log_level must be info|debug");
  return { token, log_level };
}

function ensureWireguardKeypair(log: ReturnType<typeof createLogger>) {
  fs.mkdirSync(WG_DIR, { recursive: true });

  const hasPriv = fs.existsSync(WG_PRIVATE_KEY_FILE);
  const hasPub = fs.existsSync(WG_PUBLIC_KEY_FILE);

  if (hasPriv && hasPub) {
    const privateKey = fs.readFileSync(WG_PRIVATE_KEY_FILE, "utf8").trim();
    const publicKey = fs.readFileSync(WG_PUBLIC_KEY_FILE, "utf8").trim();
    return { privateKey, publicKey };
  }

  log.info("[ha-remote] generating WireGuard keypair");
  const privateKey = execSync("wg genkey", { encoding: "utf8" }).trim();
  const publicKey = execSync("wg pubkey", { input: privateKey, encoding: "utf8" }).trim();

  fs.writeFileSync(WG_PRIVATE_KEY_FILE, privateKey + "\n", { mode: 0o600 });
  fs.writeFileSync(WG_PUBLIC_KEY_FILE, publicKey + "\n", { mode: 0o600 });

  return { privateKey, publicKey };
}

async function provisionWireguard(
  apiBaseUrl: string,
  token: string,
  clientPublicKey: string,
  log: ReturnType<typeof createLogger>
) {
  type WireguardProvisionResponse = {
    error?: string;
    message?: string;
    wireguard_config?: string | null;
    wireguard_endpoint?: string | null;
    wireguard_allowed_ips?: string | null;
    wireguard_server_public_key?: string | null;
    wireguard_preshared_key?: string | null;
    wireguard_private_key?: string | null;
    wireguard_ip?: string | null;
    wireguard_dns?: string | null;
  };

  const r = await fetch(`${apiBaseUrl}/api/tunnels/wireguard`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`
    },
    body: JSON.stringify({
      public_key: clientPublicKey,
      addon_version: ADDON_VERSION
    })
  });

  const rawText = await r.text().catch(() => "");
  const json = ((): WireguardProvisionResponse => {
    if (!rawText) return {};
    try {
      return JSON.parse(rawText) as WireguardProvisionResponse;
    } catch {
      return {};
    }
  })();
  if (!r.ok) {
    const msg = json?.error || json?.message || rawText || "wireguard_provision_failed";
    log.error(`[ha-remote] wireguard provisioning failed (status ${r.status})`, msg);
    throw new Error(msg);
  }

  const {
    wireguard_config,
    wireguard_endpoint,
    wireguard_allowed_ips,
    wireguard_server_public_key,
    wireguard_preshared_key,
    wireguard_private_key,
    wireguard_ip,
    wireguard_dns
  } = json || {};
  if (!wireguard_config && (!wireguard_endpoint || !wireguard_server_public_key || !wireguard_ip)) {
    log.warn("[ha-remote] wireguard provisioning response missing fields", json);
  }

  return {
    config: wireguard_config ? String(wireguard_config) : "",
    endpoint: String(wireguard_endpoint || ""),
    allowedIps: String(wireguard_allowed_ips || "10.8.0.0/24"),
    serverPublicKey: String(wireguard_server_public_key || ""),
    presharedKey: wireguard_preshared_key ? String(wireguard_preshared_key) : "",
    clientPrivateKey: wireguard_private_key ? String(wireguard_private_key) : "",
    ip: String(wireguard_ip || ""),
    dns: wireguard_dns ? String(wireguard_dns) : ""
  };
}

function writeWireguardConfig(
  cfg: { endpoint: string; allowedIps: string; serverPublicKey: string; presharedKey?: string; ip: string; dns?: string },
  privateKey: string
) {
  const lines = [
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${cfg.ip}/32`
  ];

  if (cfg.dns) lines.push(`DNS = ${cfg.dns}`);

  lines.push(
    "",
    "[Peer]",
    `PublicKey = ${cfg.serverPublicKey}`,
    ...(cfg.presharedKey ? [`PresharedKey = ${cfg.presharedKey}`] : []),
    `AllowedIPs = ${cfg.allowedIps}`,
    `Endpoint = ${cfg.endpoint}`,
    "PersistentKeepalive = 25"
  );

  fs.writeFileSync(WG_CONFIG_FILE, lines.join("\n") + "\n", { mode: 0o600 });
}

function normalizeConfigAllowedIps(config: string, allowedIps: string) {
  return config.replace(/AllowedIPs\s*=\s*.*$/gm, `AllowedIPs = ${allowedIps}`);
}

function stripDnsFromConfig(config: string) {
  return config.replace(/^DNS\s*=\s*.*$/gm, "").replace(/\n{2,}/g, "\n\n");
}

function stripIpv6FromConfig(config: string) {
  const withoutIpv6Address = config.replace(/^Address\s*=\s*.*$/gm, (line) => {
    const value = line.split("=")[1] || "";
    const ipv4Only = value
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part && !part.includes(":"))
      .join(", ");
    return ipv4Only ? `Address = ${ipv4Only}` : "";
  });

  return withoutIpv6Address.replace(/^AllowedIPs\s*=\s*.*$/gm, (line) => {
    const value = line.split("=")[1] || "";
    const ipv4Only = value
      .split(",")
      .map((part) => part.trim())
      .filter((part) => part && !part.includes(":"))
      .join(", ");
    return ipv4Only ? `AllowedIPs = ${ipv4Only}` : "AllowedIPs = 0.0.0.0/0";
  });
}

function extractPrivateKey(config: string) {
  const match = config.match(/PrivateKey\s*=\s*([^\s]+)/);
  return match?.[1] || "";
}

function extractEndpoint(config: string) {
  const match = config.match(/^Endpoint\s*=\s*(.+)$/m);
  return match?.[1]?.trim() || "";
}

function extractAddress(config: string) {
  const match = config.match(/^Address\s*=\s*([^\/,\s]+)/m);
  return match?.[1]?.trim() || "";
}

function logWireguardStatus(log: ReturnType<typeof createLogger>) {
  try {
    const status = execSync(`wg show ${WG_INTERFACE}`, { encoding: "utf8" }).trim();
    if (status) log.debug("[ha-remote] wg status:\n" + status);
  } catch (e: any) {
    log.debug("[ha-remote] wg show failed", e?.message || e);
  }
}

type WireguardPeerStats = {
  endpoint: string;
  handshake: string;
  transfer: string;
  handshakeAgeSeconds: number | null;
};

function getWireguardPeerStats(log: ReturnType<typeof createLogger>): WireguardPeerStats | null {
  try {
    // Parse wg show output to get handshake info
    const status = execSync(`wg show ${WG_INTERFACE}`, { encoding: "utf8" }).trim();
    const handshakeMatch = status.match(/latest handshake:\s*(.+)/);
    const transferMatch = status.match(/transfer:\s*(.+)/);
    const endpointMatch = status.match(/endpoint:\s*(.+)/);

    const handshake = handshakeMatch?.[1]?.trim() || "never";
    const transfer = transferMatch?.[1]?.trim() || "none";
    const endpoint = endpointMatch?.[1]?.trim() || "-";

    let handshakeAgeSeconds: number | null = null;
    if (handshake !== "never") {
      // Use wg's numeric output for age in seconds if available
      try {
        const latestHandshakes = execSync(`wg show ${WG_INTERFACE} latest-handshakes`, { encoding: "utf8" }).trim();
        const firstLine = latestHandshakes.split("\n").find(Boolean) || "";
        const parts = firstLine.split(/\s+/);
        const unix = Number(parts[1]);
        if (Number.isFinite(unix) && unix > 0) {
          handshakeAgeSeconds = Math.max(0, Math.floor(Date.now() / 1000 - unix));
        }
      } catch (e: any) {
        log.debug("[ha-remote] latest-handshakes check failed", e?.message || e);
      }
    }

    return { endpoint, handshake, transfer, handshakeAgeSeconds };
  } catch (e: any) {
    log.debug("[ha-remote] wg show failed", e?.message || e);
    return null;
  }
}

function logWireguardConnectionStats(log: ReturnType<typeof createLogger>) {
  const stats = getWireguardPeerStats(log);
  if (!stats) return;
  log.debug(
    `[ha-remote] wg peer endpoint=${stats.endpoint} handshake=${stats.handshake}` +
      ` transfer=${stats.transfer}` +
      (stats.handshakeAgeSeconds !== null ? ` age=${stats.handshakeAgeSeconds}s` : "")
  );
}

function isWireguardLogLine(line: string) {
  const lower = line.toLowerCase();
  return (
    lower.includes("wireguard") ||
    lower.includes("wg-quick") ||
    lower.includes(`${WG_INTERFACE}`.toLowerCase()) ||
    lower.includes("wg0") ||
    lower.includes("wg:") ||
    lower.includes("peer(") ||
    lower.includes("allowedip") ||
    lower.includes("handshake")
  );
}

function tryEnableWireguardDebug(log: ReturnType<typeof createLogger>) {
  // Try to enable WireGuard kernel module dynamic debug (requires debugfs)
  const debugControl = "/sys/kernel/debug/dynamic_debug/control";
  try {
    if (fs.existsSync(debugControl)) {
      fs.writeFileSync(debugControl, "module wireguard +p");
      log.debug("[ha-remote] enabled WireGuard kernel debug logging");
    }
  } catch (e: any) {
    log.debug("[ha-remote] could not enable WireGuard debug (normal in containers):", e?.message || e);
  }
}

function dumpDmesgWireguardLines(log: ReturnType<typeof createLogger>, seenLines: Set<string>) {
  try {
    const output = execSync("dmesg 2>/dev/null || cat /dev/kmsg 2>/dev/null || true", {
      encoding: "utf8",
      timeout: 5000
    });
    const lines = output.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && isWireguardLogLine(trimmed) && !seenLines.has(trimmed)) {
        seenLines.add(trimmed);
        log.debug(`[ha-remote][wglog] ${trimmed}`);
      }
    }
  } catch {
    // ignore errors
  }
}

function runWgCommand(log: ReturnType<typeof createLogger>, command: string, args: string[]): string {
  try {
    const result = execSync(`${command} ${args.join(" ")}`, { encoding: "utf8", timeout: 10000 });
    return result;
  } catch (e: any) {
    log.debug(`[ha-remote] ${command} failed:`, e?.message || e);
    return "";
  }
}

function logWgQuickOutput(log: ReturnType<typeof createLogger>, action: "up" | "down", configFile: string) {
  try {
    const result = execSync(`wg-quick ${action} ${configFile} 2>&1`, { encoding: "utf8", timeout: 30000 });
    const lines = result.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) {
        log.info(`[ha-remote][wg-quick] ${trimmed}`);
      }
    }
  } catch (e: any) {
    // wg-quick may exit with error but still output useful info
    const output = e?.stdout || e?.stderr || e?.message || "";
    if (output) {
      const lines = String(output).split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed) {
          log.info(`[ha-remote][wg-quick] ${trimmed}`);
        }
      }
    }
    throw e;
  }
}

function startWireguardLogParser(log: ReturnType<typeof createLogger>) {
  if (!log.debugEnabled) return null;

  log.debug("[ha-remote] starting WireGuard log parser");

  // Try to enable kernel debug for wireguard
  tryEnableWireguardDebug(log);

  // Track seen lines to avoid duplicates
  const seenLines = new Set<string>();

  // Dump initial dmesg wireguard lines
  dumpDmesgWireguardLines(log, seenLines);

  // Set up periodic polling for kernel logs (works in containers where streaming fails)
  const pollInterval = setInterval(() => {
    dumpDmesgWireguardLines(log, seenLines);
  }, 10_000);

  // Also try streaming sources
  const attachLineParser = (sourceName: string, readable: NodeJS.ReadableStream) => {
    let buffer = "";
    const flushLine = (line: string) => {
      const trimmed = line.trim();
      if (trimmed && isWireguardLogLine(trimmed) && !seenLines.has(trimmed)) {
        seenLines.add(trimmed);
        log.debug(`[ha-remote][wglog] ${trimmed}`);
      }
    };
    readable.on("data", (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || "";
      for (const line of lines) flushLine(line);
    });
    readable.on("end", () => {
      if (buffer) flushLine(buffer);
      buffer = "";
      log.debug(`[ha-remote] ${sourceName} log stream ended`);
    });
  };

  const trySpawn = (
    sourceName: string,
    command: string,
    args: string[],
    onExit?: () => void
  ) => {
    log.debug(`[ha-remote] trying log source: ${command} ${args.join(" ")}`);
    const proc = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    attachLineParser(sourceName, proc.stdout);

    proc.stderr.on("data", (chunk: Buffer | string) => {
      const msg = String(chunk).trim();
      if (msg) log.debug(`[ha-remote] ${sourceName} stderr: ${msg}`);
    });

    proc.on("error", (err: any) => {
      log.debug(`[ha-remote] ${sourceName} failed:`, err?.message || err);
      onExit?.();
    });

    proc.on("exit", (code: number | null, signal: string | null) => {
      log.debug(`[ha-remote] ${sourceName} exited (code=${code ?? "?"}, signal=${signal ?? "?"})`);
      if (code && code !== 0) onExit?.();
    });

    return proc;
  };

  // Try streaming sources in order, but polling is our fallback
  trySpawn("dmesg", "dmesg", ["-w"], () => {
    trySpawn("dmesg", "dmesg", ["--follow"], () => {
      // Polling is already running, just log
      log.debug("[ha-remote] using polling for kernel logs");
    });
  });

  return { pollInterval };
}

function triggerHandshake(log: ReturnType<typeof createLogger>) {
  try {
    execSync("ping -c 1 -W 3 10.8.0.1", { encoding: "utf8" });
    log.debug("[ha-remote] Ping to 10.8.0.1 succeeded - tunnel is up!");
    return true;
  } catch {
    log.debug("[ha-remote] Ping to 10.8.0.1 failed - tunnel not connected");
    return false;
  }
}

function reconnectWireguard(log: ReturnType<typeof createLogger>) {
  try {
    log.info("[ha-remote] reconnecting WireGuard interface...");
    logWgQuickOutput(log, "down", WG_CONFIG_FILE);
  } catch (e: any) {
    log.debug("[ha-remote] wg-quick down failed:", e?.message || e);
  }
  bringWireguardUp(log);
}

function bringWireguardUp(log: ReturnType<typeof createLogger>) {
  try {
    execSync(`wg show ${WG_INTERFACE}`, { stdio: "ignore" });
    log.info("[ha-remote] WireGuard interface exists, leaving up");
    return;
  } catch {
    // interface not up yet
  }

  logWgQuickOutput(log, "up", WG_CONFIG_FILE);
}

function getHaVersionBestEffort(): string | undefined {
  // Optional: if reachable, you could query http://homeassistant:8123/api/config with a long-lived token.
  // But we intentionally avoid handling HA tokens here.
  return undefined;
}

const HA_UPSTREAM_HOST = process.env.HA_UPSTREAM_HOST || "homeassistant";
const HA_UPSTREAM_PORT = Number(process.env.HA_UPSTREAM_PORT || "8123");
const PROXY_LISTEN_PORT = 8123;
const WG_MONITOR_INTERVAL_MS = 60_000; // For logging stats
const WG_PING_INTERVAL_MS = 2_000; // Fast health check every 2 seconds
const WG_PING_FAIL_THRESHOLD = 3; // Reconnect after 3 consecutive failures (6 seconds)
const WG_NO_HANDSHAKE_GRACE_SECONDS = 120;

function startReverseProxy(wireguardIp: string, log: ReturnType<typeof createLogger>) {
  const server = http.createServer((req, res) => {
    // Strip X-Forwarded-* headers to avoid 400 errors from HA's proxy detection
    const cleanHeaders: Record<string, string | string[] | undefined> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lowerKey = key.toLowerCase();
      if (!lowerKey.startsWith("x-forwarded") && lowerKey !== "x-real-ip") {
        cleanHeaders[key] = value;
      }
    }

    const proxyReq = http.request(
      {
        hostname: HA_UPSTREAM_HOST,
        port: HA_UPSTREAM_PORT,
        path: req.url,
        method: req.method,
        headers: {
          ...cleanHeaders,
          host: `${HA_UPSTREAM_HOST}:${HA_UPSTREAM_PORT}`
        }
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(res, { end: true });
      }
    );

    proxyReq.on("error", (err) => {
      log.error("[ha-remote] proxy error:", err.message);
      if (!res.headersSent) {
        res.writeHead(502, { "Content-Type": "text/plain" });
      }
      res.end("Bad Gateway");
    });

    req.pipe(proxyReq, { end: true });
  });

  // Handle WebSocket upgrades
  server.on("upgrade", (req, socket, head) => {
    // Strip X-Forwarded-* headers for WebSocket connections too
    const cleanHeaders: Record<string, string | string[] | undefined> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lowerKey = key.toLowerCase();
      if (!lowerKey.startsWith("x-forwarded") && lowerKey !== "x-real-ip") {
        cleanHeaders[key] = value;
      }
    }

    const proxyReq = http.request({
      hostname: HA_UPSTREAM_HOST,
      port: HA_UPSTREAM_PORT,
      path: req.url,
      method: req.method,
      headers: cleanHeaders
    });

    proxyReq.on("upgrade", (proxyRes, proxySocket, proxyHead) => {
      socket.write(
        `HTTP/1.1 101 Switching Protocols\r\n` +
        Object.entries(proxyRes.headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join("\r\n") +
        "\r\n\r\n"
      );
      if (proxyHead.length > 0) socket.write(proxyHead);
      proxySocket.pipe(socket);
      socket.pipe(proxySocket);
    });

    proxyReq.on("error", (err) => {
      log.error("[ha-remote] websocket proxy error:", err.message);
      socket.end();
    });

    proxyReq.end();
  });

  server.listen(PROXY_LISTEN_PORT, wireguardIp, () => {
    log.info(`[ha-remote] reverse proxy listening on ${wireguardIp}:${PROXY_LISTEN_PORT} -> ${HA_UPSTREAM_HOST}:${HA_UPSTREAM_PORT}`);
  });

  server.on("error", (err) => {
    log.error("[ha-remote] proxy server error:", err.message);
  });

  return server;
}

async function main() {
  const opts = readOptions();
  const log = createLogger(opts.log_level);
  log.info(`[ha-remote] add-on version ${ADDON_VERSION}`);

  let wgLogProcess = startWireguardLogParser(log);

  const extraAllowedIps = EXTRA_ALLOWED_IPS;

  let lastConfigHash: string | null = null;
  let proxyServer: http.Server | null = null;
  let monitorTimer: NodeJS.Timeout | null = null;

  for (;;) {
    try {
      const { privateKey: localPrivateKey, publicKey: localPublicKey } = ensureWireguardKeypair(log);
      const cfg = await provisionWireguard(API_BASE_URL, opts.token, localPublicKey, log);

      if (!cfg.endpoint || !cfg.serverPublicKey || !cfg.ip) {
        if (!cfg.config) throw new Error("wireguard_provision_incomplete");
      }

      if (cfg.config) {
        const desiredAllowedIps = [cfg.allowedIps || "10.8.0.0/24", extraAllowedIps]
          .map((v) => v.trim())
          .filter(Boolean)
          .join(", ");
        const normalized = normalizeConfigAllowedIps(cfg.config, desiredAllowedIps);
        const cleaned = stripIpv6FromConfig(stripDnsFromConfig(normalized));
        fs.writeFileSync(WG_CONFIG_FILE, cleaned + (cleaned.endsWith("\n") ? "" : "\n"), { mode: 0o600 });

        const privateKeyFromConfig = extractPrivateKey(cleaned) || localPrivateKey;
        const publicKeyFromConfig = execSync("wg pubkey", { input: privateKeyFromConfig, encoding: "utf8" }).trim();
        fs.writeFileSync(WG_PRIVATE_KEY_FILE, privateKeyFromConfig + "\n", { mode: 0o600 });
        fs.writeFileSync(WG_PUBLIC_KEY_FILE, publicKeyFromConfig + "\n", { mode: 0o600 });
      } else {
        const effectivePrivateKey = cfg.clientPrivateKey || localPrivateKey;
        const effectivePublicKey = cfg.clientPrivateKey
          ? execSync("wg pubkey", { input: cfg.clientPrivateKey, encoding: "utf8" }).trim()
          : localPublicKey;

        fs.writeFileSync(WG_PRIVATE_KEY_FILE, effectivePrivateKey + "\n", { mode: 0o600 });
        fs.writeFileSync(WG_PUBLIC_KEY_FILE, effectivePublicKey + "\n", { mode: 0o600 });

        const effectiveCfg = {
          ...cfg,
          allowedIps: [cfg.allowedIps || "10.8.0.0/24", extraAllowedIps]
            .map((v) => v.trim())
            .filter(Boolean)
            .join(", ")
        };
        writeWireguardConfig(effectiveCfg, effectivePrivateKey);
      }
      try {
        const configText = fs.readFileSync(WG_CONFIG_FILE, "utf8");
        const endpoint = extractEndpoint(configText);
        if (endpoint) log.info(`[ha-remote] WireGuard endpoint: ${endpoint}`);
      } catch {
        // ignore
      }
      const currentConfig = fs.readFileSync(WG_CONFIG_FILE, "utf8");
      const currentHash = Buffer.from(currentConfig).toString("base64");

      if (currentHash !== lastConfigHash) {
        lastConfigHash = currentHash;
        bringWireguardUp(log);
        logWireguardStatus(log);
        logWireguardConnectionStats(log);

        // Start reverse proxy on WireGuard IP
        const wireguardIp = extractAddress(currentConfig);
        if (wireguardIp && !proxyServer) {
          proxyServer = startReverseProxy(wireguardIp, log);
        }
        if (!monitorTimer) {
          let consecutivePingFailures = 0;
          let isReconnecting = false;

          // Fast ping-based health check every 2 seconds
          const pingTimer = setInterval(() => {
            if (isReconnecting) return;

            const pingOk = triggerHandshake(log);
            if (pingOk) {
              if (consecutivePingFailures > 0) {
                log.debug(`[ha-remote] Ping recovered after ${consecutivePingFailures} failures`);
              }
              consecutivePingFailures = 0;
            } else {
              consecutivePingFailures++;
              log.debug(`[ha-remote] Ping failed (${consecutivePingFailures}/${WG_PING_FAIL_THRESHOLD})`);

              if (consecutivePingFailures >= WG_PING_FAIL_THRESHOLD) {
                log.info(`[ha-remote] ${WG_PING_FAIL_THRESHOLD} consecutive ping failures - reconnecting...`);
                isReconnecting = true;
                consecutivePingFailures = 0;
                try {
                  reconnectWireguard(log);
                } finally {
                  isReconnecting = false;
                }
              }
            }
          }, WG_PING_INTERVAL_MS);

          // Slower interval just for logging stats
          monitorTimer = setInterval(() => {
            logWireguardConnectionStats(log);
          }, WG_MONITOR_INTERVAL_MS);
        }
      } else {
        log.info("[ha-remote] WireGuard config unchanged");
        logWireguardStatus(log);
        logWireguardConnectionStats(log);
      }

      if (!wgLogProcess && log.debugEnabled) {
        wgLogProcess = startWireguardLogParser(log);
      }

      log.info("[ha-remote] WireGuard is up. Standing by...");
      await new Promise((r) => setTimeout(r, 300_000));
    } catch (e: any) {
      log.error("[ha-remote] wireguard setup error:", e?.message || e);
      await new Promise((r) => setTimeout(r, 5000));
    }
  }
}

main().catch((e) => {
  console.error("[ha-remote] fatal:", e);
  process.exit(1);
});
