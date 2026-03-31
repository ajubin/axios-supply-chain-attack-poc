# C2 POC — axios supply chain attack demo

> **Educational purpose only.**
> Reproduces the npm supply chain attack discovered on March 31, 2026 that compromised `axios@1.14.1` and `axios@0.30.4`.

---

## What this demo shows

On March 31, 2026, an attacker compromised the npm account of the primary axios maintainer and published two poisoned versions of the library. The attack injected a fake dependency (`plain-crypto-js@4.2.1`) whose sole purpose was to silently install a Remote Access Trojan (RAT) on the developer's machine during `npm install` — with no warning, no visible change in the axios source code, and no trace left after execution.

This POC reproduces the full chain:

```
npm install
  └─ postinstall hook fires silently
       └─ dropper contacts C2, downloads RAT
            └─ RAT drops to /Library/Caches/com.apple.act.mond.js
                 └─ dropper self-destructs, package looks clean
                      └─ RAT beacons every 5s, awaits commands
```

---

## Setup

### Prerequisites

- Node.js >= 18

### 1. Start the C2 server

```bash
cd c2-server
npm install
node server.js
# C2 running on http://localhost:8000
# Open http://localhost:8000 to see the operator dashboard
```

### 2. Run npm install on the victim app

```bash
cd victim-app
npm install
# This triggers the full attack chain
```

> The victim app references the fake package via `file:../fake-package` —
> no registry needed. In the real attack, the package was published to npm.

---

## Project structure

```
c2-poc/
├── c2-server/
│   ├── server.js          # Express C2 server + operator API
│   ├── rat.js             # Second-stage payload served to victims
│   └── public/index.html  # Operator dashboard
├── fake-package/
│   ├── package.json       # Mimics plain-crypto-js@4.2.1
│   └── setup.js           # Dropper — runs via postinstall hook
└── victim-app/
    └── package.json       # Innocent app with plain-crypto-js as dependency
```

---

## Demo script

**1.** Open the operator dashboard at `http://localhost:8000` — empty, no victims yet.

**2.** Show `victim-app/package.json` — looks like any normal project.

**3.** Show `fake-package/package.json` — point out the `postinstall` hook. This is the only difference from a legitimate package.

**4.** Run `npm install` in `victim-app/`. Output looks completely normal.

**5.** Immediately inspect the installed package:
```bash
cat victim-app/node_modules/plain-crypto-js/package.json
# No postinstall hook. Package looks clean.
# The dropper already ran, deleted itself, and rewrote its own package.json.
```

**6.** Switch to the dashboard — the victim is already registered, fingerprint visible. While you were reading that clean `package.json`, the RAT was connecting to the C2.

**7.** Send a command (`runscript: ls ~`) — result appears 5 seconds later.

---

## Key evasion techniques reproduced

| Technique | Where | Real attack |
|---|---|---|
| `postinstall` hook fires on `npm install` | `fake-package/package.json` | `plain-crypto-js@4.2.1` |
| Dropper self-deletes after execution | `setup.js` | `setup.js` unlinks itself |
| `package.json` rewritten to remove hook | `setup.js` | `package.md` renamed to `package.json` |
| RAT dropped to system-looking path | `setup.js` | `/Library/Caches/com.apple.act.mond` |
| Process spawned detached (survives terminal) | `setup.js` | `nohup zsh ... &` |
| Fake npm traffic as POST body | `setup.js` | `packages.npm.org/product0` |
| Fake IE8/WinXP User-Agent | `rat.js` | `mozilla/4.0 (compatible; msie 8.0...)` |
| Payloads base64-encoded in both directions | `rat.js` + `server.js` | real RAT |
| Single C2 endpoint for all traffic | `server.js` | `/6202033` |

---

## What is NOT reproduced (intentionally)

- `peinject` — arbitrary binary injection and execution
- Persistence mechanism (LaunchAgent plist on macOS, registry Run key on Windows)
- Encrypted C2 traffic
- Ad-hoc code signing via `codesign` of injected payloads
- Multi-platform payloads (Windows PowerShell, Linux Python)

---

## Indicators of compromise (real attack)

If you ran `axios@1.14.1` or `axios@0.30.4` in a `npm install`:

```bash
# Check for the RAT binary
ls -la /Library/Caches/com.apple.act.mond

# Check for C2 connections in system logs
log show --predicate 'eventMessage contains "sfrclak"' --last 7d

# Check your axios version
cat node_modules/axios/package.json | grep '"version"'
# 1.14.1 or 0.30.4 → compromised / 1.14.0 or 0.30.3 → safe

# Check if the malicious dep was ever installed
ls node_modules/plain-crypto-js
```

Network IOCs:
```
Domain : sfrclak.com
IP     : 142.11.206.73
Port   : 8000
Path   : /6202033
User-Agent : mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)
```

---

## Sources

- **StepSecurity** (découvreur de l'attaque) — analyse technique complète incluant le reverse du dropper et la capture réseau en live :
  https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

- **Socket** — analyse de `plain-crypto-js@4.2.1` et des packages secondaires (`@shadanai/openclaw`, `@qqbrowser/openclaw-qbot`) :
  https://socket.dev/blog/axios-npm-package-compromised

- **Snyk** — timeline de l'attaque, fenêtre d'exposition (00:21–03:29 UTC), et impact sur les lockfiles :
  https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/

- **Mend.io / Joe DeSimone (Elastic Security)** — reverse engineering complet du binaire Mach-O, reconstruction du dispatch loop, offsets des fonctions :
  https://www.mend.io/blog/poisoned-axios-npm-account-takeover-50-million-downloads-and-a-rat-that-vanishes-after-install/

- **SafeDep** — analyse du RAT Linux (`ld.py`), commandes supportées, absence de persistence :
  https://safedep.io/axios-npm-supply-chain-compromise/

- **Wiz** — impact en environnements cloud, détection dans 3% des envs exposés, GHSA-fw8c-xr5c-95f9 :
  https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack

- **The Hacker News** — synthèse et timeline :
  https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html

- **GitHub issue axios/axios#10604** — thread de découverte communautaire :
  https://github.com/axios/axios/issues/10604

---

## CVE / Advisory

- `GHSA-fw8c-xr5c-95f9` — advisory GitHub pour axios
- `MAL-2026-2306` — advisory pour plain-crypto-js
