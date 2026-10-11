# DeviceGuard (Phase 1)
Software-only IoT security **simulation**. Not a deployed hardware security system. No backend, no real devices, no real network monitoring.
## Run
VS Code → install *Live Server* → right-click `index.html` → *Open with Live Server* (ES modules need http, not file://).
Login: `analyst` / `devguard-demo`. This is a **demonstration login only** (client-side check, SHA-256 compared in the browser): it gives no real protection and anyone with browser access can bypass it.
## Demo order
Lab → *Normal behaviour* (no alerts) → *Failed access* → *Conflicting door states* → *Combined attack chain* (one incident) → *Unrelated events* (separate incidents) → Incidents (resolve / false positive needs a note) → refresh page (data persists).
## How it works
`threat-dna.js`: transparent rules R1–R7 with configurable thresholds; findings are deduplicated by a cooldown; each distinct rule counts once in the 0–100 risk score (weights in Settings; severity bands 0–24 Low, 25–49 Guarded, 50–74 High, 75+ Critical: demonstration thresholds). Correlation links only the same or directly connected devices (excluding the shared gateway) within the correlation window; links are *inferred*. No ML or AI is used. Scenarios use a virtual clock, so results are repeatable.
## Implemented vs not yet
Implemented: login/logout, dashboard, device explorer + details, ThreatDNA rules, risk, incidents + notes + audit, 10 scenarios with pause/resume/stop/speed, settings with validation, CSV/JSON export, reset with confirmation, corrupted-storage handling.
**Not yet built:** hash-chain demo, first-run wizard, printable report, per-device failure injection buttons, relearn-baseline control. Untested in a browser so far; run the manual checklist first.
## Limitations
localStorage is not encrypted or tamper-proof; audit records are local demonstration records; "no alerts" never means secure.
- **Guard Assistant** (`assistant.js`): local keyword-based helper answering from app state. Not AI; no external service.
- **Network map** (`network-map.js`): SVG topology from configured links; select a device to highlight links; "possible impact" is inferred, not confirmed.
- **Posture** (`posture.js`): weights Availability 30, Unresolved incidents 30, Device health 15, Configuration 15, Critical devices 10. No history chart yet.
- **Replay and forensics** (`replay.js`): read-only step-through of recorded events, risk/severity progression, forensic summary, timeline CSV, print/save-as-PDF report.
- **What-if simulator** (`whatif.js`): projected risk only; nothing is changed.
