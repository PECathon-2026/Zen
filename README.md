# ZenLens: privacy-preserving AI browser agent (PS-004 PrivacyLens, PECathon 2026)

An AI agent that works on web pages for you, while sensitive data (cards, Aadhaar, PAN, passwords, OTPs,
API keys, phones, emails, IPs, faces) never reaches the external model.

**Core rule:** compute what is sensitive locally; reason globally only on sanitized data.

Three ways to use it:

| Surface | What it does | Where |
|---|---|---|
| **Agent + demo** (Python) | Drives a real headless browser; the model only ever sees a redacted view and placeholders | `zenlens/`, `demo/` |
| **Web app** (PC + phone, installable PWA) | Before/after privacy preview for text, screenshots and web pages; runs agent tasks; local-only mode | `app/` |
| **Chrome extension** (MV3) | Highlights and masks PII on any page; guards pastes into ChatGPT/Claude/Gemini; works offline | `extension/` |

---

## Architecture and data flow

```mermaid
flowchart LR
  subgraph Local["User's machine (trusted)"]
    P[Web page<br/>Playwright / Chrome tab] --> C[capture.py<br/>DOM elements + screenshot]
    C --> S1[structural.py<br/>field types, labels, autocomplete]
    C --> S2[detect.py<br/>regex + Luhn/Verhoeff/IP checks]
    C --> S3[screenshot.py<br/>OCR + blackout, faces]
    S1 & S2 & S3 --> V[Sanitized view<br/>REDACTED:KIND placeholders, ids e1..eN]
    V --> G{gate.py<br/>egress_check<br/>fail closed}
    X[executor.py<br/>validate + approve] --> P
    VA[(vault.py<br/>real secrets)] -. "{{SECRET:name}} resolved locally" .-> X
    U((User)) -. approve sensitive / irreversible .-> X
  end
  G -- "sanitized JSON only" --> M[External LLM<br/>Claude]
  M -- "action: click(e7) / type(e5, {{SECRET:pw}})" --> X
```

Step by step (`zenlens/agent.py` loop, wired to a real browser by `zenlens/browser.py`):

1. **Capture** (`capture.py`): headless Chromium snapshots the page. Every visible element gets a stable id
   (`e1`, `e2`, …). Raw DOM and screenshot stay in memory locally.
2. **Detect** (all local, no network):
   - `detect.py` text rules with checksums (Luhn for cards, Verhoeff for Aadhaar, octet/IPv6 validation),
     Devanagari digit normalisation.
   - `structural.py` flags fields by structure even when the text looks harmless: `type=password`,
     `autocomplete=cc-number/one-time-code`, labels like OTP/CVV/PIN/token.
   - `screenshot.py` OCRs the screenshot (Apple Vision or Tesseract), blacks out PII boxes and DOM-flagged
     element boxes, optional face blackout (OpenCV). Fails closed: never returns an unredacted image.
3. **Sanitize**: values become `[REDACTED:KIND]`; URL query/fragment dropped.
4. **Gate** (`gate.py`): every outbound payload is re-scanned; any PII, vault value or canary ⇒ `Blocked`.
   A scanner error also blocks.
5. **Reason**: the model receives only the sanitized view and returns an action. Page text is marked
   UNTRUSTED in the system prompt.
6. **Validate** (`executor.py`): allowed action types, target id must exist, navigation only to allowed
   origins, typed text must be non-sensitive or exactly one `{{SECRET:name}}` placeholder whose kind matches
   the field (a password can't go into a comment box).
7. **Approve**: vault substitutions and irreversible clicks (submit/pay/delete/send…) need the user's OK;
   default deny.
8. **Execute**: the executor resolves the placeholder from the local vault and fills the real field. The
   real value never appears in model payloads, history, logs or reports.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m playwright install chromium
```

Optional: `brew install tesseract` (OCR on non-macOS; macOS uses Apple Vision by default),
`export ANTHROPIC_API_KEY=...` for real Claude runs.

## Run

```bash
.venv/bin/python -m pytest -q                       # tests
.venv/bin/python -m eval.run_eval                   # detector benchmark (exit 1 on any counted leak)
.venv/bin/python demo/run_demo.py --yes             # narrated end-to-end demo, scripted model
.venv/bin/python demo/run_demo.py --pace 1.5 --headed --yes   # slower, visible browser, for recording
.venv/bin/python demo/run_demo.py --claude --yes    # real Claude (needs ANTHROPIC_API_KEY)
```

Demo scenes: (1) checkout page detection + redacted screenshot, (2) sign-in with vault secrets and
approvals, (3) card payment from the vault, raw card typed by the model rejected, (4) prompt-injection page:
all 5 hijack attempts blocked, (5) gate blocks PII payloads, (6) leak audit: 0 vault values in any payload
or report.

### Web app (PC and phone)

```bash
.venv/bin/python -m app.server            # PC: open http://127.0.0.1:8765/ (localhost only, no token)
.venv/bin/python -m app.server --lan      # phone: scan the printed QR / open http://<LAN-IP>:8765/#token=…
```

The server runs on your own machine; the phone reaches it over Wi-Fi. The token sits in the URL fragment
(never sent to the server or its logs), is stored by the page, and every POST needs `X-ZenLens-Token`
in LAN mode. Flags: `--local-only` (disables Claude mode), `--port`, `--token` / `ZENLENS_TOKEN`,
`--cert`/`--key` for HTTPS (needed for installing the PWA on a phone; e.g. an mkcert certificate).

Screens (mobile bottom bar / desktop tabs, light/dark, no CDNs, strict CSP):
- **Text**: before/after with spans coloured by kind and a "why redacted" explanation per span.
- **Screenshot**: phone camera or file upload → redacted image with a before/after slider, optional face blur.
- **Web page**: URL or bundled test page → redacted screenshot + sanitized element list.
- **Agent task**: goal + page, scripted demo or Claude; each step's verdict (allowed / rejected / needs
  approval) and a **"Data that left this device"** panel showing the exact sanitized payloads.
- **Settings**: local-only mode, custom regex rules (validated server-side), connection status.

API (port 8765, also used by the extension): `GET /api/health`, `POST /api/sanitize`,
`/api/sanitize_html`, `/api/redact_image`, `/api/preview`, `/api/agent/run`, `/api/gate`. Findings carry
offsets and kinds only, never values; errors never echo input; request bodies are never logged; other
web origins are refused (only same-origin and `chrome-extension://`).

### Chrome extension

Load it: `chrome://extensions` → Developer mode → **Load unpacked** → pick `extension/`. Reload tabs that
were already open (or click the ZenLens icon once). Details and permission justifications:
[extension/README.md](extension/README.md).

- **Works offline.** `lib/detect.js` is an exact port of `detect.py`: identical spans on all 124 eval
  cases (`node --test extension/tests/`; refresh the Python reference with
  `.venv/bin/python extension/tests/dump_py.py`).
- **Highlight and mask**: outlines PII on any page with a per-kind badge; "Mask on screen" blurs it.
  Page text and input values are never modified.
- **AI-chat guard**: on ChatGPT, Claude, Gemini, Copilot and Perplexity (configurable), pasting or sending
  PII opens a dialog that defaults to **Send sanitized** (`[REDACTED:KIND]`).
- **Popup / side panel**: per-kind counts, copy sanitized page text, before/after view, and a redacted
  screenshot (DOM boxes blacked out locally, then OCR via the local server if it's running).
- **Options**: custom rules, AI-site list, allow/deny sites, server URL + token. Detected values are never
  stored. Network access is limited to `localhost:8765`.
- Not verified as a loaded extension in a real Chrome profile yet (popup, side panel, screenshot capture,
  context menu); the detector, content script, guard and options page were exercised in a browser.

## Modules

| File | Role |
|---|---|
| `zenlens/detect.py` | Regex + checksum PII detector (CARD, AADHAAR, PAN, EMAIL, PHONE, IP, API_KEY, TOKEN, PASSWORD, OTP) |
| `zenlens/sanitize.py` | `[REDACTED:KIND]` replacement |
| `zenlens/gate.py` | Fail-closed `egress_check(payload, canaries)` |
| `zenlens/structural.py` | HTML structural detector: `scan_html`, `sanitize_html`, `element_kind` |
| `zenlens/screenshot.py` | OCR redaction `redact_image(png, extra_boxes, faces)` |
| `zenlens/capture.py` | Playwright `Session`, `PageSnapshot`, `sanitized_view` |
| `zenlens/browser.py` | `PlaywrightPage`: the agent's real-browser `Page` |
| `zenlens/vault.py` | Local secret store, `{{SECRET:name}}` placeholders |
| `zenlens/llm.py` | `Action`, `ScriptedLLM`, `ClaudeLLM` (structured output, egress-checked) |
| `zenlens/executor.py` | Action validation, approval, injection defence |
| `zenlens/agent.py` | Capture → gate → model → validate → execute loop |
| `zenlens/runner.py` | `run_task(...)` and `preview(...)`, used by the web app |
| `app/` | Local FastAPI server + installable PWA (phone and PC) |
| `extension/` | Chrome MV3 extension with JS detector port |
| `demo/` | Localhost test-page server and narrated demo |
| `testpages/` | 5 synthetic pages + `.truth.json` ground truth, plus `injection.html` |
| `eval/` | Deterministic case generator + benchmark |

## Evaluation

`eval/make_cases.py` generates 124 synthetic, labelled cases from a fixed seed (valid/invalid Luhn and
Verhoeff numbers computed, not hand-typed) across checkout, auth, support, video and dev-settings
scenarios. Includes hard negatives (order IDs, timestamps, versions, UUIDs, git SHAs, GSTIN), format
variants, Hindi/Hinglish text, canaries and a separately reported adversarial set.

Current results (`python -m eval.run_eval`):

| Metric | Value |
|---|---|
| Recall (non-adversarial) | 0.99 (85/86) |
| Precision | 1.00 |
| Leaks in counted cases | 0 |
| Canaries blocked by gate | 5/5 |
| Context preservation (non-PII tokens unchanged) | 1.00 |
| `detect()` latency | ~0.008 ms mean, ~0.013 ms p95 |
| Adversarial recall (reported, not counted) | 0.20 |

End-to-end tests (`tests/test_e2e.py`, real headless Chromium) prove that vault secrets reach the page
but never appear in model payloads, logs (DEBUG, all loggers) or reports; that every injection hijack is
rejected; and that `preview()` output and OCR of the redacted screenshot contain no ground-truth values.

**Zero-leak claims cover only these synthetic cases and tested pathways.**

## Security assumptions and limitations

- **Trusted:** the local machine, the Python process and the browser it drives. The model and its
  provider are untrusted; page content is untrusted (prompt injection).
- **Known gaps:** person names need NER (one known-gap case); obfuscated PII ("anu at example dot com",
  digits with spaces, zero-width characters, lowercase PAN, keys split across strings) is mostly missed.
- **Screenshots:** OCR misses small (< ~12 px), low-contrast or stylised text and text over images; PII
  split across lines isn't joined. DOM-flagged element boxes are blacked out regardless, which covers form
  fields. Haar face detection is weak on profiles and small faces.
- **Layout leakage:** element positions and field types are visible to the model (needed to act).
- **Retention:** snapshots live in memory for one step; nothing is persisted; logs carry ids, kinds and
  placeholder names only.
- **Local test servers must use `localhost`**, not `127.0.0.1`: IPs are detected, so an IP in the URL is
  blocked by the gate.
- Synthetic data only throughout; never test with real PII.

Reference only: `~/Desktop/Github-C` (third-party project, not copied).
