# Zen Chrome extension (Manifest V3)

Zen in your own browser. It finds sensitive data on the pages you visit, can mask it on screen, and checks what you paste or send into AI chat sites. All detection runs inside the extension. The optional local Zen server (`http://localhost:8765`) is used only for screenshot OCR.

## Agent Shield (the point of the extension)

When an AI agent drives the browser (Claude in Chrome, Antigravity, Playwright/CDP scripts), it sees the page through
**screenshots** and **DOM reads** (page text, accessibility tree, input values). Agent Shield makes both show
`[REDACTED:KIND]` instead of sensitive data, on the page itself, so it works for any agent without integrating with it.

| What the agent uses | What Shield does |
|---|---|
| Screenshot (`Captures composited pixels`) | Opaque black blocks with the kind label over every sensitive field and text span. Painted synchronously on scroll and layout shifts. No blur, no focus exemption: focusing a field does not drop its cover. |
| Page text / accessibility tree | Sensitive text nodes are rewritten to `[REDACTED:KIND]` (originals kept only in page memory, restored when the shield drops). |
| Input values (`el.value`, form reads) | Pre-filled / autofilled sensitive values, including hidden CSRF fields, are swapped for the placeholder. Typing into one starts from empty. Real values are restored for the instant of a submit, click or Enter so the page still works, then masked again. |
| Page load | With an automation signal present the page stays blank until the first scan has put covers up (max 1.5 s). |
| New content | Rescan every 40 ms while the shield is up; median 3 ms from insertion to redacted in the benchmark. |

**Turning on:** `Auto` (default) switches on when `navigator.webdriver` is true (Playwright, Puppeteer, many agent browsers)
or when the service worker sees a debugger client attached to the tab (`chrome.debugger.getTargets()`, the `debugger`
permission; the extension never attaches, so no infobar). `Always on` is the fail-closed choice for agents that hide both
signals. Opening DevTools also counts as a debugger client.

**Measured** (`python -m eval.shield_eval`, real Chromium with this extension, 5 synthetic scenario pages, 34 sensitive
items; screenshots taken with `page.screenshot()` like a CDP agent, read back with local OCR):

- Baseline, shield off: OCR reads 21 of the values (so a zero below is meaningful).
- Shield on: **0** values readable by OCR, **0** in `innerText`, **0** in `input.value`.
- Non-sensitive text still readable (context kept): 100%. Form-field cover: 87% mean pixel coverage, every field above 85%.
- Focusing a field keeps it covered (95%). Insert-to-redacted latency: median 3 ms, max 4.5 ms.
- These claims cover the tested pages and these two channels (screenshot, DOM read) only.

**Photos, faces and text in pictures.** In shield mode each photo-sized image (64 px and up) is analysed once by a
bundled face detector (`lib/vendor/tracking-min.js` + `face-min.js`, tracking.js, BSD, Viola-Jones; runs in the service
worker, cross-origin pixels included because the worker fetches them with host permission) and covered **per face**,
object-fit aware. Until the answer is in, and if analysis fails, the whole image is covered (fail closed). If the local Zen
server is running, its OCR/OpenCV boxes are added, so text inside images and canvases is covered too; canvases are
re-analysed every 2 s, and without the server a canvas is covered whole. Setting `shieldImages`: `detect` (default),
`all` (cover every photo) or `hinted`.
Test portrait: NASA public-domain astronaut photo (`testpages/img/nasa_pd_1.png`).

**Copying.** Copy, cut and drag of covered content put `[REDACTED:KIND]` on the clipboard; covers over text and media block
clicks and selection starts. Closed shadow roots are scanned (`chrome.dom.openOrClosedShadowRoot`).

**Known gaps:** faces the Viola-Jones cascade misses (profile, small, occluded) are not covered; video that is not a live
camera stream is only covered by hint; text inside images without the local server running is not read; an agent that runs JavaScript in the page's
*main world* can read the page's own variables (we protect what the DOM shows, not what the app's scripts hold);
detection is regex/structure based (see Limitations below).

## Install

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose this `extension/` folder.
4. Pin Zen from the puzzle-piece menu. Tabs that were already open need a reload, or one click on the Zen icon, which injects the scripts into that tab.

Optional: start the local server (`.venv/bin/python -m app.server`). The popup's status dot turns green, and screenshot redaction gets an extra OCR pass. If you run the server in LAN mode, enter its token under **Options**.

## Features

| Feature | Where | Notes |
|---|---|---|
| Local PII detection | `lib/detect.js` | Port of `zenlens/detect.py`: API keys (sk-, AKIA, ghp_, AIza, xox*, `aws_secret_access_key`), JWT, card + Luhn, Aadhaar + Verhoeff, PAN, email, Indian phone (same lookbehinds and validator), IPv4/IPv6 (with `ipaddress` rules), password, OTP, and Devanagari-digit normalisation. Also includes `redact`, a fail-closed `egressCheck`/`gate`, and user-defined rules. |
| Structural detection | `lib/structural.js` | Port of `structural._rule`. Uses `type=password`, `autocomplete` (cc-*, one-time-code, ...), and name/id/class/placeholder/label hints (OTP, CVV, PIN, token, secret, API key, Aadhaar, PAN, ...). Fields are flagged even when their value would not match a regex. |
| Highlight | content script | Each sensitive text span or field gets a coloured outline and a badge showing its kind. Everything is drawn in a closed shadow-root overlay, so the page DOM and input values are never changed. |
| Mask on screen | popup toggle | Blurs and covers every finding with `backdrop-filter`. The overlay ignores pointer events, so you can still click and type. A field you are typing in drops its mask while focused so you can see your input. |
| Dynamic pages | content script | A `MutationObserver` and input/change events trigger a rescan, throttled to at most one every 600 ms. The overlay is redrawn on scroll and resize. |
| Paste / submit guard | `content/guard.js` | Runs on the AI sites in your list (default: chat.openai.com, chatgpt.com, claude.ai, gemini.google.com, copilot.microsoft.com, perplexity.ai). It intercepts paste and Enter/send/submit in the prompt box. If PII is found, a dialog offers **Send sanitized** (the default; values become `[REDACTED:KIND]`), **Send anyway**, or **Cancel**. If the editor rejects the sanitized text, the message is **not** sent (fail closed). |
| Popup | `popup/` | Counts per kind with a short explanation of each, the mask toggle, **Copy sanitized page text**, **Privacy preview** (opens the side panel), a server status dot, and a Local-only badge. |
| Side panel | `sidepanel/` | Before/after view of the page text with highlights, plus a table showing what an AI would see for each sensitive form field. **Redact a screenshot**: captures the tab, blacks out the DOM boxes of every finding locally, then optionally sends the *already-redacted* image to the local server's `/api/redact_image` for OCR. Download the result as PNG. |
| Context menu | background | **Redact selection & copy**: copies the selection with `[REDACTED:KIND]` placeholders. |
| Options | `options/` | Server URL (localhost:8765 or 127.0.0.1:8765) and token, AI-site list, custom rules (kind + regex, validated, with a live test box), site allow/deny list, and behaviour toggles. |

## Permissions and why each is needed

| Permission | Why |
|---|---|
| `activeTab` | `captureVisibleTab` for screenshot redaction, and injecting the scripts into tabs opened before install. Granted only when you click the icon or the context menu. |
| `storage` | Settings in `chrome.storage.sync`. Only configuration is stored, never detected values. |
| `debugger` | Read-only: `chrome.debugger.getTargets()` tells the shield whether an agent is attached to a tab. We never call `attach`. |
| `scripting` | Injects the content scripts on demand (see `activeTab`). |
| `sidePanel` | The Privacy preview panel. |
| `contextMenus` | "Redact selection & copy". |
| host `http://localhost:8765/*`, `http://127.0.0.1:8765/*` | The optional local Zen server, and nothing else. The extension CSP also sets `connect-src` to these two origins. |
| content scripts on `<all_urls>`, all frames, `document_start` | The shield must be up before first paint and inside iframes (payment forms). Sensitive data can be on any page (banking, HR, cloud consoles), and the paste guard has to be in place *before* you paste. That is why the scripts load on every page instead of on request. They do no network I/O. Use the deny list, or allow-list mode, to limit where they run. |

## Privacy guarantees

- **Detection is local.** The detector and classifier are plain JS bundled in the extension. There is no remote code, CDN or analytics.
- **Network:** content scripts never call `fetch`. The service worker makes plain GET requests for images it analyses (needs `<all_urls>` host access and a wide `connect-src`) and POSTs image bytes only to the local server on `localhost:8765`. Nothing is sent to any other host. The screenshot is blacked out locally *before* it is sent to the local OCR server.
- **Nothing is persisted.** Findings live only in page memory and hold element/range references and kinds, not copies of values. Settings hold configuration only.
- **The page is not changed.** Highlights and masks are an overlay, and input values are never rewritten. The single exception is the guard: when you choose "Send sanitized" or "Paste sanitized", the text of the prompt box you are using is replaced.
- **The guard does not send anything.** The site's own UI sends whatever is in the box.

## Limitations

- Regex/checksum detection only. There is no NER, so free-text names and addresses are flagged only when the field structure says so (`autocomplete=name`, `.participant-name`, ...). The adversarial cases in `eval/cases.jsonl` (spaced digits, "at/dot" emails, zero-width characters) are mostly missed, exactly as in the Python version.
- The detector shares the Python version's false positives, e.g. PAN-shaped coupon codes (`checkout-016/017`).
- Only the top frame is scanned (`all_frames: false`). Iframes, closed shadow DOMs, canvas, images and video are not scanned. Screenshot OCR covers images only when the server is running.
- Only what is visible is highlighted: hidden inputs (e.g. `<input type=hidden name=csrf_token>`) are not flagged. In-browser checks against `testpages/*.truth.json` found 35/36 items; the miss is the hidden CSRF field on dev_settings.
- Chrome blocks extensions on `chrome://` pages, the Web Store and the built-in PDF viewer.
- The guard relies on common prompt-box and send-button selectors. A heavily custom editor could bypass the guard, for example sending through a path other than Enter, a send button or form submit, or one that ignores `execCommand('insertText')`. Drag-and-drop and file uploads are not inspected.
- The mask is visual (CSS). It does not stop the page's own scripts from reading values.
- Screenshot capture needs the `activeTab` grant: click the toolbar icon on the tab first.

## Development

```bash
node --test extension/tests/                              # parity + unit tests (Node 18+; tested on 24)
.venv/bin/python extension/tests/dump_py.py               # refresh Python reference spans (run from Zen/)
node extension/tools/make_icons.mjs                       # regenerate icons
```

`tests/parity.test.mjs` checks the following:

1. Against `eval/cases.jsonl` truth, every non-adversarial, non-known_gap case must give the same `(value, kind)` set as the truth. Mismatches that the Python reference makes identically are reported as shared detector gaps, not as port bugs.
2. The JS spans equal Python's `detect()` spans exactly, as code-point offsets, on *all* cases.
3. The same exact-span check on 20 Unicode edge-case texts: dotless-ı and long-ſ case folding, NBSP/BOM/`\x1c` whitespace, emoji offsets, Devanagari digits, IPv6 variants and phone lookbehinds.
4. The `element_kind` parity on 30 synthetic element descriptors.
