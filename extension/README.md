# ZenLens Chrome extension (Manifest V3)

ZenLens in your own browser. It finds sensitive data on the pages you visit, can mask it on screen, and checks what you paste or send into AI chat sites. All detection runs inside the extension. The optional local ZenLens server (`http://localhost:8765`) is used only for screenshot OCR.

## Install

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and choose this `extension/` folder.
4. Pin ZenLens from the puzzle-piece menu. Tabs that were already open need a reload, or one click on the ZenLens icon, which injects the scripts into that tab.

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
| `scripting` | Injects the content scripts on demand (see `activeTab`). |
| `sidePanel` | The Privacy preview panel. |
| `contextMenus` | "Redact selection & copy". |
| host `http://localhost:8765/*`, `http://127.0.0.1:8765/*` | The optional local ZenLens server, and nothing else. The extension CSP also sets `connect-src` to these two origins. |
| content scripts on `<all_urls>` | Sensitive data can be on any page (banking, HR, cloud consoles), and the paste guard has to be in place *before* you paste. That is why the scripts load on every page instead of on request. They do no network I/O. Use the deny list, or allow-list mode, to limit where they run. |

## Privacy guarantees

- **Detection is local.** The detector and classifier are plain JS bundled in the extension. There is no remote code, CDN or analytics.
- **No network traffic except the local server.** Content scripts never call `fetch`. Extension pages are limited by CSP to `localhost:8765` and `127.0.0.1:8765`. The screenshot is blacked out locally *before* it is sent to the local OCR server.
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
.venv/bin/python extension/tests/dump_py.py               # refresh Python reference spans (run from ZenLens/)
node extension/tools/make_icons.mjs                       # regenerate icons
```

`tests/parity.test.mjs` checks the following:

1. Against `eval/cases.jsonl` truth, every non-adversarial, non-known_gap case must give the same `(value, kind)` set as the truth. Mismatches that the Python reference makes identically are reported as shared detector gaps, not as port bugs.
2. The JS spans equal Python's `detect()` spans exactly, as code-point offsets, on *all* cases.
3. The same exact-span check on 20 Unicode edge-case texts: dotless-ı and long-ſ case folding, NBSP/BOM/`\x1c` whitespace, emoji offsets, Devanagari digits, IPv6 variants and phone lookbehinds.
4. The `element_kind` parity on 30 synthetic element descriptors.
