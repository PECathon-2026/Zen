# Zen: PS-004 PrivacyLens (PECathon 2026)

Goal: AI agent that interacts with web interfaces while sensitive data never reaches an external model.
Core rule: compute what is sensitive locally; reason globally only on sanitized data.
Stack: Python 3.14, pytest, Playwright (Chromium), Apple Vision / Tesseract OCR, OpenCV (faces), Claude API (`anthropic`), FastAPI web app + PWA, Chrome MV3 extension. Reference-only third-party repo: `~/Desktop/Github-C` (do not copy code from it).

## Commands
- Setup: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python -m playwright install chromium`
- Tests: `.venv/bin/python -m pytest -q`; extension: `node --test extension/tests/`
- Eval: `.venv/bin/python -m eval.run_eval` (exit 1 on any counted leak); regenerate cases: `.venv/bin/python -m eval.make_cases`
- Inference red-team: `.venv/bin/python -m eval.inference.run` (exit 1 on a non-known_gap leak after minimize)
- Demo: `.venv/bin/python demo/run_demo.py --yes`
- Web app: `.venv/bin/python -m app.server` (add `--lan` for phone access, `--lan --https` with mkcert for PWA install / share target)

## Layout
- `zenlens/`: detect, sanitize, pseudonym, minimize, gate, structural, screenshot, capture, browser, vault, llm, executor, agent, runner (see README "Modules")
- `testpages/`: synthetic pages + `.truth.json`; `injection.html` for prompt-injection tests
- `eval/`: `make_cases.py` (fixed seed) -> `cases.jsonl`; `run_eval.py` metrics; `eval/inference/` red-team (scenarios, attackers, run)
- `demo/`: `serve.py` (localhost test server), `run_demo.py` (narrated demo)
- `app/`: local server + PWA; `extension/`: Chrome MV3 extension with JS detector port

## Remaining ideas
- NER for names/addresses; adversarial obfuscation (spaced digits, "at/dot" emails, zero-width chars)
- detect.py misses values glued to `_`/`-` (`statement_<card>.pdf`, `tel-<phone>`): 8 `detector_gap` red-team scenarios
- Port `minimize` to the extension's paste guard; run the Claude attacker (`--claude`) once a key is available
- Live agent-step streaming in the web app (runner's `on_step` + SSE); HTTPS for phone PWA install
- Load-test the extension in a real Chrome profile and on live AI chat sites
- Fully local model option (bonus)

## Rules
- Use synthetic data only; never real PII.
- Any code path sending data externally must call `egress_check` first and fail closed.
- Pseudonymize before minimize (minimize protects `[EMAIL_1]`-style tokens); never put partial values (last-4, domains) in tokens.
- Every new detector gets a labelled case in `eval/make_cases.py` (then regenerate) and a test.
- JS detector in `extension/lib/detect.js` must stay in parity with `zenlens/detect.py` (parity test).
- Local test servers bind `localhost`, never `127.0.0.1` (IPs are detected and blocked by the gate).

## Git
- Two remotes: `origin` (ShadowIzzHerZ/ZenLens) and `pecathon` (PECathon-2026/Zen). `git push origin main` pushes to both (two push URLs on origin). Push both on every push.
- No `Co-Authored-By` trailers in commits.
- GitHub push protection blocks secret-shaped strings, even synthetic ones: keep test tokens non-vendor-shaped (e.g. `xoxb-SYNTHETIC-...`).
