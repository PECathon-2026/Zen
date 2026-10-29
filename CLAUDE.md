# ZenLens: PS-004 PrivacyLens (PECathon 2026)

Goal: AI agent that interacts with web interfaces while sensitive data never reaches an external model.
Core rule: compute what is sensitive locally; reason globally only on sanitized data.
Stack: Python 3, pytest, Playwright (planned), Claude API (planned).

## Commands
- Setup: `python3 -m venv .venv && .venv/bin/pip install pytest`
- Tests: `.venv/bin/python -m pytest -q`
- Eval: `.venv/bin/python -m eval.run_eval` (prints recall, precision, leaks; exit 1 on any leak)

## Done
- `zenlens/detect.py`: regex + Luhn/Verhoeff for CARD, AADHAAR, PAN, EMAIL, PHONE, API_KEY, OTP, PASSWORD
- `zenlens/sanitize.py`: `[REDACTED:KIND]` placeholders
- `zenlens/gate.py`: fail-closed egress check, canary support, raises `Blocked`
- `eval/run_eval.py`: 8 synthetic text cases, recall/precision/leakage
- `tests/test_core.py`: 5 tests passing

## TODO (priority order)
1. **Test pages**: 5 synthetic local HTML pages with annotated ground truth: checkout (card, address), auth (password, email, OTP), support chat (phones, messages), video call (faces, participant names), dev settings (API keys, tokens, IPs).
2. **Structural detector**: DOM/accessibility-tree analysis (`type=password`, `autocomplete=cc-number`, labels such as OTP/CVV). Add IP address detection.
3. **Playwright capture**: page -> DOM + screenshot, sanitize DOM text before anything leaves.
4. **Screenshot redaction**: OCR (Tesseract/EasyOCR) boxes + blackout; optional face detection (OpenCV), NER (spaCy).
5. **Agent loop**: LLM/VLM sees only sanitized view and returns actions (`click(id)`, `type(id, text)`). Executor validates target exists, rejects unsafe ops, requires user approval for sensitive/irreversible actions. Real secrets injected locally via `{{SECRET:name}}` placeholders; model never sees them.
6. **Safety**: block model from inferring redacted values; prompt-injection test page; egress gate wraps every external call; no PII in logs/metadata; minimal retention.
7. **UI/preview**: before/after privacy preview, redaction explanations, optional local-only mode.
8. **Eval**: grow dataset incl. hard negatives and mixed-language text; metrics: PII recall, redaction precision, leakage (canary values), context preservation, task success, latency. Results must be reproducible by script. Claim zero leakage only for tested scenarios/pathways.
9. **Deliverables**: README with architecture diagram + data flow, setup, methodology, action validation, security assumptions/limitations, eval method; 2-3 min demo (detect, sanitize, AI task, blocked unsafe payload).
10. **Bonus**: fully local AI, adaptive redaction, user-defined privacy rules, canary leak automation, human approval flow.

## Rules
- Use synthetic data only; never real PII.
- Any code path sending data externally must call `egress_check` first and fail closed.
- Every new detector gets a labelled case in `eval/run_eval.py` and a test.
