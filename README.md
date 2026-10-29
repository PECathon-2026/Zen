# ZenLens (PS-004: privacy-preserving AI browser agent)

Rule: compute what is sensitive locally; reason globally only on sanitized data.

## Layout
- `zenlens/detect.py`: regex + Luhn/Verhoeff detection (card, Aadhaar, PAN, email, phone, API key, OTP, password)
- `zenlens/sanitize.py`: `[REDACTED:KIND]` placeholders
- `zenlens/gate.py`: fail-closed egress check (detected PII or canary => `Blocked`)
- `eval/run_eval.py`: recall, precision, leakage on synthetic labelled cases
- `tests/`: pytest

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate && pip install pytest
python -m pytest -q
python -m eval.run_eval
```

## TODO (build order)
Playwright capture, screenshot OCR redaction, LLM action loop + executor validation, approval flow, prompt-injection page, demo video.

