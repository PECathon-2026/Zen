"""Dump Python detector output so the JS port can be compared span-for-span.

Run from the ZenLens dir:  .venv/bin/python extension/tests/dump_py.py
Writes extension/tests/py_spans.json (code-point offsets, synthetic eval data only).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from zenlens.detect import detect  # noqa: E402
from zenlens.structural import element_kind  # noqa: E402

HERE = Path(__file__).resolve().parent
cases = [json.loads(l) for l in open(ROOT / "eval" / "cases.jsonl", encoding="utf-8") if l.strip()]
extra = json.loads((HERE / "extra_texts.json").read_text(encoding="utf-8"))
elements = json.loads((HERE / "elements.json").read_text(encoding="utf-8"))

out = {
    "cases": {c["id"]: [[s.start, s.end, s.kind] for s in detect(c["text"])] for c in cases},
    "extra": [[[s.start, s.end, s.kind] for s in detect(t)] for t in extra],
    "elements": [element_kind(e) for e in elements],
}
(HERE / "py_spans.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
print(f"wrote {len(out['cases'])} cases, {len(out['extra'])} extra texts, {len(out['elements'])} elements")
