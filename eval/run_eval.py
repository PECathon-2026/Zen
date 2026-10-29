"""Reproducible benchmark of the local text detector (detect -> redact -> egress gate).

Run:  python -m eval.run_eval [--json out.json] [--cases eval/cases.jsonl] [--verbose]
Data: eval/cases.jsonl, regenerated deterministically by `python -m eval.make_cases`.

Metrics
- recall / precision: span-level. A truth item is found if a detected span of the SAME kind
  overlaps it; a detection is a false positive if it overlaps no truth item of its kind.
  Broken down per kind and per scenario; adversarial cases are reported separately.
- leakage: a truth value leaks if part of it is not covered by any detected span AND the
  egress gate lets the sanitized text through (gate run without canaries, so the detector
  pathway is measured on its own). Canary leakage: each case's canary strings are passed to
  egress_check(sanitized, canaries) and must be blocked.
- context preservation: fraction of whitespace tokens that contain no PII and survive
  redaction unchanged (i.e. are not touched by any detected span).
- latency: mean / p95 milliseconds per detect() call over all cases (REPEAT runs each).
Exit code: 1 if any non-adversarial, non-known_gap case leaks (truth value or canary).
Zero leakage is claimed only for the cases and the text pathway tested here.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
import time
from collections import defaultdict
from pathlib import Path

from zenlens.detect import detect
from zenlens.gate import Blocked, egress_check
from zenlens.sanitize import redact

CASES_PATH = Path(__file__).with_name("cases.jsonl")
REPEAT = 20


def load_cases(path: Path | str = CASES_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _truth_spans(case: dict) -> list[tuple[int, int, str, str]]:
    out, used = [], defaultdict(int)
    for value, kind in case["truth"]:
        start = case["text"].find(value, used[value])
        if start < 0:
            raise ValueError(f"{case['id']}: truth value not in text: {value!r}")
        used[value] = start + 1
        out.append((start, start + len(value), value, kind))
    return out


def _gate_passes(text: str, canaries=()) -> bool:
    try:
        egress_check(text, tuple(canaries))
        return True
    except Blocked:
        return False


def _ratio(a: int, b: int) -> float:
    return a / b if b else 1.0


def evaluate(cases: list[dict], repeat: int = REPEAT) -> dict:
    tally = lambda: {"tp": 0, "fn": 0, "fp": 0}  # noqa: E731
    by_kind, by_scen = defaultdict(tally), defaultdict(tally)
    overall, adv = tally(), tally()
    misses, false_pos, leaks, gate_saves, overblock = [], [], [], [], []
    canary_total = canary_leaks = 0
    tok_total = tok_kept = 0
    latencies: list[float] = []
    gap_fixed: list[str] = []

    for case in cases:
        text, cid, scen = case["text"], case["id"], case["scenario"]
        tags = set(case["tags"])
        is_adv, is_gap = "adversarial" in tags, "known_gap" in tags
        bucket = adv if is_adv else overall

        for _ in range(repeat):
            t0 = time.perf_counter()
            detect(text)
            latencies.append((time.perf_counter() - t0) * 1000)

        spans = detect(text)
        truth = _truth_spans(case)
        clean, _ = redact(text)
        case_ok = True

        for s, e, value, kind in truth:
            hit = any(d.kind == kind and d.start < e and s < d.end for d in spans)
            for t in (bucket, by_kind[kind], by_scen[scen]) if not is_adv else (bucket,):
                t["tp" if hit else "fn"] += 1
            if not hit:
                case_ok = False
                got = [(text[d.start:d.end], d.kind) for d in spans if d.start < e and s < d.end]
                misses.append({"id": cid, "kind": kind, "value": value, "tags": sorted(tags),
                               "detected_as": got})
            covered = all(any(d.start <= i < d.end for d in spans) for i in range(s, e))
            if not covered:
                if _gate_passes(clean):
                    leaks.append({"id": cid, "kind": kind, "value": value, "adversarial": is_adv,
                                  "known_gap": is_gap, "sanitized": clean})
                else:
                    gate_saves.append({"id": cid, "kind": kind, "value": value})
        for d in spans:
            if not any(k == d.kind and d.start < e and s < d.end for s, e, _, k in truth):
                case_ok = False
                for t in (bucket, by_kind[d.kind], by_scen[scen]) if not is_adv else (bucket,):
                    t["fp"] += 1
                false_pos.append({"id": cid, "kind": d.kind, "value": text[d.start:d.end],
                                  "tags": sorted(tags)})

        for c in case.get("canaries", []):
            canary_total += 1
            if _gate_passes(clean, [c]):
                canary_leaks += 1
                leaks.append({"id": cid, "kind": "CANARY", "value": c, "adversarial": is_adv,
                              "known_gap": is_gap, "sanitized": clean})

        if all(any(d.start <= i < d.end for d in spans) for s, e, _, _ in truth for i in range(s, e)) \
                and not _gate_passes(clean) and not case.get("canaries"):
            overblock.append({"id": cid, "sanitized": clean})

        for m in re.finditer(r"\S+", text):
            if any(m.start() < e and s < m.end() for s, e, _, _ in truth):
                continue
            tok_total += 1
            tok_kept += not any(m.start() < d.end and d.start < m.end() for d in spans)

        if is_gap and case_ok:
            gap_fixed.append(cid)

    def prf(t):
        return {**t, "recall": _ratio(t["tp"], t["tp"] + t["fn"]),
                "precision": _ratio(t["tp"], t["tp"] + t["fp"])}

    lat = sorted(latencies)
    failing = [lk for lk in leaks if not lk["adversarial"] and not lk["known_gap"]]
    return {
        "cases": len(cases),
        "overall": prf(overall),
        "adversarial": prf(adv),
        "by_kind": {k: prf(v) for k, v in sorted(by_kind.items())},
        "by_scenario": {k: prf(v) for k, v in sorted(by_scen.items())},
        "leaks": leaks,
        "failing_leaks": len(failing),
        "canaries": {"total": canary_total, "leaked": canary_leaks},
        "gate_saves": gate_saves,
        "gate_overblock": overblock,
        "context_preservation": _ratio(tok_kept, tok_total),
        "context_tokens": tok_total,
        "latency_ms": {"mean": statistics.fmean(lat), "p95": lat[int(0.95 * (len(lat) - 1))],
                       "calls": len(lat)},
        "misses": misses,
        "false_positives": false_pos,
        "known_gap_now_passing": gap_fixed,
    }


def _row(name, m):
    return (f"  {name:<14} {m['tp']:>4} {m['fn']:>4} {m['fp']:>4} "
            f"{m['recall']:>7.2f} {m['precision']:>9.2f}")


def print_report(r: dict, cases: list[dict], verbose: bool = False) -> None:
    tags = {c["id"]: set(c["tags"]) for c in cases}
    hdr = f"  {'':<14} {'TP':>4} {'FN':>4} {'FP':>4} {'recall':>7} {'precision':>9}"
    print(f"Zen text-detector eval: {r['cases']} cases\n")
    print("Per kind (non-adversarial)\n" + hdr)
    for k, m in r["by_kind"].items():
        print(_row(k, m))
    print("\nPer scenario (non-adversarial)\n" + hdr)
    for k, m in r["by_scenario"].items():
        print(_row(k, m))
    print("\n" + hdr)
    print(_row("OVERALL", r["overall"]))
    print(_row("adversarial", r["adversarial"]))

    print("\nMisses (FN)")
    for m in r["misses"]:
        lab = "ADV " if "adversarial" in m["tags"] else "GAP " if "known_gap" in m["tags"] else "    "
        extra = f"  detected as {m['detected_as']}" if m["detected_as"] else ""
        print(f"  {lab}[{m['id']}] {m['kind']}: {m['value']!r}{extra}")
    print("False positives (FP)")
    for f in r["false_positives"]:
        print(f"  [{f['id']}] {f['kind']}: {f['value']!r}")

    nonadv = [lk for lk in r["leaks"] if not lk["adversarial"]]
    advl = [lk for lk in r["leaks"] if lk["adversarial"]]
    print("\nLeakage (value survives redact AND passes egress gate)")
    for lk in nonadv:
        lab = "known_gap" if lk["known_gap"] else "LEAK"
        print(f"  {lab:<9} [{lk['id']}] {lk['kind']}: {lk['value']!r}")
    print("  Adversarial leaks (known limitations, not counted in exit code):")
    for lk in advl:
        print(f"    [{lk['id']}] {lk['kind']}: {lk['value']!r}")
    if r["gate_saves"]:
        print("  Caught only by the egress gate (redaction incomplete, fail-closed):")
        for g in r["gate_saves"]:
            print(f"    [{g['id']}] {g['kind']}: {g['value']!r}")
    if r["gate_overblock"] and verbose:
        print("  Gate re-flagged fully sanitized text (over-block):")
        for o in r["gate_overblock"]:
            print(f"    [{o['id']}] {o['sanitized']!r}")
    if r["known_gap_now_passing"]:
        print(f"\nknown_gap cases now passing (drop the tag in make_cases.py): {r['known_gap_now_passing']}")

    lat, can = r["latency_ms"], r["canaries"]
    gap_leaks = sum(1 for lk in nonadv if lk["known_gap"])
    print("\nSummary")
    print(f"  recall={r['overall']['recall']:.3f} precision={r['overall']['precision']:.3f} "
          f"(adversarial recall={r['adversarial']['recall']:.3f})")
    print(f"  leaks: failing={r['failing_leaks']} known_gap={gap_leaks} adversarial={len(advl)} "
          f"| canaries blocked {can['total'] - can['leaked']}/{can['total']} "
          f"| gate over-blocks={len(r['gate_overblock'])}")
    print(f"  context preservation={r['context_preservation']:.3f} ({r['context_tokens']} non-PII tokens)")
    print(f"  latency per detect(): mean={lat['mean']:.3f} ms p95={lat['p95']:.3f} ms ({lat['calls']} calls)")
    print("  Zero-leak claim covers only these synthetic text cases and the detect->redact->gate path.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cases", default=str(CASES_PATH))
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--repeat", type=int, default=REPEAT)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)
    cases = load_cases(a.cases)
    r = evaluate(cases, a.repeat)
    print_report(r, cases, a.verbose)
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if r["failing_leaks"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
