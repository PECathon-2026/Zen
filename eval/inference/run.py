"""Inference red-team benchmark: recovery of redacted values, plain redaction vs redaction + minimize.

Run:  python -m eval.inference.run [--json out.json] [--verbose] [--claude]
Data: eval/inference/scenarios.jsonl (python -m eval.inference.make_scenarios).

Pipeline per scenario: synthetic elements -> capture.sanitized_view (the real redaction + gate path)
  (a) plain     : attacker sees the sanitized view
  (b) minimized : attacker sees zenlens.minimize.minimize_view(sanitized view)
A view the gate blocks counts as "blocked" (nothing leaves, nothing to infer).
Metrics per category: exact recovery rate, leak rate (exact, >=1 bit narrowed, or re-identified), mean bits
leaked. Utility cost: fraction of non-sensitive tokens minimize changes on eval/cases.jsonl (hard negatives
and all cases), after normal redaction.
Exit 1 if any non-known_gap secret still leaks to the offline attacker after minimize.
Reports print rates and rule names only, never secret values.
"""
from __future__ import annotations

import argparse
import difflib
import json
from collections import defaultdict
from pathlib import Path

from eval.inference.attack import ClaudeAttacker, OfflineAttacker, assess_scenario
from eval.inference.make_scenarios import OUT as SCENARIOS_PATH, load
from eval.run_eval import load_cases
from zenlens.capture import Element, PageSnapshot, sanitized_view
from zenlens.gate import Blocked
from zenlens.minimize import minimize, minimize_view
from zenlens.sanitize import redact

CATEGORIES = ("partial", "recompute", "quasi_id", "cross_field", "context")


def plain_view(sc: dict) -> dict | None:
    els = [Element(**{k: v for k, v in e.items() if v is not None or k == "value"}) for e in sc["elements"]]
    snap = PageSnapshot(url=sc["url"], title=sc["title"], elements=els, html="", screenshot=b"")
    try:
        return sanitized_view(snap)
    except Blocked:
        return None


def views(sc: dict) -> dict[str, dict | None]:
    v = plain_view(sc)
    return {"plain": v, "minimized": minimize_view(v)[0] if v is not None else None}


def utility_cost(cases: list[dict] | None = None) -> dict:
    cases = load_cases() if cases is None else cases
    out = {}
    for name, subset in (("hard_negatives", [c for c in cases if "hard_negative" in c["tags"]]), ("all_cases", cases)):
        total = changed = 0
        for c in subset:
            a = redact(c["text"])[0].split()
            b = minimize(" ".join(a))[0].split()
            keep = [i for i, t in enumerate(a) if "[REDACTED:" not in t]
            same = set()
            for blk in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_matching_blocks():
                same.update(range(blk.a, blk.a + blk.size))
            total += len(keep)
            changed += sum(1 for i in keep if i not in same)
        out[name] = {"tokens": total, "changed": changed, "fraction": changed / total if total else 0.0}
    return out


def evaluate(scenarios: list[dict], attacker=None) -> dict:
    attacker = attacker or OfflineAttacker()
    rows, failing, blocked = [], [], defaultdict(int)
    for sc in scenarios:
        vs = views(sc)
        for mode, v in vs.items():
            if v is None:
                blocked[mode] += 1
            for i, res in enumerate(assess_scenario(sc, v, attacker)):
                rows.append({"id": sc["id"], "category": sc["category"], "subcategory": sc["subcategory"],
                             "mode": mode, "secret": i, "known_gap": "known_gap" in sc["tags"],
                             "detector_gap": "detector_gap" in sc["tags"], "expect": sc["expect"], **res})
                if mode == "minimized" and res["leak"] and "known_gap" not in sc["tags"]:
                    failing.append(f"{sc['id']}#{i}")
    table = {}
    for cat in CATEGORIES:
        table[cat] = {}
        for mode in ("plain", "minimized"):
            rs = [r for r in rows if r["category"] == cat and r["mode"] == mode]
            n = len(rs) or 1
            table[cat][mode] = {"secrets": len(rs), "exact": sum(r["recovered"] for r in rs) / n,
                                "leak": sum(r["leak"] for r in rs) / n,
                                "mean_bits_leaked": sum(r["leaked_bits"] for r in rs) / n}
    unmet = [r["id"] for r in rows if r["mode"] == "plain" and not r["leak"]]
    return {"scenarios": len(scenarios), "by_category": table, "rows": rows, "failing": failing,
            "blocked": dict(blocked), "plain_not_leaking": unmet, "utility": utility_cost(),
            "by_category_counts": {c: sum(1 for s in scenarios if s["category"] == c) for c in CATEGORIES}}


def claude_eval(scenarios: list[dict]) -> dict:
    if not ClaudeAttacker.available():
        return {"skipped": "ANTHROPIC_API_KEY not set"}
    att, out = ClaudeAttacker(), defaultdict(lambda: {"n": 0, "exact": 0, "prefix": 0.0})
    for sc in scenarios:
        for mode, v in views(sc).items():
            try:
                res = att.score(sc, v)
            except Blocked:
                continue
            for r in res:
                if r.get("skipped"):
                    continue
                t = out[f"{sc['category']}/{mode}"]
                t["n"] += 1; t["exact"] += r["exact"]; t["prefix"] += r["prefix_frac"]
    return {k: {"n": v["n"], "exact": v["exact"] / v["n"], "mean_prefix": v["prefix"] / v["n"]} for k, v in out.items()}


def print_report(r: dict, verbose: bool = False) -> None:
    print(f"ZenLens inference red-team: {r['scenarios']} scenarios ({r['by_category_counts']})\n")
    print(f"  {'category':<12} {'n':>3} | {'plain exact':>11} {'leak':>6} {'bits':>6} | {'min exact':>9} {'leak':>6} {'bits':>6}")
    for cat, m in r["by_category"].items():
        p, q = m["plain"], m["minimized"]
        print(f"  {cat:<12} {p['secrets']:>3} | {p['exact']:>11.2f} {p['leak']:>6.2f} {p['mean_bits_leaked']:>6.1f} |"
              f" {q['exact']:>9.2f} {q['leak']:>6.2f} {q['mean_bits_leaked']:>6.1f}")
    print("  (leak = exact recovery, >=1 bit narrowed, or re-identified: anonymity set < K_ANON)")
    if verbose:
        print("\nPer scenario (bits left plain -> minimized)")
        by = defaultdict(dict)
        for row in r["rows"]:
            by[(row["id"], row["secret"])][row["mode"]] = row
        for (sid, i), m in by.items():
            p, q = m["plain"], m["minimized"]
            tag = "GAP " if p["known_gap"] else "DET " if p["detector_gap"] else "    "
            print(f"  {tag}{sid:<16} {p['subcategory']:<28} {p['bits_left']:>6.1f} -> {q['bits_left']:>6.1f}"
                  f"  leak {p['leak']!s:<5} -> {q['leak']!s:<5} {','.join(p['rules'])}")
    u = r["utility"]
    print(f"\nUtility cost of minimize: hard negatives {u['hard_negatives']['changed']}/{u['hard_negatives']['tokens']}"
          f" tokens changed ({u['hard_negatives']['fraction']:.3f}); all cases {u['all_cases']['changed']}/"
          f"{u['all_cases']['tokens']} ({u['all_cases']['fraction']:.3f})")
    gaps = sorted({row["id"] for row in r["rows"] if row["mode"] == "minimized" and row["leak"] and row["known_gap"]})
    print(f"Gate-blocked views: {r['blocked'] or 'none'} | known_gap still leaking after minimize: {gaps or 'none'}")
    if r["plain_not_leaking"]:
        print(f"Scenarios the offline attacker could not exploit even in plain mode: {r['plain_not_leaking']}")
    print(f"FAILING (non-known_gap leak after minimize): {r['failing'] or 'none'}")
    if "claude" in r:
        print(f"Claude attacker: {r['claude']}")
    print("Claims cover only these synthetic scenarios and this offline attacker; an LLM may infer more.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scenarios", default=str(SCENARIOS_PATH))
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--claude", action="store_true", help="also run ClaudeAttacker (needs ANTHROPIC_API_KEY)")
    a = ap.parse_args(argv)
    scenarios = load(a.scenarios)
    r = evaluate(scenarios)
    if a.claude:
        r["claude"] = claude_eval(scenarios)
    print_report(r, a.verbose)
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if r["failing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
