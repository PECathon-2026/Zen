import json

from eval import make_cases, run_eval

KINDS = {"CARD", "AADHAAR", "PAN", "EMAIL", "PHONE", "API_KEY", "OTP", "PASSWORD", "IP", "NAME", "TOKEN"}
SCENARIOS = {"checkout", "auth", "support", "video", "devsettings"}


def test_dataset_loads_and_is_well_formed():
    cases = run_eval.load_cases()
    assert 80 <= len(cases) <= 150
    assert len({c["id"] for c in cases}) == len(cases)
    assert {c["scenario"] for c in cases} == SCENARIOS
    tags = {t for c in cases for t in c["tags"]}
    assert {"hard_negative", "mixed_lang", "adversarial", "format_variant", "canary"} <= tags
    for c in cases:
        assert all(k in KINDS for _, k in c["truth"]), c["id"]


def test_generator_is_deterministic_and_file_is_fresh():
    a, b = make_cases.dumps(make_cases.build()), make_cases.dumps(make_cases.build())
    assert a == b
    assert make_cases.OUT.read_text(encoding="utf-8") == a, "run: python -m eval.make_cases"
    assert make_cases.dumps(make_cases.build(seed=1)) != a  # seed actually drives values


def test_truth_values_and_canaries_appear_in_text():
    for c in run_eval.load_cases():
        for value, _ in c["truth"]:
            assert value in c["text"], (c["id"], value)
        for canary in c["canaries"]:
            assert canary in c["text"], c["id"]


def test_run_eval_main_runs(tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = run_eval.main(["--json", str(out), "--repeat", "1"])
    assert rc in (0, 1)
    r = json.loads(out.read_text(encoding="utf-8"))
    assert r["cases"] == len(run_eval.load_cases())
    assert 0 <= r["overall"]["recall"] <= 1 and 0 <= r["context_preservation"] <= 1
    assert r["canaries"]["leaked"] == 0
    assert rc == (1 if r["failing_leaks"] else 0)
    assert "Summary" in capsys.readouterr().out
