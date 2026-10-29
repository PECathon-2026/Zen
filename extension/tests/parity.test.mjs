// Parity tests: JS port (extension/lib/detect.js, structural.js) vs Python (zenlens/).
// Run: node --test extension/tests/
// Regenerate Python reference spans: .venv/bin/python extension/tests/dump_py.py  (from the ZenLens dir)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const Z = require("../lib/detect.js");
const ST = require("../lib/structural.js");

const cases = readFileSync(join(here, "../../eval/cases.jsonl"), "utf8")
  .split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
const scored = cases.filter((c) => !c.tags.includes("adversarial") && !c.tags.includes("known_gap"));

/** UTF-16 offset -> Python code-point offset. */
const cp = (text, i) => Array.from(text.slice(0, i)).length;
const jsSpansCp = (text) => Z.detect(text).map((s) => [cp(text, s.start), cp(text, s.end), s.kind]);
const key = (pairs) => pairs.map((p) => JSON.stringify(p)).sort();

const pyPath = join(here, "py_spans.json");
const py = existsSync(pyPath) ? JSON.parse(readFileSync(pyPath, "utf8")) : null;

// A miss/false positive that the Python reference makes identically is a detector-level gap shared by
// both implementations (reported, not a port bug). Any JS-only divergence fails.
test("truth (value, kind) set matches for every non-adversarial, non-known_gap case", () => {
  const fails = [], inherited = [];
  for (const c of scored) {
    const got = Z.detect(c.text).map((s) => [c.text.slice(s.start, s.end), s.kind]);
    if (JSON.stringify(key(got)) === JSON.stringify(key(c.truth))) continue;
    const pyGot = py && py.cases[c.id] && JSON.stringify(jsSpansCp(c.text)) === JSON.stringify(py.cases[c.id]);
    (pyGot ? inherited : fails).push({ id: c.id, got, truth: c.truth });
  }
  console.log(`truth parity: ${scored.length - fails.length - inherited.length}/${scored.length} exact; ` +
    `${inherited.length} shared with Python reference: ${inherited.map((f) => f.id).join(", ") || "none"}`);
  assert.deepEqual(fails, []);
});

test("exact span parity with Python detect() on ALL cases (incl. adversarial)", { skip: !py && "run dump_py.py first" }, () => {
  const fails = [];
  for (const c of cases) {
    const got = jsSpansCp(c.text), want = py.cases[c.id];
    if (JSON.stringify(got) !== JSON.stringify(want)) fails.push({ id: c.id, got, want });
  }
  console.log(`python span parity: ${cases.length - fails.length}/${cases.length} cases`);
  assert.deepEqual(fails, []);
});

test("exact span parity on Unicode / edge-case texts", { skip: !py && "run dump_py.py first" }, () => {
  const texts = JSON.parse(readFileSync(join(here, "extra_texts.json"), "utf8"));
  const fails = [];
  texts.forEach((t, i) => {
    const got = jsSpansCp(t);
    if (JSON.stringify(got) !== JSON.stringify(py.extra[i])) fails.push({ i, t, got, want: py.extra[i] });
  });
  console.log(`edge-case parity: ${texts.length - fails.length}/${texts.length}`);
  assert.deepEqual(fails, []);
});

test("structural element_kind parity", { skip: !py && "run dump_py.py first" }, () => {
  const els = JSON.parse(readFileSync(join(here, "elements.json"), "utf8"));
  const got = els.map((e) => ST.elementKind(e));
  assert.deepEqual(got, py.elements);
});

// ---------- direct unit tests ----------
test("checksums", () => {
  assert.ok(Z.luhnOk("4111111111111111"));
  assert.ok(!Z.luhnOk("4111111111111112"));
  const payload = "23456789012";
  const full = payload + Z.verhoeffCheckDigit(payload);
  assert.ok(Z.verhoeffOk(full));
  assert.ok(!Z.verhoeffOk(payload + String((+Z.verhoeffCheckDigit(payload) + 1) % 10)));
});

test("ipv6 validator", () => {
  for (const ok of ["fd00:1234:5678::25", "2001:db8:0:0:0:0:2:1", "fe80::1:2:3"]) assert.ok(Z.ipv6Ok(ok), ok);
  for (const bad of ["a::b", "::1", "1:2:3:4:5:6:7:8:9", ":::1", "1::2::3", "12345::1:2"]) assert.ok(!Z.ipv6Ok(bad), bad);
});

test("redact + Devanagari digits", () => {
  const r = Z.redact("नंबर ६२७०६१९७८७ mail a@b.co");
  assert.equal(r.text, "नंबर [REDACTED:PHONE] mail [REDACTED:EMAIL]");
});

test("egress gate fails closed", () => {
  assert.equal(Z.egressCheck("hello world"), "hello world");
  assert.throws(() => Z.egressCheck("card 4111 1111 1111 1111"), /CARD/);
  assert.throws(() => Z.egressCheck("benign CANARY-77", ["CANARY-77"]), /CANARY/);
  assert.throws(() => Z.egressCheck(null), /scanner error/);
  assert.deepEqual(Z.gate("ok"), { allowed: true, reason: "clean" });
});

test("detectAll extras + custom rules", () => {
  const { rules, errors } = Z.compileCustomRules([
    { kind: "EMP_ID", pattern: "EMP-\\d{6}" }, { kind: "bad kind!", pattern: "x" },
    { kind: "EMPTY", pattern: "a*" }, { kind: "BROKEN", pattern: "(" },
  ]);
  assert.equal(rules.length, 1);
  assert.equal(errors.length, 3);
  const r = Z.redactAll("Authorization: Bearer abcdefghijklmnop1234 for EMP-123456", rules);
  assert.equal(r.text, "Authorization: Bearer [REDACTED:TOKEN] for [REDACTED:EMP_ID]");
});

test("structural rules on synthetic fields", () => {
  assert.deepEqual(ST.rule({ tag: "input", attrs: { type: "password" } }), ["PASSWORD", "type=password"]);
  assert.deepEqual(ST.rule({ tag: "input", attrs: { autocomplete: "one-time-code" } }), ["OTP", "autocomplete=one-time-code"]);
  assert.deepEqual(ST.rule({ tag: "input", attrs: { id: "f3" } }, "CVV / CVC"), ["CVV", "label:cvv"]);
  assert.equal(ST.rule({ tag: "input", attrs: { name: "username" } }), null);
});
