/*
 * ZenLens local PII detector: a faithful JS port of zenlens/detect.py (+ redact, egress gate,
 * structural extras). Pure functions, no DOM, no network. Works as a classic script (sets
 * globalThis.ZenLensDetect) in content scripts / extension pages / service worker, and via
 * require() in Node for the parity tests.
 *
 * Python `re` on str is Unicode-aware; JS is not, so the Python classes are emulated:
 *   \w -> [\p{L}\p{N}_]   (Python: str.isalnum() or "_")
 *   \d -> \p{Nd}          \D -> \P{Nd}
 *   \s -> exact str.isspace() set (JS \s differs: it has U+FEFF, lacks \x1c-\x1f and \x85)
 *   \b -> lookaround boundary over the \w class above
 *   (?i) -> explicit per-letter classes including Python's extra case equivalences
 *          (i/I/U+0131/U+0130, s/S/U+017F, k/K/U+212A), since JS /i folds differently.
 * Spans are UTF-16 offsets (what the DOM uses); tests convert to code points for Python parity.
 */
(function (root) {
  "use strict";

  // ---------- checksums (identical tables to detect.py) ----------
  const _D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
    [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
    [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const _P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
    [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  const _INV = [0,4,3,2,1,5,6,7,8,9];

  const ND = /\p{Nd}/u;
  /** Numeric value of any Unicode decimal digit (Python int(ch)). Nd runs are contiguous 0..9 blocks. */
  function digitValue(ch) {
    let cp = ch.codePointAt(0);
    if (cp >= 48 && cp <= 57) return cp - 48;
    let start = cp;
    while (start > 0 && ND.test(String.fromCodePoint(start - 1))) start--;
    return (cp - start) % 10;
  }
  const chars = (s) => Array.from(s); // code points, like Python str iteration

  function verhoeffOk(num) {
    let c = 0;
    chars(num).reverse().forEach((ch, i) => { c = _D[c][_P[i % 8][digitValue(ch)]]; });
    return c === 0;
  }
  function verhoeffCheckDigit(payload) {
    let c = 0;
    chars(payload).reverse().forEach((ch, i) => { c = _D[c][_P[(i + 1) % 8][digitValue(ch)]]; });
    return String(_INV[c]);
  }
  function luhnOk(num) {
    let total = 0;
    chars(num).reverse().forEach((ch, i) => {
      let d = digitValue(ch);
      if (i % 2) d = d > 4 ? d * 2 - 9 : d * 2;
      total += d;
    });
    return total % 10 === 0;
  }
  const digits = (s) => s.replace(/\P{Nd}/gu, "");

  /** Port of ipaddress.IPv6Address(s) validity for strings of [0-9A-Fa-f:] (no scope, no IPv4 tail). */
  function ipv6Valid(s) {
    if (!s || s.length > 45 || s.includes("/")) return false;
    const parts = s.split(":");
    if (parts.length < 3) return false;
    if (parts[parts.length - 1].includes(".")) return false; // regex never yields dots; be strict
    if (parts.length > 9) return false;
    let skip = null;
    for (let i = 1; i < parts.length - 1; i++) {
      if (!parts[i]) { if (skip !== null) return false; skip = i; }
    }
    let hi, lo;
    if (skip !== null) {
      hi = skip; lo = parts.length - skip - 1;
      if (!parts[0]) { hi -= 1; if (hi) return false; }
      if (!parts[parts.length - 1]) { lo -= 1; if (lo) return false; }
      if (8 - (hi + lo) < 1) return false;
    } else {
      if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return false;
      hi = parts.length; lo = 0;
    }
    const hext = (h) => /^[0-9A-Fa-f]{0,4}$/.test(h); // Python int('',16) raises -> empty invalid
    for (let i = 0; i < hi; i++) if (!parts[i] || !hext(parts[i])) return false;
    for (let i = parts.length - lo; i < parts.length; i++) if (!parts[i] || !hext(parts[i])) return false;
    return true;
  }
  function ipv6Ok(s) {
    return ipv6Valid(s) && s.split(":").filter(Boolean).length >= 3;
  }

  // ---------- Python-compatible regex building blocks ----------
  const WC = "\\p{L}\\p{N}_";                      // \w class body
  const W = `[${WC}]`;
  const B = `(?:(?<=${W})(?!${W})|(?<!${W})(?=${W}))`; // \b
  const D = "\\p{Nd}";                              // \d
  const ND_ = "\\P{Nd}";                            // \D
  const SC = "\\t-\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
  const S = `[${SC}]`;                              // \s
  const NS = `[^${SC}]`;                            // \S
  const CASE_EXTRA = { i: "\\u0131\\u0130", s: "\\u017f", k: "\\u212a" };
  /** Python (?i) literal: each ASCII letter becomes a class with its case partners. */
  function ci(word) {
    return word.replace(/[A-Za-z]/g, (c) => {
      const l = c.toLowerCase();
      return `[${l}${l.toUpperCase()}${CASE_EXTRA[l] || ""}]`;
    });
  }
  const AZ_I = "a-zA-Z\\u017f\\u212a\\u0131\\u0130"; // [a-z] / [A-Za-z] under (?i)
  const OCT = `(?:25[0-5]|2[0-4]${D}|1${D}${D}|[1-9]?${D})`;

  const re = (src) => new RegExp(src, "gud");

  // (kind, regex, group, validator). Order = priority when spans overlap. Mirrors detect._RULES.
  const RULES = [
    ["API_KEY", re(`${B}(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,})${B}`), 0, null],
    ["API_KEY", re(`${ci("aws_secret_access_key")}${S}*[:=]${S}*([${AZ_I}0-9/+]{40})(?![${AZ_I}0-9/+])`), 1, null],
    ["TOKEN", re(`${B}eyJ[${WC}-]{10,}\\.[${WC}-]{10,}\\.[${WC}-]{10,}`), 0, null],
    ["CARD", re(`${B}${D}(?:[ .-]{0,2}${D}){12,18}${B}`), 0, (s) => luhnOk(digits(s))],
    ["AADHAAR", re(`${B}[2-9]${D}{3}[ -]?${D}{4}[ -]?${D}{4}${B}`), 0, (s) => verhoeffOk(digits(s))],
    ["PAN", re(`${B}[A-Z]{3}[ABCFGHJLPT][A-Z]${D}{4}[A-Z]${B}`), 0, null],  // 4th letter = PAN holder type
    ["EMAIL", re(`${B}[${WC}.+-]+@[${WC}-]+(?:\\.[${WC}-]+)+${B}`), 0, null],
    ["PHONE", re(`(?<![${WC}#-])(?<!${B}${ci("id")} )(?<!${B}${ci("id")}: )(?<!${B}${ci("id is")} )(?:(?:\\+?91|0)[ -]?)?[6-9]${D}{4}[ -]?${D}{5}${B}`), 0,
      (s) => new Set(chars(digits(s)).slice(-10)).size > 2],
    ["IP", re(`(?<![${WC}.])(?<!${B}${ci("version")} )(?<!${B}${ci("release")} )(?<!${B}${ci("build")} )(?<!${B}${ci("ver")} )(?:${OCT}\\.){3}${OCT}(?!\\.?${D}|${W})`), 0, null],
    ["IP", re(`(?<![${WC}:.])(?=[0-9A-Fa-f:]*[0-9A-Fa-f]:[0-9A-Fa-f]*:)[0-9A-Fa-f:]{3,39}(?![${WC}:])`), 0, ipv6Ok],
    ["PASSWORD", re(`(?<![${AZ_I}])(?:${ci("password")}|${ci("passwd")}|${ci("pwd")}|पासवर्ड)${S}*(?:[:=]|${ci("is")}${B}|${ci("hai")}${B})${S}*(?!\\[${ci("REDACTED")})(?!\\*+(?:${S}|$))(${NS}+?)[,;]?(?=${S}|$)`), 1, null],
    ["OTP", re(`${B}(?:${ci("otp")}|${ci("verification code")}|${ci("one")}[- ]${ci("time")} (?:${ci("code")}|${ci("password")})|${ci("login code")}|${ci("security code")}|${ci("code is")})${ND_}{0,20}?(${D}{4,8})${B}(?!${S}*(?:${ci("seconds")}|${ci("sec")}${ci("s")}?|${ci("minutes")}|${ci("min")}${ci("s")}?)${B})`), 1, null],
  ];

  // Text-only extras from structural.py EXTRA (bearer tokens, short JWTs). Used for page scanning.
  const EXTRA = [
    ["TOKEN", re(`${B}${ci("bearer")}${S}+([A-Za-z0-9._~+/\\-${"\\u017f\\u212a\\u0131\\u0130"}]{16,}=*)`), 1, null],
    ["TOKEN", re(`${B}eyJ[${WC}-]{8,}\\.[${WC}-]{8,}\\.[${WC}-]{8,}`), 0, null],
  ];

  /** Devanagari digits -> ASCII (same length, so spans still map). */
  function normaliseDigits(text) {
    return text.replace(/[०-९]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 0x0966 + 48));
  }

  function runRules(text, rules, spans) {
    for (const [kind, rx, grp, ok] of rules) {
      rx.lastIndex = 0;
      let m;
      while ((m = rx.exec(text)) !== null) {
        if (m[0] === "") { rx.lastIndex++; continue; }
        if (ok && !ok(m[0])) continue;
        const ix = m.indices && m.indices[grp];
        if (!ix) continue;
        const [s, e] = ix;
        if (!spans.some((b) => s < b.end && b.start < e)) spans.push({ start: s, end: e, kind });
      }
    }
    return spans;
  }

  /** Port of detect.detect(): [{start, end, kind}] sorted by start (UTF-16 offsets). */
  function detect(text) {
    const t = normaliseDigits(String(text ?? ""));
    return runRules(t, RULES, []).sort((a, b) => a.start - b.start);
  }

  // ---------- user-defined rules ----------
  const KIND_RE = /^[A-Z][A-Z0-9_]{1,23}$/;
  /** Validate + compile [{kind, pattern}]. Returns {rules, errors}. Rejects bad/empty-matching patterns. */
  function compileCustomRules(list) {
    const rules = [], errors = [];
    (Array.isArray(list) ? list : []).forEach((r, i) => {
      const kind = String(r && r.kind || "").trim().toUpperCase();
      const pattern = String(r && r.pattern || "");
      if (!KIND_RE.test(kind)) { errors.push(`rule ${i + 1}: kind must be A-Z/0-9/_ (2-24 chars)`); return; }
      if (!pattern || pattern.length > 500) { errors.push(`rule ${i + 1}: pattern empty or longer than 500 chars`); return; }
      let rx;
      try { rx = new RegExp(pattern, "gud"); } catch (e) { errors.push(`rule ${i + 1}: invalid regex (${e.message})`); return; }
      if (new RegExp(pattern, "u").test("")) { errors.push(`rule ${i + 1}: pattern matches the empty string`); return; }
      rules.push([kind, rx, 0, null]);
    });
    return { rules, errors };
  }

  /** Everything the extension flags in free text: detect() + structural extras + custom rules. */
  function detectAll(text, customRules) {
    const t = normaliseDigits(String(text ?? ""));
    const spans = runRules(t, RULES, []);
    runRules(t, EXTRA, spans);
    if (customRules && customRules.length) runRules(t, customRules, spans);
    return spans.sort((a, b) => a.start - b.start);
  }

  /** [{start,end,kind,value}] — values only for local in-memory use, never stored or sent. */
  function detectEach(text, customRules) {
    const s = String(text ?? "");
    return detectAll(s, customRules).map((x) => ({ ...x, value: s.slice(x.start, x.end) }));
  }

  function redactSpans(text, spans) {
    let out = "", pos = 0;
    for (const s of spans) { out += text.slice(pos, s.start) + `[REDACTED:${s.kind}]`; pos = s.end; }
    return out + text.slice(pos);
  }
  /** Port of sanitize.redact(): {text, spans}. Uses detect() only (exact Python behaviour). */
  function redact(text) {
    const s = String(text ?? ""), spans = detect(s);
    return { text: redactSpans(s, spans), spans };
  }
  /** Extension redaction: detect() + extras + custom rules. */
  function redactAll(text, customRules) {
    const s = String(text ?? ""), spans = detectAll(s, customRules);
    return { text: redactSpans(s, spans), spans };
  }

  class Blocked extends Error { constructor(m) { super(m); this.name = "Blocked"; } }
  /** Port of gate.egress_check: fail closed — any hit, any canary, or any scanner error blocks. */
  function egressCheck(payload, canaries = [], customRules) {
    let hits, leaked;
    try {
      if (typeof payload !== "string") throw new TypeError("payload must be a string");
      hits = customRules ? detectAll(payload, customRules) : detect(payload);
      leaked = (canaries || []).filter((c) => c && payload.includes(c));
    } catch (e) {
      throw new Blocked(`scanner error: ${e && e.message}`);
    }
    if (hits.length || leaked.length) {
      const kinds = [...new Set(hits.map((h) => h.kind).concat(leaked.length ? ["CANARY"] : []))].sort();
      throw new Blocked(`blocked, detected: ${kinds.join(", ")}`);
    }
    return payload;
  }
  /** Non-throwing form: {allowed, reason}. */
  function gate(payload, canaries, customRules) {
    try { egressCheck(payload, canaries, customRules); return { allowed: true, reason: "clean" }; }
    catch (e) { return { allowed: false, reason: e.message }; }
  }

  const api = {
    detect, detectAll, detectEach, redact, redactAll, redactSpans, egressCheck, gate, Blocked,
    compileCustomRules, luhnOk, verhoeffOk, verhoeffCheckDigit, ipv6Ok, normaliseDigits,
    _py: { W, WC, B, D, S, NS, ci },
  };
  root.ZenLensDetect = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
