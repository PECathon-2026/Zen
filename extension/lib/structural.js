/*
 * Structural field classification: port of zenlens/structural.py `_rule` / `_keyword` / `element_kind`.
 * Flags elements by what they ARE (type=password, autocomplete=cc-csc, label "OTP", name "api_key"...)
 * even when the value would slip past text regexes. Pure functions over plain objects; the DOM adapter
 * (`classifyDomElement`) lives at the bottom and is only used in the browser.
 */
(function (root) {
  "use strict";
  const PY = (root.ZenLensDetect || (typeof require === "function" ? require("./detect.js") : {}))._py;
  const { S, NS } = PY;

  const NO_STRUCT = new Set(["label", "button", "h1", "h2", "h3", "h4", "h5", "h6", "title", "option", "legend", "th"]);
  const RAW = new Set(["script", "style"]);
  const SKIP_INPUT = new Set(["submit", "button", "reset", "checkbox", "radio", "image", "file", "range", "color"]);
  const FACE_TAGS = new Set(["img", "video", "canvas"]);
  const INLINE = new Set(["b", "i", "em", "strong", "span", "code", "small", "mark", "br", "sup", "sub", "u", "kbd", "samp"]);

  const AUTOCOMPLETE = {
    "cc-number": "CARD", "cc-csc": "CVV", "cc-exp": "CARD_EXP", "cc-exp-month": "CARD_EXP", "cc-exp-year": "CARD_EXP",
    "cc-name": "NAME", "name": "NAME", "given-name": "NAME", "family-name": "NAME",
    "one-time-code": "OTP", "current-password": "PASSWORD", "new-password": "PASSWORD",
    "email": "EMAIL", "tel": "PHONE", "tel-national": "PHONE", "street-address": "ADDRESS",
    "address-line1": "ADDRESS", "address-line2": "ADDRESS", "postal-code": "ADDRESS",
  };
  const TYPES = { password: "PASSWORD", email: "EMAIL", tel: "PHONE" };
  // Hint text is normalised to [a-z0-9 ] first, so ASCII \b is exact here.
  const KEYWORDS = [
    ["OTP", /\b(?:otp|one ?time (?:code|password|pin)|verification code|2fa|totp|mfa code)\b/],
    ["CVV", /\b(?:cvv2?|cvc2?|csc|card security|security code)\b/],
    ["PASSWORD", /\b(?:password|passwd|passcode|pwd)\b/],
    ["PIN", /\b(?:upi |atm )?pin\b(?! ?code)/],
    ["UPI_ID", /\b(?:upi ?id|upi address|upi handle|vpa)\b/],
    ["IFSC", /\bifsc(?: code)?\b/],
    ["BANK_ACCOUNT", /\b(?:bank account|account ?(?:no|number|num)|acc ?no|acct(?: ?no| ?number)?|a c no|khata(?: sankhya| number| no)?)\b/],
    ["GSTIN", /\b(?:gstin|gst ?no|gst ?number|gst ?reg(?:istration)? ?no)\b/],
    ["VOTER_ID", /\b(?:voter ?id|voter card|epic ?(?:no|number))\b/],
    ["PASSPORT", /\bpassport(?: ?(?:no|number))?\b/],
    ["VEHICLE", /\b(?:vehicle ?(?:no|number|reg(?:istration)?(?: no| number)?)|number ?plate|licen[cs]e ?plate|gaadi ?(?:no|number))\b/],
    ["API_KEY", /\b(?:api ?key|access ?key|secret ?key|private ?key)\b/],
    ["TOKEN", /\b(?:token|bearer|session ?id|csrf|authorization)\b/],
    ["SECRET", /\bsecret\b/],
    ["AADHAAR", /\b(?:aadhaa?r|uidai)\b/],
    ["PAN", /\bpan(?: number| card| no)?\b/],
    ["CARD", /\b(?:card ?number|cc ?number|credit card|debit card)\b/],
    ["CARD_EXP", /\b(?:expiry|expiration|exp date|cc exp|valid thru)\b/],
    ["EMAIL", /\be ?mail\b/],
    ["PHONE", /\b(?:phone|mobile|telephone|mob ?no|contact ?(?:no|number)|whatsapp ?(?:no|number)|fone)\b/],
    ["IP", /\b(?:ip|ipv4|ipv6|ip address|host ip)\b/],
    ["FACE", /\b(?:face|webcam|camera|selfie|avatar|participant|self view|video tile)\b/],
    ["NAME", /\b(?:participant|display|full|speaker|caller|card ?holder) name\b|\bcardholder\b|\bnaam\b/],
    ["ADDRESS", /\b(?:address|street|postal code|zip|pincode|pin code|ghar ka pata)\b/],
  ];
  const GATE = {
    NAME: new RegExp(`^(?:[A-Z][${PY.WC}.'-]*(?: [A-Z][${PY.WC}.'-]*){0,3})$`, "u"),
    ADDRESS: new RegExp(`^(?:(?=.*\\p{Nd})[^<>]{5,200})$`, "u"),
  };
  const VALUE_LIKE = new RegExp(`^(?:(?:${PY.ci("bearer")}${S}+)?${NS}{3,200})$`, "u");
  const HAS_DIGIT_OR_SYMBOL = new RegExp(`[\\p{Nd}_]|[^${PY.WC}]`, "u");

  /** Python " ".join(s.split()) */
  const collapse = (s) => String(s || "").split(new RegExp(`${S}+`, "u")).filter(Boolean).join(" ");
  function norm(s) {
    s = String(s || "").replace(/([a-z])([A-Z])/g, "$1 $2");
    return s.toLowerCase().replace(/[^a-z0-9]+/g, " ").split(" ").filter(Boolean).join(" ");
  }
  function keyword(hint, face = false) {
    const h = norm(hint);
    for (const [kind, rx] of KEYWORDS) {
      if ((kind === "FACE") !== face) continue;
      const m = rx.exec(h);
      if (m) return [kind, m[0]];
    }
    return null;
  }

  /**
   * Port of structural._rule. el = {tag, attrs:{...}, text, blockChild}; lab = label text.
   * Returns [kind, reason] or null.
   */
  function rule(el, lab = "") {
    const a = el.attrs || {}, tag = String(el.tag || "").toLowerCase();
    if (NO_STRUCT.has(tag) || RAW.has(tag)) return null;
    const form = tag === "input" || tag === "textarea" || tag === "select";
    const typ = String(a.type || "text").toLowerCase();
    if (tag === "input" && SKIP_INPUT.has(typ)) return null;
    const ac = String(a.autocomplete || "").toLowerCase().split(new RegExp(`${S}+`, "u")).find((t) => t in AUTOCOMPLETE);
    const hint = ["name", "id", "class", "aria-label", "placeholder", "data-testid", "title"].map((k) => a[k] || "").join(" ");
    const face = FACE_TAGS.has(tag);
    let kind, why, k;
    if (tag === "input" && typ === "password") { kind = "PASSWORD"; why = "type=password"; }
    else if (ac) { kind = AUTOCOMPLETE[ac]; why = `autocomplete=${ac}`; }
    else if ((k = keyword(hint, face))) { kind = k[0]; why = `attr:${k[1]}`; }
    else if (lab && (k = keyword(lab, face))) { kind = k[0]; why = `label:${k[1]}`; }
    else if (tag === "input" && typ in TYPES) { kind = TYPES[typ]; why = `type=${typ}`; }
    else return null;
    if (!form && !face) {
      const t = collapse(el.text);
      if (el.blockChild || !t) return null;
      const g = GATE[kind];
      if (g && !g.test(t)) return null;
      if (!g && !(VALUE_LIKE.test(t) && (HAS_DIGIT_OR_SYMBOL.test(t) || Array.from(t).length >= 16))) return null;
    }
    return [kind, why];
  }

  /** Port of structural.element_kind(e). */
  function elementKind(e) {
    const attrs = { id: e.id, type: e.type, autocomplete: e.autocomplete, name: e.field_name, placeholder: e.placeholder, class: e.class };
    const r = rule({ tag: e.tag || "", attrs, text: e.text || "", blockChild: false }, e.name || "");
    return r ? r[0] : null;
  }

  // ---------- DOM adapter (browser only) ----------
  function labelText(el) {
    let lab = "";
    try {
      if (el.id) {
        const l = el.ownerDocument.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (l) lab = collapse(l.textContent);
      }
      if (!lab) { const p = el.closest && el.closest("label"); if (p) lab = collapse(p.textContent); }
      if (!lab && el.getAttribute) {
        const ids = (el.getAttribute("aria-labelledby") || "").split(/\s+/).filter(Boolean);
        lab = collapse(ids.map((i) => (el.ownerDocument.getElementById(i) || {}).textContent || "").join(" "));
      }
    } catch (_) { /* ignore */ }
    return lab;
  }
  function hasBlockChild(el) {
    for (const c of el.children || []) if (!INLINE.has(c.tagName.toLowerCase())) return true;
    return false;
  }
  /** Classify a live DOM element: [kind, reason] | null. Never reads or keeps more than needed. */
  function classifyDomElement(el) {
    const attrs = {};
    for (const k of ["type", "autocomplete", "name", "id", "class", "aria-label", "placeholder", "data-testid", "title"]) {
      const v = el.getAttribute(k); if (v != null) attrs[k] = v;
    }
    const tag = el.tagName.toLowerCase();
    const form = tag === "input" || tag === "textarea" || tag === "select";
    return rule({ tag, attrs, text: form ? "" : el.textContent, blockChild: form ? false : hasBlockChild(el) }, labelText(el));
  }

  const api = { rule, elementKind, keyword, norm, classifyDomElement, labelText, AUTOCOMPLETE, KEYWORDS };
  root.ZenLensStructural = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
