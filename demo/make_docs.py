"""Generate professional-looking SPECIMEN documents full of synthetic PII for demoing Zen to judges.

Every organisation, person and number here is fictional; IDs are made valid (Luhn, Verhoeff, GSTIN mod-36,
real state codes) only so the detectors fire. Each document carries a "Specimen: synthetic data" footer.

Run: .venv/bin/python demo/make_docs.py   ->  demo/docs/{*.html, *.png, *.txt, *.log}
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zenlens.detect import gstin_check_char, verhoeff_check_digit  # noqa: E402

OUT = Path(__file__).parent / "docs"

# --- synthetic identities (fictional; values computed to be format-valid) ---
_a = "48203917561"
AADHAAR = f"{_a[:4]} {_a[4:8]} {_a[8:]}{verhoeff_check_digit(_a)}"
PAN = "BQRPK4721M"
SELLER_PAN, BUYER_PAN = "AAFCS5821K", "AAGFN3305L"
GSTIN_S = (p := f"27{SELLER_PAN}1Z") + gstin_check_char(p)
GSTIN_B = (p := f"29{BUYER_PAN}1Z") + gstin_check_char(p)
CARD_FULL, CARD_ALT = "5555 5555 5555 4444", "4111 1111 1111 1111"
PHONE, PHONE2, PHONE_SELLER = "+91 98200 41763", "87654 32109", "+91 22 4097 1180"
EMAIL, EMAIL_SELLER, EMAIL_BUYER = "priya.menon@example.com", "accounts@saffronloom.example", "ap@northstar.example"
UPI, UPI_SHOP, UPI_RENT = "priya.menon@okaxis", "ravi.stores@ybl", "9820041763@paytm"
ACCT, IFSC = "50100231784459", "MRDN0004521"
PASSPORT, VOTER, VEHICLE = "M4827316", "XKP4821736", "MH 12 KT 4821"

FOOT = '<footer class="spec">SPECIMEN · synthetic data generated for the Zen privacy demo · not a real document</footer>'
CSS = """
*{box-sizing:border-box}body{margin:0;background:#eef0f3;font:14px/1.45 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#1d2433}
.page{width:860px;margin:24px auto;background:#fff;padding:40px 48px 28px;box-shadow:0 1px 3px rgba(0,0,0,.12);border-top:6px solid var(--brand)}
header.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #d8dde6;padding-bottom:16px;margin-bottom:20px}
.logo{display:flex;gap:12px;align-items:center}.mark{width:44px;height:44px;border-radius:10px;background:var(--brand);color:#fff;display:grid;place-items:center;font-weight:700;font-size:20px}
.org{font-size:19px;font-weight:700;letter-spacing:.2px}.sub{color:#5b6475;font-size:12px}
h1{font-size:18px;margin:0;text-align:right;color:var(--brand);text-transform:uppercase;letter-spacing:1px}
.meta{text-align:right;color:#5b6475;font-size:12px;margin-top:4px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:6px 32px;margin-bottom:18px}
.kv{display:flex;gap:8px}.kv b{min-width:132px;color:#5b6475;font-weight:600}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.8px;color:var(--brand);margin:20px 0 8px;border-bottom:2px solid var(--brand);padding-bottom:4px}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:#f4f6f9;text-align:left;padding:8px;border-bottom:1px solid #d8dde6}
td{padding:8px;border-bottom:1px solid #eef0f3}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.tot td{font-weight:700;border-top:2px solid #1d2433}.box{border:1px solid #d8dde6;border-radius:6px;padding:12px 14px;margin-top:14px;background:#fafbfc}
.field{border:1px solid #c9cfd9;border-radius:4px;padding:6px 10px;min-height:32px;font-family:"SF Mono",Menlo,Consolas,monospace}
.f{display:flex;flex-direction:column;gap:4px}.f label{font-size:11px;font-weight:600;color:#5b6475;text-transform:uppercase;letter-spacing:.5px}
.sig{font-family:"Snell Roundhand","Brush Script MT",cursive;font-size:26px;color:#22396b}
.spec{margin-top:26px;padding-top:10px;border-top:1px dashed #c9cfd9;color:#8a93a3;font-size:11px;text-align:center;letter-spacing:.4px}
.cr{color:#1b7f4b}.dr{color:#b42318}
"""


def page(title, brand, body):
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title>'
            f'<style>:root{{--brand:{brand}}}{CSS}</style></head><body><div class="page">{body}{FOOT}</div></body></html>')


def kv(k, v): return f'<div class="kv"><b>{k}</b><span>{v}</span></div>'


STATEMENT = page("Account Statement", "#123a6b", f"""
<header class="top"><div class="logo"><div class="mark">M</div><div><div class="org">Meridian Co-operative Bank Ltd.</div>
<div class="sub">Andheri (East) Branch · 14 Marol Industrial Estate, Mumbai 400059</div></div></div>
<div><h1>Account Statement</h1><div class="meta">01 Oct 2026 to 28 Oct 2026<br>Page 1 of 1</div></div></header>
<div class="grid">
{kv("Account holder", "Priya Menon")}{kv("Customer ID", "CIF 7718 2045")}
{kv("Address", "B-704, Lakeview Heights, Powai, Mumbai 400076")}{kv("Branch code", "0452 · Andheri (E)")}
{kv("Mobile", PHONE)}{kv("Nominee", "Registered")}
{kv("Email", EMAIL)}{kv("PAN", PAN)}
{kv("UPI ID", UPI)}{kv("Account type", "Savings · Regular")}
</div>
<div class="box" style="margin:0 0 6px">Savings account · A/c no {ACCT} · IFSC {IFSC} · MICR 400152018</div>
<h2>Transactions</h2>
<table><tr><th>Date</th><th>Description</th><th>Ref no.</th><th class="n">Debit (₹)</th><th class="n">Credit (₹)</th><th class="n">Balance (₹)</th></tr>
<tr><td>01 Oct</td><td>Opening balance</td><td></td><td></td><td></td><td class="n">1,24,560.00</td></tr>
<tr><td>02 Oct</td><td>NEFT CR · Northstar Analytics LLP · Salary Oct</td><td>N275261190344</td><td></td><td class="n cr">1,42,000.00</td><td class="n">2,66,560.00</td></tr>
<tr><td>03 Oct</td><td>UPI/{UPI_RENT}/Rent October</td><td>627514903317</td><td class="n dr">38,000.00</td><td></td><td class="n">2,28,560.00</td></tr>
<tr><td>07 Oct</td><td>UPI/{UPI_SHOP}/Groceries</td><td>627910288471</td><td class="n dr">2,846.50</td><td></td><td class="n">2,25,713.50</td></tr>
<tr><td>11 Oct</td><td>POS · Debit card ending 4242 · Voltline Electronics, Lower Parel</td><td>POS40391177</td><td class="n dr">18,499.00</td><td></td><td class="n">2,07,214.50</td></tr>
<tr><td>15 Oct</td><td>IMPS DR · to A/c XXXXXX8812 · Mother</td><td>628811430925</td><td class="n dr">15,000.00</td><td></td><td class="n">1,92,214.50</td></tr>
<tr><td>22 Oct</td><td>ACH DR · SIP · Order ORD-2026-118934</td><td>ACH90017724</td><td class="n dr">10,000.00</td><td></td><td class="n">1,82,214.50</td></tr>
<tr><td>28 Oct</td><td>Interest credit</td><td>INT2610</td><td></td><td class="n cr">612.40</td><td class="n">1,82,826.90</td></tr>
<tr class="tot"><td colspan="3">Closing balance</td><td class="n">84,345.50</td><td class="n">1,42,612.40</td><td class="n">1,82,826.90</td></tr></table>
<div class="box">For queries call <b>1800 266 0400</b> or write to care@meridianbank.example. Never share your OTP, PIN or CVV with anyone, including bank staff.</div>
""")

INVOICE = page("Tax Invoice", "#7a3e12", f"""
<header class="top"><div class="logo"><div class="mark">S</div><div><div class="org">Saffron Loom Textiles Pvt. Ltd.</div>
<div class="sub">Plot 22, MIDC Bhiwandi, Thane, Maharashtra 421302<br>GSTIN {GSTIN_S} · PAN {SELLER_PAN}</div></div></div>
<div><h1>Tax Invoice</h1><div class="meta">Invoice SLT/26-27/0418<br>Date 24 Oct 2026 · Due 23 Nov 2026</div></div></header>
<div class="grid">
<div><h2>Billed to</h2>{kv("Company", "Northstar Analytics LLP")}{kv("GSTIN", GSTIN_B)}{kv("Address", "3rd Floor, Cedar Grove Tech Park, Bengaluru 560103")}
{kv("Contact", "Arjun Rao · " + PHONE2)}{kv("Email", EMAIL_BUYER)}</div>
<div><h2>Supplier contact</h2>{kv("Phone", PHONE_SELLER)}{kv("Email", EMAIL_SELLER)}{kv("Place of supply", "Karnataka (29)")}
{kv("PO reference", "PO-NSA-2026-0773")}{kv("Vehicle no.", VEHICLE)}</div>
</div>
<table><tr><th>#</th><th>Description</th><th>HSN</th><th class="n">Qty</th><th class="n">Rate (₹)</th><th class="n">Amount (₹)</th></tr>
<tr><td>1</td><td>Handloom cotton throws, 140×200 cm</td><td>6301</td><td class="n">120</td><td class="n">1,250.00</td><td class="n">1,50,000.00</td></tr>
<tr><td>2</td><td>Block-printed cushion covers, set of 4</td><td>6304</td><td class="n">80</td><td class="n">890.00</td><td class="n">71,200.00</td></tr>
<tr><td>3</td><td>Packing and freight</td><td>9965</td><td class="n">1</td><td class="n">6,500.00</td><td class="n">6,500.00</td></tr>
<tr><td colspan="5">Taxable value</td><td class="n">2,27,700.00</td></tr>
<tr><td colspan="5">IGST @ 12%</td><td class="n">27,324.00</td></tr>
<tr class="tot"><td colspan="5">Total payable</td><td class="n">₹ 2,55,024.00</td></tr></table>
<div class="box"><b>Bank details for payment</b><br>Saffron Loom Textiles Pvt. Ltd. · Meridian Co-operative Bank · A/c no 60200417733081 · IFSC MRDN0001137<br>
Or pay by UPI: saffronloom@okicici · Questions: {EMAIL_SELLER}</div>
<p style="text-align:right;margin-top:22px">For Saffron Loom Textiles Pvt. Ltd.<br><span class="sig">K. Deshmukh</span><br>Authorised signatory</p>
""")

KYC = page("KYC Application", "#0f6b5c", f"""
<header class="top"><div class="logo"><div class="mark">N</div><div><div class="org">Northwind Wealth Services</div>
<div class="sub">SEBI-style account opening · Individual investor</div></div></div>
<div><h1>KYC Application</h1><div class="meta">Application no. NWS-KYC-2026-55120<br>Received 18 Oct 2026</div></div></header>
<h2>1 · Personal details</h2>
<div class="grid">
<div class="f"><label>Full name</label><div class="field">Priya Menon</div></div>
<div class="f"><label>Date of birth</label><div class="field">14/03/1996</div></div>
<div class="f"><label>Gender</label><div class="field">Female</div></div>
<div class="f"><label>Mobile no.</label><div class="field">{PHONE}</div></div>
<div class="f"><label>Email</label><div class="field">{EMAIL}</div></div>
<div class="f"><label>Residential address</label><div class="field">B-704, Lakeview Heights, Powai, Mumbai, PIN 400076</div></div>
</div>
<h2>2 · Identity documents</h2>
<div class="grid">
<div class="f"><label>Aadhaar number</label><div class="field">{AADHAAR}</div></div>
<div class="f"><label>PAN</label><div class="field">{PAN}</div></div>
<div class="f"><label>Passport no.</label><div class="field">Passport no. {PASSPORT}</div></div>
<div class="f"><label>Voter ID (EPIC)</label><div class="field">Voter ID {VOTER}</div></div>
</div>
<h2>3 · Bank account for payouts</h2>
<div class="grid">
<div class="f"><label>Account number</label><div class="field">A/c no {ACCT}</div></div>
<div class="f"><label>IFSC</label><div class="field">IFSC {IFSC}</div></div>
<div class="f"><label>UPI ID</label><div class="field">{UPI}</div></div>
<div class="f"><label>Annual income</label><div class="field">₹ 15–25 lakh</div></div>
</div>
<div class="box">I declare that the information above is true. I consent to verification of my identity documents.
<div style="display:flex;justify-content:space-between;align-items:flex-end;margin-top:10px"><span>Place: Mumbai · Date: 18/10/2026</span><span class="sig">Priya Menon</span></div></div>
""")

CHAT = f"""Meridian Bank · Customer Support · Chat transcript
Ticket TKT-20431 · Channel: in-app chat · 27 Oct 2026, 14:02–14:19 IST
SPECIMEN · synthetic data generated for the Zen privacy demo · not a real conversation
------------------------------------------------------------------------

[14:02] Priya Menon: Hi, mera card block ho gaya hai, I can't pay at checkout.
[14:03] Agent Kavya: Sorry to hear that! Please share your registered mobile number so I can find the account.
[14:03] Priya Menon: {PHONE}. Email is {EMAIL} if needed.
[14:05] Agent Kavya: Thanks. Which card is affected?
[14:05] Priya Menon: Card number {CARD_FULL}, expiry 08/29
[14:06] Agent Kavya: Got it. For verification, please confirm your PAN.
[14:06] Priya Menon: {PAN}
[14:08] Agent Kavya: I've sent a one-time code to your phone. Please read it out.
[14:08] Priya Menon: OTP is 482913
[14:09] Priya Menon: Btw my net banking password: Monsoon@2026 – should I change it?
[14:10] Agent Kavya: Please never share your password with anyone, including us. Change it right away from the app.
[14:12] Priya Menon: Ok. Also can I get the refund on UPI? Mera UPI {UPI} hai.
[14:13] Agent Kavya: Yes, the refund of ₹18,499.00 for order ORD-2026-118934 will reach {UPI} in 3–5 working days.
[14:15] Priya Menon: And update my address proof, Aadhaar {AADHAAR}.
[14:17] Agent Kavya: Done. Your card has been unblocked. Reference SR-77120-B.
[14:19] Agent Kavya: Is there anything else I can help with? Rate this chat 1–5.
"""

LOG = f"""# payments-api · incident 2026-10-26 · exported for postmortem
# SPECIMEN · synthetic data generated for the Zen privacy demo · all keys below are fake
2026-10-26T09:14:02.118Z INFO  boot service=payments-api version=v3.18.2 build 2026.10.25 region=ap-south-1
2026-10-26T09:14:02.231Z INFO  config OPENAI_API_KEY=sk-proj-Zx8Qm2Lr7Tn4Vb9Kc1Wd6Hs3Pj5Fg0Ye8Ua2Nq
2026-10-26T09:14:02.232Z INFO  config AWS_ACCESS_KEY_ID=AKIAZ7Q4M2LR8TN4VB9K
2026-10-26T09:14:02.233Z INFO  config GITHUB_TOKEN=ghp_Q7m2Lr8Tn4Vb9Kc1Wd6Hs3Pj5Fg0Ye8Ua2Nq
2026-10-26T09:14:02.240Z INFO  db connect host=10.24.3.17 port=5432 user=payments DB_PASSWORD=pg_R7v2Kq9Lm4Xt
2026-10-26T09:31:47.902Z WARN  slow request path=/v1/charges latency_ms=2381 request_id=550e8400-e29b-41d4-a716-446655440000
2026-10-26T09:31:48.004Z ERROR charge failed customer_email={EMAIL} card={CARD_ALT} reason=issuer_timeout
2026-10-26T09:31:48.006Z ERROR upstream auth header=Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjdXN0XzQ4MjEiLCJyb2xlIjoiYWRtaW4ifQ.c3ludGhldGljLXNpZ25hdHVyZS0wMDE
2026-10-26T09:32:10.551Z INFO  retry ok order=ORD-2026-118934 amount=18499.00 currency=INR client_ip=203.0.113.45
2026-10-26T09:40:00.000Z INFO  on-call paged: s.ghosh@zen-team.example, phone {PHONE2}
"""


def render(htmls):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 960, "height": 800}, device_scale_factor=2)
        for name in htmls:
            pg.goto((OUT / f"{name}.html").resolve().as_uri())
            pg.locator(".page").screenshot(path=str(OUT / f"{name}.png"))
        b.close()


def main():
    OUT.mkdir(exist_ok=True)
    docs = {"bank_statement": STATEMENT, "tax_invoice": INVOICE, "kyc_application": KYC}
    for name, html in docs.items():
        (OUT / f"{name}.html").write_text(html, encoding="utf-8")
    (OUT / "support_chat.txt").write_text(CHAT, encoding="utf-8")
    (OUT / "payments_incident.log").write_text(LOG, encoding="utf-8")
    render(docs)
    for f in sorted(OUT.iterdir()):
        print(f"wrote {f.relative_to(OUT.parent.parent)}")


if __name__ == "__main__":
    main()
