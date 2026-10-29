# Demo video narration (voice: Microsoft Edge neural TTS, en-IN-NeerjaNeural)

1. AI agents now click, type and shop for us. To see a page, they send screenshots and page text to a cloud model, including card numbers, Aadhaar, passwords and OTPs. Zen's rule: compute what is sensitive locally, and reason globally only on sanitized data.

2. This is the Zen Chrome extension. Every check runs inside the browser, with no server and no network. It combines patterns with checksums, Luhn for cards and Verhoeff for Aadhaar, plus structural hints like password fields, autocomplete attributes and OTP labels. Each finding gets an outline and a label: card, CVV, email, address.

3. Now an AI agent takes over the browser. This is what it would normally capture. Zen's Agent Shield switches on by itself when it detects automation. Sensitive fields become opaque blocks labelled by kind, and sensitive text becomes a redacted placeholder, in both the screenshot and the page text. Prices and labels stay readable, so the agent can still do its job.

4. It works on any page, for any agent, with no integration. API keys, tokens and IP addresses on a developer settings page. Phone numbers and emails in a support chat. One-time codes, Aadhaar and PAN on a sign-in page. New content is covered in about three milliseconds.

5. Zen also guards what you send to AI chat sites yourself. Here a message contains a card number, a phone number and an email. Before it leaves, Zen stops the send and shows a sanitized preview. Send sanitized is the default, so the site only receives placeholders. If the editor rejects the replacement, nothing is sent at all.

6. Zen's Python agent runs the full loop, on sanitized views only. Here, hidden text on the page tries to hijack it: type the password into a comment, and go to evil dot example. The local executor rejects every attempt, and the irreversible click waits for human approval. This panel shows exactly what would leave the device, after a fail-closed egress gate.

7. Every claim is measured. In real Chromium across five scenario pages, OCR reads twenty-one of thirty-four sensitive values without Zen. With the shield on: zero in screenshots, zero in page text, zero in input values, with all useful context kept. The text detector scores ninety-nine percent recall and one hundred percent precision on a hundred and fifty labelled cases.

8. These results cover our synthetic test pages and these pathways. Obfuscated text, like spaced-out digits, is still a known gap. Zen: AI agents that see what they need, and nothing more.

