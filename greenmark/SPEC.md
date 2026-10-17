# GREENMARK — protocol spec v0 (draft, 2026-10-14; research)
Origin: J 10-14 (readback confirmed). Evaluation: `published research notes Reference: `greenmark.py`.

## 1. What a greenmark is
A signature that makes a sender ACCOUNTABLE for a message and proves it was not altered. It does not claim the sender is human or
that a model is safe. A greenmark is an RFC 9421 HTTP Message Signature (or the same signature base over a non-HTTP message), made
with Ed25519 (RFC 8032), whose `keyid` names a key in a key directory the verifier can read.

## 2. Signing (v0 profile)
- Algorithm: `ed25519`. Covered components, minimum: `@method`, `@authority`, `@path`, `date` (or `created`), and for a body
  `content-digest`. Parameters: `created` (required), `keyid` (required), `nonce` (recommended), `expires` (recommended ≤ 300 s).
- Header fields: `Signature-Input: <label>=(<components>);created=…;keyid="…"` and `Signature: <label>=:<base64 sig>:`.
- Non-HTTP inputs (files, agent messages): the signature base is the same line format with components `"@kind"`, `"@source"`,
  `"content-digest"` and `"@signature-params"` (v0 names
