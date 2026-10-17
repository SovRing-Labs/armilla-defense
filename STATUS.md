> **Status: under development — pre-alpha.** Interfaces, numbers and file layout can change without notice.

## Works today
- S1: PASS — Unsigned data and signed/tampered/revoked provenance; evidence: results/2026-10-17-S1.log.
- S2: PASS — Ed25519 oracle and RFC vectors; evidence: results/2026-10-17-S2.log.
- S3: PASS — Scratch Unix watch-only and signed-only default-deny; evidence: results/2026-10-17-S3.log.
- S4: PASS — Scratch TCP watch-only tiers, rate and rhythm; evidence: results/2026-10-17-S4.log.
- S5: PASS — Historical guard faults: PASS, zero silent wrong; evidence: results/guard_demo.result.json.
- S6: EXTERNAL — External redundant-RNS fault demo; evidence: results/guard_demo.result.json.
- S7: PASS — No audit or constant-time conversion claim; evidence: STATUS.md.

## Not yet tested
Production and adversarial security evaluation. Stage about 30 % (author estimate).
External rows need their named prerequisite.

## Known failures and honest negatives
No security audit, conversions not constant-time, no security claim. Signatures establish provenance, not benign intent or humanity. Replay/freshness policy is not enforced by this reference. Fences are text, not a model isolation boundary. Vault blind analytics, federated Sentinel, Seal DRM and production router enforcement remain research. Keyed check slots are not cryptographic signatures and are not implemented in this bundle.

## Corrections
Historical plans predate some existing code. Historical measurements are not current reruns.
Publication path rewrites and scratch harnesses replace private assumptions.

## How to re-check
python3 tests/local_demo.py lanes; all row commands are in suite.json.

## Defensive publication
TECHNICAL-DISCLOSURE.md dated 2026-10-16; DOI pending first release.


## Findings update — 2026-10-17

See [FINDINGS-2026-10-17.md](FINDINGS-2026-10-17.md) for later implemented opt-in APIs, exact engineering/scientific limits and a portable source-only smoke check. Earlier statements above remain the dated historical record; they are scoped to the earlier bundle. The new capsule is not a full research-gate reproduction or deployed integration.
