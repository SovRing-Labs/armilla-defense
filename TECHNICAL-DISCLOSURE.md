# TECHNICAL DISCLOSURE — armilla-defense
Author: Juan Carlos De Santiago, with the Sovereign Raptor fleet (AI-assisted). Date of disclosure: 2026-10-16.
Published as defensive prior art: the author claims no patent on what is described here and asks that none be granted on it.
Licence of this text: CC BY 4.0.

## Problem and mechanism
Greenmark builds a canonical HTTP Message Signature base and uses its reference Ed25519 implementation to sign/verify. A trusted valid key receives +1, unsigned/unknown keys receive 0, and a bad or revoked signature receives -1. Lanes sign a content digest together with kind and source; unsigned content is wrapped as data and may_instruct is false. TCP gates observe signature tiers, per-source rates and arrival rhythm, forwarding by default; Unix gates frame signed bodies and optionally refuse anything except +1. No host firewall is changed. Redundant RNS guard mode adds independent check systems to the data systems; decode checks consistency, reconstructs after one faulty system and emits an event, or refuses an uncorrectable state. The engine itself is an external prerequisite. Keyed check slots are a separate probabilistic integrity proposal, not this signature mechanism.

## Data layout and reproduction
Source modules and suite.json describe the executable layout. Run: python3 tests/local_demo.py lanes.
Outputs and temporary stores stay in temporary directories; results/ stores the author's saved command output.

## Measurements
The 2026-10-17 quick-test command and output are preserved in results/2026-10-17-quicktest.log. No throughput or production detection rate is claimed.
Historical results: results/historical-test_lanes.result.json records 21 unsigned inputs, 0 permitted instructions; results/historical-test_ugate.result.json records signed-only relay in default-deny mode; results/guard_demo.result.json records fault trials and silent-wrong count. These are prior recorded runs, not reruns of the external engine. Guard/Verify are the demonstrated components; Vault/Sentinel/Seal remain future product directions.

## What is not claimed
No security audit, conversions not constant-time, no security claim. Signatures establish provenance, not benign intent or humanity. Replay/freshness policy is not enforced by this reference. Fences are text, not a model isolation boundary. Vault blind analytics, federated Sentinel, Seal DRM and production router enforcement remain research. Keyed check slots are not cryptographic signatures and are not implemented in this bundle.

## Field lineage
SHA-256: NIST, Secure Hash Standard, 2015. Residue arithmetic: Szabo and Tanaka, Residue Arithmetic and its Applications to Computer Technology, 1967.
HTTP signatures: Backman, Richer and Sporny, HTTP Message Signatures (RFC 9421), 2024. Ed25519: Josefsson and Liusvaara, EdDSA (RFC 8032), 2017.
Conceptual sources; no reference implementation was copied into the authored core.


## Findings update — 2026-10-17

See [FINDINGS-2026-10-17.md](FINDINGS-2026-10-17.md) for later implemented opt-in APIs, exact engineering/scientific limits and a portable source-only smoke check. Earlier statements above remain the dated historical record; they are scoped to the earlier bundle. The new capsule is not a full research-gate reproduction or deployed integration.
