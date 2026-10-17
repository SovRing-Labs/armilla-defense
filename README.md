# armilla-defense

[![status: pre-alpha](https://img.shields.io/badge/status-pre--alpha%20(under%20development)-orange)](STATUS.md)
[![defensive publication](https://img.shields.io/badge/defensive%20publication-TECHNICAL--DISCLOSURE.md-blue)](TECHNICAL-DISCLOSURE.md)

Status: **under development — pre-alpha** (STATUS.md). Defensive publication: TECHNICAL-DISCLOSURE.md (dated 2026-10-16; the DOI is
minted by Zenodo on the first GitHub release).

Signed input lanes, watch-only socket gates and redundant-residue fault sensing.

## Run it
Use only files and services you own. Tests use temporary directories.

    git clone https://github.com/SovRing-Labs/armilla-defense
    cd armilla-defense
    python3 tests/local_demo.py lanes

## What it does today
| Capability | Evidence |
|---|---|
| Isolated quick test | results/2026-10-17-quicktest.log |
| Method and scope | TECHNICAL-DISCLOSURE.md |

## Not shown here
No security audit, conversions not constant-time, no security claim. Signatures establish provenance, not benign intent or humanity. Replay/freshness policy is not enforced by this reference. Fences are text, not a model isolation boundary. Vault blind analytics, federated Sentinel, Seal DRM and production router enforcement remain research. Keyed check slots are not cryptographic signatures and are not implemented in this bundle.

## Files
| Path | Purpose |
|---|---|
| tests/ | Isolated harnesses |
| suite.json | Runnable claims and commands |
| results/ | Dated output and historical records |
| DATA.md | Exclusions and prerequisites |

## Licence and stage
PolyForm Small Business 1.0.0 OR PolyForm Noncommercial 1.0.0 OR PolyForm Free Trial 1.0.0 (code); CC BY 4.0 (documents). See LICENSING.md. Development stage: about 30 %, an author estimate rather than measured coverage.


## Findings update — 2026-10-17

See [FINDINGS-2026-10-17.md](FINDINGS-2026-10-17.md) for later implemented opt-in APIs, exact engineering/scientific limits and a portable source-only smoke check. Earlier statements above remain the dated historical record; they are scoped to the earlier bundle. The new capsule is not a full research-gate reproduction or deployed integration.
