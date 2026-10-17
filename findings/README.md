# armilla-defense — findings addendum, 2026-10-17

This dated addition preserves the earlier disclosure and its historical limits. Code remains pre-alpha. No publication, browser/renderer/playback wiring or production service is established.

## wave

Implementation: Replay/prepare, explicit Pilot/match, complementary read/admit/checked_readback and Affine/diagnose.

Engineering: 2018 parent checks; known collisions/duplicated mirrors/ineffective actuators/stale inputs.

Science: phase/direct complex tie32.26%top1,40.65%recall4 at extra cost; checksum/readback cheaper; integer IFS uncertified.

Deployment: opt-in Python, standalone synthetic video/JS fixtures, actual audio read-only adapter external.

Limits: pilot serialized/costed; only supplied common rotation invariance; no pilot-free/absolute phase or strict integer contraction.

## defense

Implementation: Own Greenmark Ed25519; Store explicit enrollment+bounded persistent anti-replay; Graph authenticated public max-plus DAG with independent state/effect target.

Engineering: freshness/restart/coherent fault/ineffective actuator controls in1364 gate.

Science: sparse1vs16 touched nodes but no10%complete latency win; dense no win.

Deployment: local trusted filesystem/clock/enrollment; graph/audit in memory; no production defense claim.

Limits: no malicious rollback proof, distributed exactly once or atomic durable graph commit; signatures do not establish benign intent.

## Run the portable subset

    OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 python3 findings/smoke.py

This source-only capsule uses tiny synthetic public inputs. See findings/LINEAGE.json for exact own-source hashes and extraction/relocation changes. It does not run the full original5482/2018/1364/62396 gates. Raw recorded audio, trained model, private fixture paths and embedded secret keys are excluded. Full research gates are EXTERNAL to this release. No dependency is installed by the check. NumPy is required for crypto/decoder; defense uses Linux/POSIX flock/fsync. The capsule signs only ephemeral test material in memory and stores no private signing key. Trusted local state is an explicit defense assumption.

Original APIs are described above; some fleet-only convenience entrypoints are deliberately omitted. The smoke exercises the exported subset. Hybrid cost rows are not transferred: unmatched measurements default to positional. Positive historical numbers are descriptive local Python comparisons, not newcomer performance guarantees.
## Minimal caller example

From the released repository root; the smoke also requires the installed cryptography package as a black-box oracle:

```python
import sys, secrets, tempfile
from pathlib import Path
sys.path.insert(0, "findings")
import greenmark
from freshness import Store, Principal, body, sign_fixture

seed = secrets.token_bytes(32)  # ephemeral memory only; never written or printed
principal = Principal(public_key=greenmark.public_key(seed))
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "freshness.json"
    store = Store.enroll(path, [principal])
    signed = sign_fixture(body({"answer": 8}, "example", sequence=1), seed)
    value, receipt = store.admit(signed, 1000, "example", expected_payload={"answer": 8})
```

Store.enroll is explicit; Store(path, principals) opens established state and refuses missing/corrupt policy state. Signed/Principal/body/sign_fixture are available, but signing now requires an explicit caller seed; no seed fixture is embedded. Graph(store, sources, edges).proposal/apply retains the actual public max-plus DAG implementation. Its fixed-key convenience signer is omitted: callers explicitly sign body(event, graph.context, "graph-update-v1", graph.dependencies, sequence=...) and supply an independently calculated full target/readback. The smoke demonstrates both observed_success and an ineffective actuator yielding observed_failure after freshness consumption.

Trusted local enrollment, clock, filesystem and actual readback are assumptions. The store retains up to4 active principal histories,64 recent nonce IDs and strictly increasing uint64 sequences. Graph is bounded32nodes/128edges/128events; graph state/audit is in memory while freshness persists. No rollback resistance against a malicious trusted-store rollback, distributed exactly once, atomic durable graph transaction, constant-time proof, security audit or deployed defense follows. A signature is provenance, not benign intent, and input signatures do not authenticate transformed arithmetic outputs.
