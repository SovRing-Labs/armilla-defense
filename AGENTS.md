# AGENTS.md — armilla-defense

For coding assistants (and people) setting this repository up. Plain steps; every command runs from the repo root.

**Status: pre-alpha, under development.** Interfaces, numbers and file layout can change without notice. Read `STATUS.md` first: what works today (each line names its test and evidence file), what is not yet tested, the known failures and the corrections.

## What it is
Stage: about 30 % (under development, pre-alpha).
Signed input lanes, watch-only socket gates and redundant-residue fault sensing.

## Install and check (3 commands)
```bash
git clone --depth 1 https://github.com/SovRing-Labs/armilla-defense && cd armilla-defense
python3 -m venv .venv && . .venv/bin/activate && python -m pip install -q cryptography
python3 tests/local_demo.py lanes   # expect: PASS
```
Needs: python3, cryptography (oracle test).
Whole suite instead: `bash install.sh --no-gui` (python check → venv → every runnable `suite.json` test, headless; without `--no-gui` it then opens the local results page on 127.0.0.1).

GUI: `bash install.sh`

## What the tests mean
`suite.json` lists every claim this repository makes with its verify command, the expected output, what passing means, how the number was obtained and how to use it in your own work (9 tests, in `suite.json` at the repository root). `STATUS.md` says what works today, what is not yet tested and the known failures; the umbrella's `STATUS.md` has one row per repository.

## Where the evidence is
- `README.md`
- `TECHNICAL-DISCLOSURE.md` — the method, as dated prior art
- `CITATION.cff`

## Honest limits (from STATUS.md)
No security audit, conversions not constant-time, no security claim. Signatures establish provenance, not benign intent or humanity. Replay/freshness policy is not enforced by this reference. Fences are text, not a model isolation boundary. Vault blind analytics, federated Sentinel, Seal DRM and production router enforcement remain research. Keyed check slots are not cryptographic signatures and are not implemented in this bundle.

## Licence
PolyForm Small Business 1.0.0 OR PolyForm Noncommercial 1.0.0 OR PolyForm Free Trial 1.0.0 (code); CC BY 4.0 (documents). Details: `LICENSING.md`.

## Guided setup through MCP
The SovRing umbrella ships an MCP server that explains, checks readiness, clones and runs these tests: https://github.com/SovRing-Labs/SovRing (README → "Paste this to your assistant"). Zero-install docs endpoint: https://gitmcp.io/SovRing-Labs/armilla-defense
