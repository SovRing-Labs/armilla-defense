# Data and exclusions
No private stores, keys, live configuration, target caches, compiled objects or models ship.
The manifest excludes files over 1,048,576 bytes. Included files are small source, documentation and results.
Needs SovRing-Labs/armilla-astrolabe for the external guard row. The demo expects ../../engine. Copy experiments/guard_events into a temporary public Armilla checkout to rerun. guard_events.jsonl is generated and omitted. Historical test_lanes requires an external redteam binary; the standalone lane harness uses an extracted payload fixture instead.
