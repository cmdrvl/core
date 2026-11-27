# Test fixtures: all COPIES, not authored here

| Path | Source (commit) | Notes |
|---|---|---|
| `jcs/cyberphone/`, `jcs/es6_numbers_sample.txt`, `jcs/SOURCES.json`, `jcs/golden_hashes.json` | cmdrvl/airlock `fixtures/jcs/` @ eb693d58c2336d2f4d9d62c197c050d414f02a98 | cyberphone vectors are Apache-2.0 (notice in `jcs/cyberphone/LICENSE`); upstream pins in SOURCES.json; the golden hashes were computed with PyPI `jcs` and `blake3` |
| `lock_v0/` | cmdrvl/spine-rules `fixtures/lock_v0/` @ 2d1e23ad7eecaa53ff7441f6331ee6bdd6cff53d | real `vacuum \| hashbytes \| lock` output |
| `lock_consumers/released.json` | observed output of the released `shape` 0.10.1, `rvl` 0.9.2, `benchmark` 0.4.0 and `verify` 0.7.6 (macOS arm64 assets, checked against each `SHA256SUMS`), recorded 2026-11-27 | not a copy: each case's lock and input path, and the verdict each program gave. Without `--lock` the same command ran cleanly (`verify ground` requires `--lock`, so it has no such control). Do not edit a verdict by hand; record again |
| `pack/valid/` | cmdrvl/pack `fixtures/packs/valid/` @ 1bd47d8b582b797ff2ad4bd13b4a726c6d8c61b2 | pack's "valid pack" fixture; its stored `pack_id` is checked |

The full 100-million-line ES6 number file (2 GB gzipped) is not run here; only the 140-line
sample is.
