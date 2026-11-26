# AGENTS.md — cmdrvl-core

Shared rules for CMD+RVL repositories are in `../AGENTS.md` (the workspace root) and apply here.

Repo-specific rules:

- The library takes bytes and values only: no `std::fs`, environment, clock, randomness,
  process, threads, `clap` or async. `#![forbid(unsafe_code)]`.
- Dependencies are exactly `blake3`, `sha2`, `hmac`, `serde`, `serde_json`. Adding one needs
  approval.
- Stored hashes and redaction markers are contracts. A change to any output byte of `jcs`,
  `sorted_compact`, `lockfile` or `redact` is a breaking change and needs a known-answer test
  computed outside this crate.
- Gates: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`,
  `cargo check --lib --target wasm32-unknown-unknown --no-default-features`.
- Beads for this work live in `cmdrvl/cmdrvl` (ids `cmd-*`); this repository has no `.beads/`.
