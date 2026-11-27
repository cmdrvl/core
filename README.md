# cmdrvl-core

Zero-I/O primitives shared by CMD+RVL tools (epic cmd-7aq, bead cmd-zjr). Callers pass bytes
and values. The library reads no file, environment variable or clock, uses no randomness,
forbids `unsafe`, and builds for `wasm32-unknown-unknown`.

**Status: phase 1.** The crate exists; **no tool has been migrated to it yet.**

| Module | What it is |
|---|---|
| `jcs` | RFC 8785 canonical JSON (ported from airlock). Integers beyond ±2^53 are refused. |
| `sorted_compact` | The sorted compact JSON that `lock` and `pack` hash today. **Not RFC 8785.** |
| `hash` | `blake3:` / `sha256:` prefixed hashes; strict `parse_prefixed`. |
| `lockfile` | `lock.v0` member verification, never looser than the released `shape`, `rvl`, `benchmark` or `verify` rules (see the module docs: some inputs a tool accepts are refused), and the `lock_hash` self-hash. Check several locks together with `verify_member_in_locks`. |
| `refusal` | Refusal envelope and the family exit-code dictionary. |
| `contract` | `ContractHash`, e.g. `blake3(JCS(value))`. No tool uses this type yet. |
| `redact` | Zero-retention markers: ordinal refs by default, keyed HMAC-SHA256 on request. |

## Two canonical forms, on purpose

`jcs` and `sorted_compact` give the same bytes for ordinary documents (ASCII keys, integers,
strings) and **different** bytes when member names mix characters in U+E000..=U+FFFF with
characters above U+FFFF, or for numbers such as `1.0` (`1` in JCS). Stored `lock_hash` and
`pack_id` values depend on `sorted_compact`; do not switch a tool to `jcs` without treating it
as a hash-format change.

## Redaction schemes

Existing tools disagree about the keyed HMAC input, so the scheme is explicit:

- `Scheme::Raw`: the bytes as given (`rvl`; a row key tuple uses `frame_components`).
  `verify` is `Raw` over the serde_json text of the value.
- `Scheme::Tagged`: namespace tag, `0x00`, bytes (`profile`, `fingerprint`).

`benchmark` and `decoding` print different marker text; build it from
`RedactionKey::hmac_sha256`. This crate maps no refusal code and reads no environment variable:
`select_key` takes the values the tool read, and a set-but-unusable tool key never falls back.

## Features

`float-roundtrip` (default) enables serde_json's `float_roundtrip`: its default float parser
can be one ULP off, which would change a JCS hash of parsed JSON.

## Gates

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check --lib --target wasm32-unknown-unknown --no-default-features
cargo tree -e normal --target all   # only blake3, sha2, hmac, serde, serde_json and their deps
```

Test fixtures are copies from other repositories; see `tests/fixtures/FIXTURES.md`.
