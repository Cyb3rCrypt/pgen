# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.2.0] — 2026-02-25

### Added

- `--typeid` flag: generate a [TypeID](https://github.com/jetpack-io/typeid) —
  a type-safe, K-sortable identifier with a lowercase ASCII prefix and a
  Crockford base32-encoded UUID v7 suffix (spec v0.3.0).
- `--typeid-prefix <PREFIX>`: optional prefix for the generated TypeID
  (1–63 lowercase ASCII letters/underscores, not starting or ending with `_`).
  When omitted, only the bare 26-character base32 suffix is printed.

## [1.1.1] — 2026-02-25

### Fixed

- UUID v7 now implements RFC 9562 §6.2 Method 1 monotonic ordering: a 12-bit
  counter in `rand_a` (bytes 6–7) guarantees strict lexicographic increase
  across all calls within the same process, even within the same millisecond.
  Previously, sub-millisecond sort order was not guaranteed.
- Clock rollback is clamped to `last_ms` rather than panicking, preserving
  local monotonicity under NTP adjustments.

### Changed

- CI: `cargo test` now runs with `--test-threads=1` to prevent races on the
  shared monotonic state in UUID v7 tests.

### Tests

- Added `uuid_v7_monotonic` — 200 UUIDs in strict lexicographic order.
- Added `uuid_v7_monotonic_counter_increments` — 50 UUIDs strictly increasing as u128.
- Added `uuid_v7_clock_rollback_clamped` — injected future timestamp is clamped; no backward movement.

## [1.1.0] — 2026-02-24

### Added

- `--uuid` / `-u` — generate a UUID instead of a password (defaults to v4).
- `--uuid-version` — select UUID version (`v4` or `v7`); implies `--uuid`.
- UUID v4: randomly generated per RFC 4122.
- UUID v7: 48-bit Unix millisecond timestamp + random, lexicographically sortable per RFC 9562.
- `--verbose` now also prints UUID version info when in UUID mode.

---

## [1.0.0] — 2026-02-24

### Added

- Password generation using ChaCha12 CSPRNG seeded from OS entropy (`rand` crate).
- Visually unambiguous character sets — excludes `I`, `L`, `O` (uppercase), `i`, `l`, `o` (lowercase), `0`, `1` (digits).
- Hybrid generation strategy: mandatory placement (≥ 2 chars per active set) + uniform fill + Fisher-Yates shuffle, guaranteeing complexity without rejection sampling.
- `--length` / `-l` — password length (minimum: 10, maximum: 4096).
- `--no-upper` — exclude uppercase letters.
- `--no-lower` — exclude lowercase letters.
- `--symbol` / `-s` — include symbols (`!@#$%^&*-_+=~()[]{};:,.?/`).
- `--number` / `-n` — include digits `2–9`.
- `--count` / `-c` — generate multiple passwords in one invocation (max: 10,000).
- `--verbose` / `-v` — print entropy estimate and pool size to stderr.
- Memory safety: all intermediate password buffers zeroized on drop via the `zeroize` crate.
- Pre-built binaries for Windows x86-64, Linux x86-64, Linux aarch64, macOS x86-64, macOS aarch64 via GitHub Actions release workflow.
- CI pipeline: `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`, `cargo audit`.

[Unreleased]: https://github.com/sharma-vikram/pgen/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/sharma-vikram/pgen/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/sharma-vikram/pgen/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sharma-vikram/pgen/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sharma-vikram/pgen/releases/tag/v1.0.0
