# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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

[Unreleased]: https://github.com/sharma-vikram/pgen/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/sharma-vikram/pgen/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sharma-vikram/pgen/releases/tag/v1.0.0
