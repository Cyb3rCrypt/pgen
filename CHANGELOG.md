# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- `passid::typeid::typeid_string(prefix, rng)` — public ergonomic entry point for
  generating a `TypeID` string. Validates the prefix, generates a monotonic `UUIDv7`,
  and returns `prefix_<26-char base32 suffix>` (or bare suffix when prefix is empty).
  Previously consumers had to manually compose `validate_prefix`, `next_v7_bytes`, and
  `encode_base32`, a security-critical multi-step operation with no safe single entry
  point.

### Changed

- Refactored monolithic `src/main.rs` (2 222 lines) into a `lib` + `bin`
  crate structure. `src/main.rs` is now a lightweight CLI frontend (~360
  lines); all generation logic lives in dedicated modules:
  `password`, `uuid`, `ulid`, `typeid`, `nanoid`, `ksuid`.
  The crate now exposes a public library API alongside the binary.
- `std_rng` feature moved from `[dependencies]` to `[dev-dependencies]`;
  release binaries no longer compile the seeded PRNG code paths.

### Fixed

- `run_typeid` now assembles each output line (`prefix_suffix\n`) into a single
  91-byte stack buffer before calling `write_all`. Previously four separate
  `write_all` calls (prefix, `_`, suffix, `\n`) were not atomic — a `BrokenPipe`
  between any two produced a truncated malformed line silently.
- `gen_password` now returns `Result<Zeroizing<Vec<u8>>>` instead of panicking
  when `length < required_sets.len() * MIN_PER_SET`. Library consumers calling
  the function directly with under-sized lengths now receive a descriptive `Err`
  rather than an integer underflow panic. The CLI path is unaffected — `Config`
  validates the same constraint before calling the function.
- NanoID `nanoid_custom` step formula now uses `u64` intermediates before
  casting back to `usize`, preventing theoretical overflow if size/alphabet
  limits are ever raised.
- Corrected misleading doc comment on `ulid_increment`: carry propagates
  from LSB (byte 9) toward MSB (byte 0), not "MSB-first".
- Removed redundant `#[cfg(debug_assertions)]` pool-disjoint check in
  `Config::try_from`; the invariant is fully covered by the
  `character_sets_are_disjoint` unit test in `password.rs`.

### Security

- All public generator functions (`gen_password`, `next_v7_bytes`, `gen_uuid_v4_bytes`,
  `next_ulid_bytes`, `nanoid_default`, `nanoid_custom`, `gen_ksuid_bytes`,
  `gen_ksuid_ms_bytes`) now require `rng: &mut impl CryptoRng`. Since `CryptoRng` is a
  supertrait of `Rng` in rand 0.10, callers can no longer pass a deterministic/seeded
  RNG (e.g. `StdRng`) — the compiler rejects it at the call site. Only OS-backed
  CSPRNGs such as `rand::rng()` satisfy the bound.
- All test code migrated from `StdRng::seed_from_u64(42)` to `rand::rng()`; the
  `std_rng` feature is no longer compiled into any build target.
- Added compile-time assertion that `NANOID_URL_ALPHABET.len() == 64`,
  making it impossible to silently break the bias-free `b & 63` indexing
  if the constant is ever modified.
- Added `debug_assert!(timestamp_ms < (1u64 << 48))` in `encode_ulid` to
  guard against silent high-bit truncation on out-of-range timestamps.

### Tests

- Added concurrent uniqueness tests: 8 threads × 500 IDs for both UUIDv7
  and ULID, verifying the internal `Mutex` guards serialise correctly under
  contention.
- Added TypeID prefix boundary tests: exactly 63-char prefix (valid),
  64-char prefix (rejected), and prefixes with internal underscores (valid).
- Added NanoID max valid alphabet test using the full 95-char printable
  ASCII range (`0x20`–`0x7E`).

## [1.6.0] — 2026-03-28

### Changed

- Binary and package renamed from `pgen` to `passid`. The CLI interface
  (flags, output format, exit codes) is unchanged — only the invocation name
  changes. Update any scripts, aliases, or CI pipelines accordingly.
- Repository moved to `https://github.com/sharma-vikram/passid`.
- Description updated to reflect DevOps positioning.

## [1.5.1] — 2026-03-28

### Fixed

- All output paths (`run_pass`, `run_uuid`, `run_typeid`, `run_ulid`, `run_nanoid`, `run_ksuid`) now handle `SIGPIPE`/`BrokenPipe` gracefully. Commands such as `passid -l 20 -c 1000 | head -1` previously printed `Error: Broken pipe` and exited 1; they now exit 0 silently.

### Changed

- CI: added `cargo-deny-action@v2` job for license and supply-chain checks; `deny.toml` added with MIT/Apache-2.0/Unicode-3.0 allowlist.
- CI: removed `--test-threads=1` from the test job — monotonic-state tests are properly isolated via mutex guards.

## [1.5.0] — 2026-03-26

### Added

- `--ksuid`: generate a Segment KSUID — a 27-character base62 encoded string combining a 32-bit timestamp (seconds since 2014) and 128-bit cryptographically secure random payload.
- `--ksuid-ms`: generate a `KsuidMs` — a Svix-compatible monotonic extension sacrificing 1 byte of payload for ~4ms sub-second precision to improve sorting guarantees, while maintaining Segment binary compatibility.
- Zero-allocation string formatting utilizing 27-byte stack arrays and disjoint-bit math for rapid base62 conversion.
- Full suite of CLI integration tests, argument conflict validations, boundary checks, and encoding/decoding round-trip tests for KSUID.
- Dedicated `--verbose` output for KSUID modes showing specification metadata.

## [1.4.0] — 2026-03-01

### Added

- `--nanoid` mode for generating NanoID-style IDs using the default
  URL-safe alphabet and default size `21`.
- `--nanoid-size` and `--nanoid-alphabet` options, including custom alphabet
  validation (printable ASCII, unique chars, length 2–255).
- NanoID generation paths inspired by upstream algorithm design: fast default path
  (`byte & 63`) and rejection-sampling custom path using dynamic `mask` and
  `step`.
- Unit and CLI integration tests covering NanoID output shape, custom alphabet
  behavior, conflicts, and argument validation.

## [1.3.1] — 2026-02-27

### Fixed

- Hardened error handling in monotonic UUIDv7/ULID generators by returning
  `Result` from spin-wait paths instead of `assert!` aborts, improving failure
  behavior under stalled clocks.
- Unified UUID v4 bit-setting logic through shared helpers to eliminate
  duplicated production/test manipulation code.
- Improved `TypeID` prefix validation by enforcing ASCII and byte-length limits
  consistently with output behavior.
- Resolved strict clippy issues for both `--all-targets` and `--all-features`
  gates.

### Added

- Expanded CLI integration coverage for argument edge cases, including missing
  required args, invalid boundaries, mode conflicts, and count validation across
  generation modes.

### Changed

- Synchronized README, contributing/release docs, and security policy metadata
  with current codebase and CI behavior.

## [1.3.0] — 2026-02-27

### Added

- `--ulid`: generate a [ULID](https://github.com/ulid/spec) — a 26-character
  Crockford Base32 encoded identifier with a 48-bit Unix millisecond timestamp
  and 80-bit random entropy. Monotonic ordering within the same millisecond is
  guaranteed by ripple-carry incrementing the entropy buffer (per ULID spec).
- `run_ulid` uses a zero-alloc `[u8; 26]` stack buffer hot path and `BufWriter`
  coalescing, consistent with `run_uuid` and `run_typeid`.
- `--verbose` mode for `--ulid` prints algorithm metadata to stderr.
- 7 new unit tests (`ulid_format_26_chars`, `ulid_chars_in_alphabet`,
  `ulid_first_char_le_7`, `ulid_monotonic_ordering`, `ulid_clock_rollback_clamped`,
  `ulid_uniqueness_smoke`, `encode_ulid_known_vector`) with `ULID_LOCK` + `UlidStateReset`
  RAII guard to avoid test-state pollution.
- 4 new integration tests in `tests/cli.rs` (`run_ulid_single_output`,
  `run_ulid_count_monotonic`, `run_ulid_verbose_to_stderr`,
  `run_ulid_conflicts_with_length`).

### Changed

- `run_pass --verbose` output label changed from `Entropy:` to `Estimated entropy:`
  to clarify that the reported value is an approximation.

## [1.2.3] — 2026-02-26

### Security

- `Config.pool` is now wrapped in `Zeroizing<Vec<u8>>`, ensuring the character pool
  bytes are zeroed on drop. The pool is not secret, but clearing it is consistent with
  the tool's security posture and closes a zeroization gap identified in an audit.
- `main()` now returns `std::process::ExitCode` instead of calling `process::exit(1)`,
  ensuring all destructors — including `Zeroizing<T>` drop impls — run on the error
  path rather than being bypassed by an abrupt libc exit.

### Performance

- `run_uuid` now uses a zero-alloc `format_uuid_bytes_buf` function that encodes UUID
  bytes directly into a caller-supplied `[u8; 36]` stack buffer, eliminating one
  `String` heap allocation per UUID. At `--count 10000` this removes 10 000 allocations.
- All three output modes (`run_pass`, `run_uuid`, `run_typeid`) now wrap stdout in a
  `BufWriter::with_capacity(65_536)`, coalescing per-item `write_all` calls into
  batched 64 KiB kernel writes and reducing syscall frequency at high `--count` values.

### Changed

- `UuidVersion` enum is now marked `#[non_exhaustive]`, preventing downstream breakage
  if future UUID versions (e.g. v8) are added as new variants.

### Fixed

- UUID v7 counter now seeds with 9 random bits (0–511) on millisecond advance per RFC 9562 
  §6.2 recommendation, leaving 3,584 headroom slots before exhaustion. Previously used 0,
  deviating from the RFC guidance.
- `next_v7_bytes` spin-loop now tracks cycle count with `MAX_SPIN_CYCLES = 50` bound and
  `assert!` panic, preventing indefinite hang if system clock is frozen (VM suspend, broken NTP).
- UUID v7 tests serialize `MONO_STATE` access via `V7_LOCK: Mutex<()>` guard, eliminating
  race conditions in parallel test execution beyond the CI's `--test-threads=1`.
- `uuid_v7_clock_rollback_clamped` test now uses `MonotonicStateReset` Drop guard to zero
  `MONO_STATE` even if assertions panic, preventing test pollution.
- Entropy calculation in `run_pass --verbose` now uses accurate two-phase formula
  (per-set bits + pool bits) instead of naïve pool-only calculation, eliminating ~10 bits
  of overstatement.

### Changed

- `format_uuid_bytes` optimized: replaced `format!` macro with direct hex loop using
  `const HEX: &[u8; 16]` into `String::with_capacity(36)`, eliminating ~10k allocations
  at `--count 10000`.
- `run_typeid` zero-alloc path: writes base32 bytes directly to stdout via 
  `handle.write_all()`, bypassing per-ID `String` allocation (~10k fewer allocs at 
  `--count 10000`). Function `gen_typeid` retained for tests, marked `#[allow(dead_code)]`.

### Docs

- Added comment in `run_pass` clarifying that `Zeroizing` covers only in-process buffer;
  bytes passed to `write_all()` enter kernel I/O buffers outside our control.
- Expanded `MonotonicState` block comment documenting 12-bit counter method, RFC 9562 §6.2
  compliance, clock clamping, spin-loop bounds, and mutex-poison assumption; clarified
  design is appropriate only for single-threaded CLI binary.
- Updated `run_pass` entropy comment explaining two-phase calculation (mandatory placement +
  uniform fill) to match accurate bit computation.

## [1.2.1] — 2026-02-25

### Fixed

- `validate_prefix` used `str::len()` (byte count) instead of `chars().count()` for the
  63-character limit, which could incorrectly reject valid multi-byte prefixes shorter
  than 63 Unicode characters (B1).
- Silent `.unwrap()` calls in `encode_base32` replaced with `.expect()` annotated with
  invariant explanations, making any future regression immediately diagnosable (B2).
- UUID v7 tests now serialize access to `MONO_STATE` via a `static V7_LOCK: Mutex<()>`
  guard, making them correct under parallel `cargo test` without requiring
  `--test-threads=1` (P3).
- `next_v7_bytes` spin-loop now escapes to `thread::sleep(100 µs)` after 10 000 spins,
  preventing CPU burn when the clock is frozen or suspended (VM pause, NTP leap
  second, test injection) (P4).

### Changed

- Count validation extracted into a `resolve_count()` helper, eliminating identical
  triplication across `run_pass`, `run_uuid`, and `run_typeid` (P1).
- `format_uuid_bytes` refactored from 16 individual byte arguments to 5 RFC 4122
  named groups (`p0`–`p4`), matching the standard `time_low / time_mid /
  time_hi_and_version / clock_seq / node` field layout (P2).
- UUID formatting optimization: replaced `format!` macro with direct hex loop using
  `const HEX: &[u8; 16]` into `String::with_capacity(36)`, eliminating ~10k allocations
  at `--count 10000` (P3).
- TypeID generation zero-alloc path: `run_typeid` now writes base32 bytes directly to
  stdout via `handle.write_all()`, bypassing per-ID `String` allocation and achieving
  ~10k fewer allocations at `--count 10000` (P4). Function `gen_typeid` is retained
  for test usage and marked `#[allow(dead_code)]`.

### Docs

- Added comment in `run_pass` noting that `Zeroizing` covers only the in-process
  buffer; bytes written to `write_all()` enter kernel I/O buffers outside our
  control (S1).
- Added block comment on `MonotonicState` documenting the 12-bit counter method,
  RFC 9562 §6.2 compliance, clock clamping behavior, and the mutex-poison assumption;
  documented that this design is appropriate only for a single-threaded CLI binary (S2).
- Entropy calculation formula updated in comments: clarified two-phase strategy
  (mandatory placement per set + uniform fill from combined pool) to reflect
  accurate `log2` computation instead of pool-only naïve formula (S3).

## [1.2.0] — 2026-02-25

### Added

- `--typeid` flag: generate a [TypeID](https://github.com/jetify-com/typeid) —
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

[Unreleased]: https://github.com/sharma-vikram/passid/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/sharma-vikram/passid/compare/v1.5.1...v1.6.0
[1.5.1]: https://github.com/sharma-vikram/passid/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/sharma-vikram/passid/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/sharma-vikram/passid/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/sharma-vikram/passid/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/sharma-vikram/passid/compare/v1.2.3...v1.3.0
[1.2.3]: https://github.com/sharma-vikram/passid/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/sharma-vikram/passid/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/sharma-vikram/passid/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/sharma-vikram/passid/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/sharma-vikram/passid/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sharma-vikram/passid/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sharma-vikram/passid/releases/tag/v1.0.0
