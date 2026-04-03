# passid

> Fast, secure, secret-safe CLI **and Rust library** for passwords + modern monotonic IDs (UUIDv7, ULID, KSUID, TypeID, NanoID). Built for DevOps pipelines.

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/passid.svg)](https://crates.io/crates/passid)
[![CI](https://github.com/sharma-vikram/passid/actions/workflows/ci.yml/badge.svg)](https://github.com/sharma-vikram/passid/actions/workflows/ci.yml)

## Design & Philosophy

- **CSPRNG**: All output uses `rand::rng()` from the `rand` crate, backed by OS randomness and suitable for cryptographic generation.
- **Memory Safety**: Intermediate password buffers are zeroized (wiped) on drop using the `zeroize` crate, limiting the window in which secrets are retained in process memory.
- **Guaranteed Password Complexity**: A hybrid strategy (Mandatory Placement + Uniform Fill + Fisher-Yates Shuffle) **guarantees** at least 2 characters from every selected set are present, with no rejection sampling.
- **Unambiguous Characters**: Password character sets exclude visually similar glyphs (`I`, `L`, `O` uppercase; `i`, `l`, `o` lowercase; `0`, `1` digits). The TypeID base32 alphabet (Crockford) similarly excludes `i`, `l`, `o`, `u`.
- **Monotonic UUID v7**: Implements RFC 9562 §6.2 Method 1 — a 12-bit counter in `rand_a` ensures strict lexicographic ordering across all calls within the same process, even within the same millisecond. Clock rollbacks are clamped rather than panicking.
- **TypeID**: Implements spec v0.3.0 — a validated lowercase ASCII prefix, a `_` separator, and a 26-character Crockford base32-encoded UUID v7 suffix. Monotonic ordering is inherited from the v7 timestamp + counter.
- **ULID**: Implements the [ULID spec](https://github.com/ulid/spec) — a 26-character Crockford Base32 encoded identifier with a 48-bit Unix millisecond timestamp and 80-bit random entropy. Monotonic ordering within the same millisecond is guaranteed by ripple-carry incrementing the entropy buffer, matching the spec's monotonicity extension.
- **NanoID**: Implements NanoID-compatible generation with the default URL-safe alphabet (`A-Za-z0-9_-`) and optional custom alphabets using rejection sampling to avoid modulo bias.
- **KSUID**: Implements the Segment KSUID standard — a 27-character base62 encoded string combining a 32-bit timestamp (seconds since 2014) and 128 bits of cryptographically secure random payload. Zero-allocation formatting paths are heavily utilized.
- **KsuidMs**: A Svix-compatible monotonic extension that sacrifices 1 byte of the standard KSUID payload for a 4ms sub-second fractional counter, providing finer temporal sorting granularity while preserving exact 27-character Segment KSUID binary decoding compatibility.

## Installation

### cargo install

```sh
cargo install passid
```

### Pre-built binaries

Download the latest release for your platform from the [Releases](../../releases) page and place it anywhere on your `PATH`:

| Platform | File |
|----------|------|
| Windows x86-64 | `passid-v1.6.0-x86_64-pc-windows-msvc.zip` |
| Linux x86-64 | `passid-v1.6.0-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `passid-v1.6.0-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86-64 | `passid-v1.6.0-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `passid-v1.6.0-aarch64-apple-darwin.tar.gz` |

### Build from source

**Prerequisites:** [Rust toolchain](https://rustup.rs) (Rust 1.85+)

```powershell
git clone https://github.com/sharma-vikram/passid
cd passid

# Standard Windows build
cargo build --release

# Smallest binary (recommended release target)
cargo build --release --target x86_64-pc-windows-gnullvm
```

The release binary is written to:
- `target\release\passid.exe` (default)
- `target\x86_64-pc-windows-gnullvm\release\passid.exe` (gnullvm target)

---

## Library Usage

`passid` is also available as a Rust library crate. Add it to your project:

```sh
cargo add passid
```

Or in `Cargo.toml`:

```toml
[dependencies]
passid = "1"
```

### Modules

| Module | Public API |
|--------|-----------|
| `passid::password` | `gen_password` — configurable password generator with zeroized output |
| `passid::uuid` | `gen_uuid_v4_bytes`, `next_v7_bytes`, `format_uuid_bytes_buf` |
| `passid::ulid` | `next_ulid_bytes` — monotonic ULID |
| `passid::typeid` | `encode_base32`, `validate_prefix` |
| `passid::nanoid` | `nanoid_default`, `nanoid_custom`, `validate_nanoid_alphabet` |
| `passid::ksuid` | `gen_ksuid_bytes`, `gen_ksuid_ms_bytes` |

> **Note:** Always pass `rand::rng()` (the OS-backed CSPRNG) as the RNG
> argument in production paths. Full API documentation will be available on
> [docs.rs](https://docs.rs/passid) once the crate is published.

---

## Usage

```
passid --length <LENGTH> [OPTIONS]
```

### Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--length <N>` | `-l` | Password length (minimum: 10) | required |
| `--symbol` | `-s` | Include symbols: `!@#$%^&*-_+=~()[]{};:,.?/` | off |
| `--number` | `-n` | Include digits: `2–9` | off |
| `--no-upper` | | Exclude uppercase letters | |
| `--no-lower` | | Exclude lowercase letters | |
| `--count <N>` | `-c` | Number of items to generate (max: 10,000) | `1` |
| `--verbose` | `-v` | Print entropy / pool size (password) or UUID version info to stderr | off |
| `--uuid` | `-u` | Generate a UUID instead of a password (defaults to v4) | |
| `--uuid-version <VER>` | | UUID version to generate: `v4` or `v7`; implies `--uuid` | |
| `--typeid` | | Generate a TypeID (spec v0.3.0): lowercase prefix + Crockford base32 UUID v7 suffix | |
| `--typeid-prefix <PREFIX>` | | Prefix for the TypeID (1–63 lowercase letters/underscores); implies `--typeid` | |
| `--ulid` | | Generate a ULID (monotonic 48-bit timestamp + 80-bit entropy, Crockford Base32) | |
| `--nanoid` | | Generate a NanoID (URL-safe by default) | |
| `--nanoid-size <N>` | | NanoID length (minimum: 1, maximum: 4096) | `21` |
| `--nanoid-alphabet <ALPHABET>` | | Custom NanoID alphabet (2–255 unique printable ASCII chars) | default URL-safe |
| `--ksuid` | | Generate a KSUID (K-Sortable Unique ID, 27-char base62, Segment-compatible) | |
| `--ksuid-ms` | | Generate a `KsuidMs` (4ms sub-second precision, 15-byte payload, Svix-compatible) | |
| `--help` | `-h` | Print help | |
| `--version` | `-V` | Print version | |

> **Note:** Uppercase and lowercase letters are **included by default**. Use `--no-upper` / `--no-lower` to opt out.

> **Distribution note:** Fill characters are sampled uniformly from the pooled alphabet, so larger enabled sets (for example symbols) appear more often than smaller sets (for example digits).

---

## Examples

**Basic — 16-character alphanumeric password:**
```
passid --length 16
```
```
wBmJsXKpVtNcGfRu
```

**With symbols and numbers:**
```
passid --length 20 --symbol --number
```
```
*6whGsV&hJRf@!Rm.M8K
```

**Lowercase and numbers only:**
```
passid --length 14 --no-upper --number
```
```
x3kp7mjq9bnc4r
```

**Generate 5 passwords at once:**
```
passid --length 16 --symbol --number --count 5
```
```
8j={AK9X^S;uf!W#
5;tj9c%7VQHqW;tr
F8gtqgrA5%Ya@}yN
HSg6k2~$uU}%p%9B
MM9Sn(,TUT6ew6!!
```

**Minimum length error:**
```
passid --length 6 --symbol
```
```
Error: --length 6 is below the minimum of 10.
```

**Generate a UUID v4:**
```
passid --uuid
```
```
f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**Generate 5 UUID v7s (timestamp-sortable):**
```
passid -u --uuid-version v7 -c 5
```
```
019c9021-822e-7181-a8db-9c63b8bb621e
019c9021-822f-7730-94a5-e770f2bd211b
019c9021-8230-7786-9f49-cd836b2c963a
019c9021-8231-7773-98c6-df0b830e4926
019c9021-8232-7541-b1d3-4f2a9e8c1b05
```

**Generate a TypeID with a prefix:**
```
passid --typeid-prefix user
```
```
user_01h455vb4pex5vsknk084sn02q
```

**Generate 3 TypeIDs with no prefix (bare suffix):**
```
passid --typeid --count 3
```
```
01h455vb4pex5vsknk084sn02q
01h455vb4r7nd5w8zeyk7j3q24
01h455vb4s0xr8ftx09c4t1k6e
```

**Generate a ULID:**
```
passid --ulid
```
```
01JNCQ8MZDBK3P9S6X4V2T7RFW
```

**Generate 5 ULIDs (monotonically ordered):**
```
passid --ulid --count 5
```
```
01JNCQ8MZDEK5V8W2P4N3Q6TXR
01JNCQ8MZDEK5V8W2P4N3Q6TXS
01JNCQ8MZDEK5V8W2P4N3Q6TXT
01JNCQ8MZDEK5V8W2P4N3Q6TXV
01JNCQ8MZDEK5V8W2P4N3Q6TXW
```

**Generate a default NanoID (21 chars):**
```
passid --nanoid
```
```
V1StGXR8_Z5jdHi6B-myT
```

**Generate a 32-char NanoID:**
```
passid --nanoid-size 32
```
```
Xv9A2x2N8y7sV3rQ1mL0bPzKcT4uW5dE
```

**Generate NanoID with custom alphabet:**
```
passid --nanoid --nanoid-alphabet ABC123 --nanoid-size 16
```
```
AC21B3A12C31AB2C
```

**Generate a KSUID:**
```
passid --ksuid
```
```
3BSGB9Ov0Y1QEgoXb993522G2PH
```

**Generate 5 KsuidMs (4ms precision):**
```
passid --ksuid-ms --count 5
```
```
3BSGC23KzC54NDJrCrSvmVzw2K4
3BSGC24cIo8VRgG1sPoOoHaHbbK
3BSGC24Yoa3T2hzekUsoU6TuOHd
3BSGC23ReVuoeZHWV3vdDww9Vjz
3BSGC23azAu7VsGhKLzOQSuRZZM
```

---

## Character Sets

| Set | Characters | Excluded (ambiguous) |
|-----|-----------|----------------------|
| Uppercase | `A-Z` | `I`, `L`, `O` |
| Lowercase | `a-z` | `i`, `l`, `o` |
| Symbols | `!@#$%^&*-_+=~()[]{};:,.?/` | — |
| Digits | `2–9` | `0`, `1` |


---

CI runs on every push and pull request to `main`: `cargo test --all-features`, `cargo fmt --check`, `cargo clippy --all-features -- -D warnings`, `rustsec/audit-check`, and `cargo deny check`. See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a branch or PR. It
covers branch naming, commit message format, pull request rules, and the
release process.

All notable changes to this project will be documented in the [CHANGELOG.md](CHANGELOG.md).

---

## Security

As a cryptographic tool, security is a top priority. If you discover a security vulnerability, please do NOT open a public issue. Let us know by following the instructions in our [Security Policy](SECURITY.md).

---

## Project Rename Notice

This project was previously named **`pgen`**. It was renamed to **`passid`** in March 2026.

**Why:**
- Avoided name collisions with other password generators
- `passid` clearly communicates **pass**words + modern **id**entifiers
- Better branding for the DevOps community

**Impact:** All CLI flags, output format, and exit codes are **unchanged**. GitHub automatically redirects old repository URLs (`sharma-vikram/pgen` → `sharma-vikram/passid`). Old release assets remain accessible.

Update any scripts, aliases, or CI pipelines that invoke `pgen` to use `passid` instead.

---

## License

[MIT](LICENSE) © 2026 Sharma Vikram
