# pgen

> A fast, cryptographically secure command-line password generator.

[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-green.svg)](Cargo.toml)
[![CI](https://github.com/sharma-vikram/pgen/actions/workflows/ci.yml/badge.svg)](https://github.com/sharma-vikram/pgen/actions/workflows/ci.yml)

## Design & Philosophy

- **CSPRNG**: Uses `ChaCha12` (via `rand`) seeded from the OS entropy source.
- **Memory Safety**: All intermediate buffers are zeroized (wiped) from memory using the `zeroize` crate.
- **Usability**: Visually ambiguous characters (`I`, `l`, `1`, `O`, `0`) are excluded to avoid confusion.
- **Guaranteed Complexity**: Uses a hybrid generation strategy (Mandatory Placement + Uniform Fill + Fisher-Yates Shuffle) to **guarantee** at least 2 characters from every selected set (e.g., symbols, numbers) are present in the final password.

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](../../releases) page and place it anywhere on your `PATH`:

| Platform | File |
|----------|------|
| Windows x86-64 | `pgen-vX.Y.Z-x86_64-pc-windows-msvc.zip` |
| Linux x86-64 | `pgen-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 | `pgen-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz` |
| macOS x86-64 | `pgen-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `pgen-vX.Y.Z-aarch64-apple-darwin.tar.gz` |

### Build from source

**Prerequisites:** [Rust toolchain](https://rustup.rs) (Rust 1.85+)

```powershell
git clone https://github.com/sharma-vikram/pgen
cd pgen

# Standard Windows build
cargo build --release

# Smallest binary (recommended release target)
cargo build --release --target x86_64-pc-windows-gnullvm
```

The release binary is written to:
- `target\release\pgen.exe` (default)
- `target\x86_64-pc-windows-gnullvm\release\pgen.exe` (gnullvm target)

---

## Usage

```
pgen --length <LENGTH> [OPTIONS]
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
| `--help` | `-h` | Print help | |
| `--version` | `-V` | Print version | |

> **Note:** Uppercase and lowercase letters are **included by default**. Use `--no-upper` / `--no-lower` to opt out.

---

## Examples

**Basic — 16-character alphanumeric password:**
```
pgen --length 16
```
```
wBmJsXKpVtNcGfRu
```

**With symbols and numbers:**
```
pgen --length 20 --symbol --number
```
```
*6whGsV&hJRf@!Rm.M8K
```

**Lowercase and numbers only:**
```
pgen --length 14 --no-upper --number
```
```
x3kp7mjq9bnc4r
```

**Generate 5 passwords at once:**
```
pgen --length 16 --symbol --number --count 5
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
pgen --length 6 --symbol
```
```
Error: --length 6 is below the minimum of 10.
```

**Generate a UUID v4:**
```
pgen --uuid
```
```
f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**Generate 5 UUID v7s (timestamp-sortable):**
```
pgen -u --uuid-version v7 -c 5
```
```
019c9021-822e-7181-a8db-9c63b8bb621e
019c9021-822f-7730-94a5-e770f2bd211b
019c9021-8230-7786-9f49-cd836b2c963a
019c9021-8231-7773-98c6-df0b830e4926
019c9021-8232-7541-b1d3-4f2a9e8c1b05
```

---

## Character Sets

| Set | Characters | Excluded (ambiguous) |
|-----|-----------|----------------------|
| Uppercase | `A-Z` | `I`, `L`, `O` |
| Lowercase | `a-z` | `i`, `l`, `o` |
| Symbols | `!@#$%^&*-_+=~()[]{};:,.?/` | — |
| Digits | `0-9` | `0`, `1` |


---

CI runs on every push and pull request to `main`: `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`, and `cargo audit` (CVE scanning). See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a branch or PR. It
covers branch naming, commit message format, pull request rules, and the
release process.

---

## License

[MIT](LICENSE) © 2026 Sharma Vikram
