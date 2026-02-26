#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pgen` — Fast random password, `UUID`, `TypeID`, and `ULID` generator.
use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, seq::IndexedRandom, seq::SliceRandom};
use std::io::Write;
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

// Visually unambiguous character sets, stored as ASCII byte slices.
// Excluded: I, L, O (uppercase) · i, l, o (lowercase) · 0, 1 (digits)
const U_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
const L_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const S_CHARS: &[u8] = b"!@#$%^&*-_+=~()[]{};:,.?/";
const N_CHARS: &[u8] = b"23456789";

// ── TypeID base32 encoding ──────────────────────────────────────────────────
//
// Spec: https://github.com/jetify-com/typeid (v0.3.0)
//
// Crockford base32 alphabet, lowercase. Index 0 = '0', index 31 = 'z'.
// Characters 'i', 'l', 'o', 'u' are absent (visually ambiguous).
const TYPEID_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

// ── ULID Crockford Base32 encoding ─────────────────────────────────────────
//
// Spec: https://github.com/ulid/spec
//
// Crockford base32 alphabet, UPPERCASE. Index 0 = '0', index 31 = 'Z'.
// Characters 'I', 'L', 'O', 'U' are absent (visually ambiguous).
const ULID_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const MIN_LENGTH: usize = 10;
const MAX_LENGTH: usize = 4096;
const MAX_COUNT: usize = 10_000;
const MIN_PER_SET: usize = 2;

#[derive(Clone, ValueEnum)]
#[non_exhaustive]
enum UuidVersion {
    /// Randomly generated (RFC 4122)
    V4,
    /// Unix-timestamp + random, lexicographically sortable (RFC 9562)
    V7,
}

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    // clap 4's default template omits {author}; this restores it.
    help_template = "{name} {version}  —  {author} {about-section}\n{usage-heading} {usage}\n\n{all-args}{after-help}",
)]
#[allow(clippy::struct_excessive_bools)] // inherent to a flag-heavy CLI struct
struct Args {
    /// Password length (minimum: 10)
    #[arg(
        short,
        long,
        value_name = "LENGTH",
        required_unless_present_any = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"],
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"]
    )]
    length: Option<usize>,

    /// Exclude uppercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"])]
    no_upper: bool,

    /// Exclude lowercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"])]
    no_lower: bool,

    /// Include symbols: !@#$%^&*-_+=~()[]{};:,.?/
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"])]
    symbol: bool,

    /// Include digits 2-9 (visually unambiguous)
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid"])]
    number: bool,

    /// Number of items to generate (max: 10 000)
    #[arg(short, long, value_name = "COUNT")]
    count: Option<usize>,

    /// Show entropy / pool size (password) or UUID version info (uuid)
    #[arg(short, long)]
    verbose: bool,

    /// Generate a UUID instead of a password
    #[arg(short, long)]
    uuid: bool,

    /// UUID version to generate
    #[arg(long, value_enum)]
    uuid_version: Option<UuidVersion>,

    /// Generate a `TypeID` (`UUIDv7` encoded as base32 with a type prefix)
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version"])]
    typeid: bool,

    /// Type prefix for the `TypeID` (max 63 lowercase [a-z_] chars); implies --typeid
    #[arg(long, value_name = "PREFIX", conflicts_with_all = ["uuid", "uuid_version"])]
    typeid_prefix: Option<String>,

    /// Generate a ULID (monotonic, 48-bit timestamp + 80-bit entropy, Crockford Base32)
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "length"])]
    ulid: bool,
}

struct Config {
    length: usize,
    count: usize,
    required_sets: Vec<&'static [u8]>,
    // Zeroizing ensures pool bytes are cleared on drop. The pool is not
    // secret, but wiping it is consistent with the tool's security posture.
    pool: Zeroizing<Vec<u8>>,
    verbose: bool,
}

impl TryFrom<&Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: &Args) -> Result<Self> {
        let length = args
            .length
            .expect("clap guarantees --length is present in password mode");

        if length < MIN_LENGTH {
            bail!("--length {length} is below the minimum of {MIN_LENGTH}.");
        }
        if length > MAX_LENGTH {
            bail!("--length {length} exceeds the maximum of {MAX_LENGTH}.");
        }

        let required_sets: Vec<&'static [u8]> = [
            (!args.no_upper, U_CHARS as &[u8]),
            (!args.no_lower, L_CHARS),
            (args.symbol, S_CHARS),
            (args.number, N_CHARS),
        ]
        .into_iter()
        .filter_map(|(enabled, set)| enabled.then_some(set))
        .collect();

        if required_sets.is_empty() {
            bail!(
                "No character sets are active. Use --no-upper / --no-lower \
                 only when --symbol or --number is also enabled."
            );
        }

        let min_required = required_sets.len() * MIN_PER_SET;
        if length < min_required {
            bail!(
                "--length {length} is too short: {} active set(s) each require at least \
                 {MIN_PER_SET} characters (minimum needed: {min_required}).",
                required_sets.len(),
            );
        }

        let count = resolve_count(args.count)?;

        let pool: Vec<u8> = required_sets
            .iter()
            .flat_map(|set| set.iter().copied())
            .collect();

        #[cfg(debug_assertions)]
        {
            let mut s = pool.clone();
            s.sort_unstable();
            assert!(
                s.windows(2).all(|w| w[0] != w[1]),
                "pool contains duplicate bytes — character sets must be disjoint"
            );
        }

        Ok(Self {
            length,
            count,
            required_sets,
            pool: Zeroizing::new(pool),
            verbose: args.verbose,
        })
    }
}

/// Generates a single password of **exactly** `length` ASCII bytes.
/// Note on distribution: "Uniform fill" draws uniformly from the *pool*.
/// Since character sets vary in size (e.g., 8 digits vs 25 symbols),
/// a symbol is more likely to appear in a fill slot than a digit. This
/// reflects the natural distribution of the pooled characters.
///
/// Returns a `Zeroizing<Vec<u8>>` (all ASCII). The wrapper guarantees
/// zeroization on drop — no manual cleanup required by the caller.
#[must_use = "password bytes must not be discarded — Zeroizing ensures cleanup on drop"]
fn pgen(
    length: usize,
    required_sets: &[&'static [u8]],
    pool: &[u8],
    rng: &mut impl Rng,
) -> Zeroizing<Vec<u8>> {
    let mut pwd: Vec<u8> = Vec::with_capacity(length);

    for set in required_sets {
        for _ in 0..MIN_PER_SET {
            pwd.push(
                *set.choose(rng)
                    .expect("invariant: set is non-empty; validated by Config"),
            );
        }
    }

    let remaining = length - pwd.len();
    for _ in 0..remaining {
        pwd.push(
            *pool
                .choose(rng)
                .expect("invariant: pool is non-empty; validated by Config"),
        );
    }

    pwd.shuffle(rng);

    Zeroizing::new(pwd)
}

/// Generates a UUID v4 (randomly generated, RFC 4122).
#[cfg(test)]
#[must_use]
fn gen_uuid_v4(rng: &mut impl Rng) -> String {
    let mut b: [u8; 16] = rng.random();
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 0b10xxxxxx (RFC 4122)
    format_uuid_bytes(&b)
}

// ── Monotonic UUIDv7 state ───────────────────────────────────────────────────
//
// RFC 9562 §6.2 Method 1: fixed-length dedicated counter in `rand_a` (12 bits).
//
// Layout of the 16-byte UUID:
//   [0..6]  48-bit big-endian millisecond timestamp
//   [6]     0x70 | counter[11..8]   (version nibble + top 4 bits of counter)
//   [7]     counter[7..0]           (low 8 bits of counter)
//   [8]     0x80 | rand[5..0]       (variant bits + 6 random bits)
//   [9..16] 56 random bits
//
// Counter is 12 bits (0x000–0xFFF). On each millisecond advance the counter
// is seeded with 9 random bits (0x000–0x1FF), leaving 3 584 headroom slots
// before exhaustion (RFC 9562 §6.2 recommendation). On exhaustion within the
// same millisecond the function spin-waits (bounded to ~500 ms) until the
// system clock advances.
//
// Clock rollback: clamped to `last_ms`; counter keeps incrementing.
// This avoids panicking in production while preserving local monotonicity.
//
// Mutex poisoning: `.expect()` panics on a poisoned mutex, terminating the
// current thread. This is acceptable for a single-threaded CLI binary.
// Do not embed this module in a library or async runtime without replacing
// `.expect()` with proper error propagation.

struct MonotonicState {
    last_ms: u64,
    counter: u16, // only low 12 bits are used; upper 4 bits always zero
}

static MONO_STATE: OnceLock<Mutex<MonotonicState>> = OnceLock::new();

fn mono_state() -> &'static Mutex<MonotonicState> {
    MONO_STATE.get_or_init(|| {
        Mutex::new(MonotonicState {
            last_ms: 0,
            counter: 0,
        })
    })
}

/// Returns the current Unix timestamp in milliseconds.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before the UNIX epoch")
            .as_millis(),
    )
    .expect("timestamp overflows u64 (~584 million years from epoch)")
}

/// Core monotonic `UUIDv7` byte generator (RFC 9562 §6.2 Method 1).
///
/// For any two calls the returned 16-byte value is strictly greater
/// (lexicographically) than any previously returned value. Clock rollbacks are
/// clamped; counter exhaustion within the same millisecond causes the caller
/// to spin-wait (bounded to ~500 ms) until the clock advances, so monotonicity
/// is unconditional.
///
/// # Panics
/// Panics if the system clock does not advance within ~500 ms (50 sleep
/// cycles). This indicates a frozen or suspended clock and is unrecoverable
/// for a monotonic generator.
fn next_v7_bytes(rng: &mut impl Rng) -> [u8; 16] {
    // 50 sleep cycles × (10 000 spins + 100 µs sleep each) ≈ 500 ms total.
    // A real clock must advance within this window; if not, the system is broken.
    const MAX_SPIN_CYCLES: u32 = 50;

    let mut state = mono_state().lock().expect("MonotonicState mutex poisoned");
    let mut spins: u32 = 0;
    let mut cycles: u32 = 0;

    let (ms, counter) = loop {
        let ms = now_ms().max(state.last_ms); // clamp: never go backward

        if ms > state.last_ms {
            // Clock advanced — seed counter randomly per RFC 9562 §6.2.
            // 9 random bits (0–511) leaves 3 584 headroom slots before
            // counter exhaustion within a single millisecond.
            state.last_ms = ms;
            state.counter = rng.random::<u16>() & 0x01FF;
            break (ms, state.counter);
        }

        // Same millisecond (or clamped rollback).
        if state.counter < 0x0FFF {
            state.counter += 1;
            break (ms, state.counter);
        }

        // Counter exhausted — release lock and wait for clock to advance.
        // Spin briefly, then sleep to avoid burning CPU on a frozen or
        // suspended clock (VM pause, NTP leap second, test injection).
        drop(state);
        spins += 1;
        if spins < 10_000 {
            std::hint::spin_loop();
        } else {
            std::thread::sleep(std::time::Duration::from_micros(100));
            spins = 0;
            cycles += 1;
            assert!(
                cycles < MAX_SPIN_CYCLES,
                "UUIDv7 counter exhausted: clock did not advance within \
                 {MAX_SPIN_CYCLES} sleep cycles (~500 ms)"
            );
        }
        state = mono_state().lock().expect("MonotonicState mutex poisoned");
    };
    drop(state); // release ASAP; don't hold the lock while building the UUID bytes
    let ms_be = ms.to_be_bytes(); // [2..8] = lower 48 bits
    let rand_tail: [u8; 8] = rng.random(); // 64 random bits for bytes 8–15

    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&ms_be[2..8]); // 48-bit timestamp
    b[6] = 0x70 | u8::try_from(counter >> 8).expect("12-bit counter: bits [11..8] fit u8"); // ver=7
    b[7] = u8::try_from(counter & 0xFF).expect("lower 8 bits always fit u8"); // counter[7..0]
    b[8] = 0x80 | (rand_tail[0] & 0x3F); // variant=10, 6 rand bits
    b[9..16].copy_from_slice(&rand_tail[1..8]); // 56 random bits

    b
}

/// Generates a UUID v7 (monotonic, RFC 9562 §6.2 Method 1).
///
/// Strict lexicographic ordering is guaranteed across all calls within the
/// same process, even within the same millisecond (12-bit counter).
#[cfg(test)]
#[must_use]
fn gen_uuid_v7(rng: &mut impl Rng) -> String {
    format_uuid_bytes(&next_v7_bytes(rng))
}

/// Encodes 16 UUID bytes into the 36-byte `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// ASCII representation, writing into a caller-supplied stack buffer.
/// No allocation — intended for use in output hot-paths.
fn format_uuid_bytes_buf(b: &[u8; 16], out: &mut [u8; 36]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos: usize = 0;
    for (i, &byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out[pos] = b'-';
            pos += 1;
        }
        out[pos] = HEX[(byte >> 4) as usize];
        out[pos + 1] = HEX[(byte & 0x0F) as usize];
        pos += 2;
    }
}

/// Returns the UUID as an owned `String`. Used by `gen_uuid_v4` / `gen_uuid_v7`
/// and their test callers. Output hot-paths use `format_uuid_bytes_buf` instead.
#[cfg(test)]
fn format_uuid_bytes(b: &[u8; 16]) -> String {
    let mut buf = [0u8; 36];
    format_uuid_bytes_buf(b, &mut buf);
    // buf contains only ASCII hex digits and hyphens — always valid UTF-8.
    std::str::from_utf8(&buf)
        .expect("UUID buffer contains only ASCII hex digits and hyphens")
        .to_owned()
}

// ── TypeID encoding / validation / generation ────────────────────────────────

/// Encodes a 16-byte (128-bit) UUID into the 26-character `TypeID` base32 suffix.
///
/// Two zero bits are prepended, giving 130 bits split into 26 × 5-bit groups.
/// The first output character is always ≤ `'7'` (the top 2 bits are zero).
///
/// # Panics
/// Never in practice — `out` is exactly 26 elements so `i ∈ 0..=25`, making
/// `5 * i ∈ 0..=125`, which trivially fits `u32` and keeps `shift ≥ 0`.
#[must_use]
fn encode_base32(uuid: &[u8; 16]) -> [u8; 26] {
    let n = u128::from_be_bytes(*uuid);
    // Group i (0 = leftmost): extract 5 bits starting at bit position 125 - 5*i.
    // i=0  → shift 125 → top 5 bits of the 130-bit value (top 2 always zero → ≤ 7).
    // i=25 → shift 0   → bottom 5 bits of n.
    let mut out = [0u8; 26];
    for (i, out_byte) in out.iter_mut().enumerate() {
        // i ∈ 0..=25 (26-element array), so 5*i ∈ 0..=125 — always fits u32 and shift ≥ 0.
        let shift = 125u32 - u32::try_from(5 * i).expect("i ≤ 25, so 5*i ≤ 125, fits u32");
        let index = usize::try_from((n >> shift) & 0x1F)
            .expect("masked 5-bit value 0..=31 always fits usize");
        *out_byte = TYPEID_ALPHABET[index];
    }
    out
}

/// Validates a `TypeID` prefix against the spec (v0.3.0).
///
/// Returns `Ok(())` if the prefix is valid, or a descriptive `Err` otherwise.
fn validate_prefix(prefix: &str) -> Result<()> {
    let char_count = prefix.chars().count();
    if char_count > 63 {
        bail!("TypeID prefix is {char_count} characters; maximum is 63.");
    }
    if prefix.is_empty() {
        return Ok(());
    }
    if !prefix.starts_with(|c: char| c.is_ascii_lowercase()) {
        bail!("TypeID prefix {prefix:?} must start with a lowercase ASCII letter [a-z].");
    }
    if !prefix.ends_with(|c: char| c.is_ascii_lowercase()) {
        bail!("TypeID prefix {prefix:?} must end with a lowercase ASCII letter [a-z].");
    }
    if let Some(bad) = prefix.chars().find(|&c| !matches!(c, 'a'..='z' | '_')) {
        bail!(
            "TypeID prefix {prefix:?} contains invalid character {bad:?}; \
             only lowercase ASCII letters and underscores are permitted."
        );
    }
    Ok(())
}

/// Generates a `TypeID` with the given prefix and a fresh monotonic `UUIDv7` suffix.
///
/// Output format: `prefix_suffix` (26-char base32) or bare suffix when prefix is empty.
///
/// # Errors
/// Returns `Err` if `prefix` fails validation (see [`validate_prefix`]).
///
/// # Note
/// Used by unit tests; `run_typeid` bypasses this to avoid per-ID heap allocation.
#[allow(dead_code)]
fn gen_typeid(prefix: &str, rng: &mut impl Rng) -> Result<String> {
    validate_prefix(prefix)?;
    let uuid_bytes = next_v7_bytes(rng);
    let suffix = encode_base32(&uuid_bytes);
    // TYPEID_ALPHABET is pure ASCII, so the output is always valid UTF-8.
    let suffix_str =
        std::str::from_utf8(&suffix).expect("base32 suffix is always valid ASCII/UTF-8");
    let typeid = if prefix.is_empty() {
        suffix_str.to_owned()
    } else {
        format!("{prefix}_{suffix_str}")
    };
    Ok(typeid)
}

// ---------------------------------------------------------------------------
// Monotonic ULID state
//
// Layout of the 26-character output:
//   chars  0..10  — 48-bit Unix timestamp in ms (10 × 5-bit groups)
//   chars 10..26  — 80-bit entropy         (16 × 5-bit groups)
//
// Monotonicity within the same millisecond is achieved by ripple-carry
// incrementing the raw 10-byte entropy buffer (MSB-first), identical to
// the approach specified in https://github.com/ulid/spec#monotonicity.
//
// Clock rollback is CLAMPED (same policy as UUIDv7): the last known
// timestamp is reused and the entropy buffer is incremented, so the
// output is always strictly greater than the previous value.
//
// Entropy overflow (all 80 bits set within one millisecond) triggers a
// spin-wait bounded to 500 ms — identical to UUIDv7's counter-exhaustion
// handling — rather than returning an error, keeping the API infallible
// for callers and consistent with the rest of pgen.
// ---------------------------------------------------------------------------
struct UlidState {
    last_ms: u64,
    entropy: [u8; 10], // 80-bit random component
}

static ULID_STATE: OnceLock<Mutex<UlidState>> = OnceLock::new();

fn ulid_state() -> &'static Mutex<UlidState> {
    ULID_STATE.get_or_init(|| {
        Mutex::new(UlidState {
            last_ms: 0,
            entropy: [0u8; 10],
        })
    })
}

/// Ripple-carry increment on the 80-bit (10-byte) entropy buffer, MSB-first.
/// Returns `false` if all 80 bits are already 1 (overflow).
fn ulid_increment(entropy: &mut [u8; 10]) -> bool {
    for byte in entropy.iter_mut().rev() {
        if *byte < 255 {
            *byte += 1;
            return true;
        }
        *byte = 0;
    }
    false // overflow: every byte wrapped to 0
}

/// Returns the next monotonic ULID as a raw `[u8; 26]` of ASCII bytes.
///
/// Spin-wait behaviour on entropy overflow mirrors `next_v7_bytes`:
/// bounded to 500 ms (50 sleep cycles); panics if the clock does not
/// advance within that window.
fn next_ulid_bytes(rng: &mut impl Rng) -> [u8; 26] {
    const MAX_SPIN_CYCLES: u32 = 50;

    let mut state = ulid_state().lock().expect("UlidState mutex poisoned");
    let mut spins: u32 = 0;
    let mut cycles: u32 = 0;

    let (ms, entropy_snapshot) = loop {
        let ms = now_ms().max(state.last_ms); // clamp: never go backward

        if ms > state.last_ms {
            // New millisecond — reseed entropy from CSPRNG.
            state.last_ms = ms;
            state.entropy = rng.random::<[u8; 10]>();
            break (ms, state.entropy);
        }

        // Same millisecond (or clamped rollback) — increment entropy.
        if ulid_increment(&mut state.entropy) {
            break (state.last_ms, state.entropy);
        }

        // Entropy exhausted — release lock and wait for clock to advance.
        drop(state);
        spins += 1;
        if spins >= 10_000 {
            std::thread::sleep(std::time::Duration::from_micros(100));
            spins = 0;
            cycles += 1;
            assert!(
                cycles < MAX_SPIN_CYCLES,
                "ULID entropy exhausted: clock did not advance within \
                 {MAX_SPIN_CYCLES} sleep cycles (500 ms)"
            );
        } else {
            std::hint::spin_loop();
        }
        state = ulid_state().lock().expect("UlidState mutex poisoned");
    };

    drop(state); // release ASAP; encoding is pure computation

    encode_ulid(ms, &entropy_snapshot)
}

/// Encodes a 48-bit timestamp and 80-bit entropy into a 26-byte
/// Crockford Base32 ASCII buffer (stack-allocated, zero heap).
fn encode_ulid(timestamp_ms: u64, entropy: &[u8; 10]) -> [u8; 26] {
    let mut buf = [0u8; 26];

    // Encode 48-bit timestamp into chars 0..10 (10 × 5-bit groups), MSB first.
    let mut t = timestamp_ms;
    for i in (0..10).rev() {
        buf[i] = ULID_ALPHABET[(t % 32) as usize];
        t /= 32;
    }

    // Encode 80-bit entropy into chars 10..26 (16 × 5-bit groups), MSB first.
    // Pack 10 bytes into a u128 then extract 5-bit groups.
    let mut r: u128 = 0;
    for &b in entropy {
        r = (r << 8) | u128::from(b);
    }
    for i in (10..26).rev() {
        buf[i] = ULID_ALPHABET[(r % 32) as usize];
        r /= 32;
    }

    buf
}

/// Generates a single ULID string (26 uppercase ASCII characters).
#[cfg(test)]
#[must_use]
fn gen_ulid(rng: &mut impl Rng) -> String {
    let bytes = next_ulid_bytes(rng);
    // SAFETY: ULID_ALPHABET is pure ASCII; every byte in buf is from it.
    std::str::from_utf8(&bytes)
        .expect("ULID buffer contains only ASCII")
        .to_owned()
}

fn run_ulid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    if args.verbose {
        eprintln!("ULID  monotonic, 48-bit timestamp + 80-bit entropy, Crockford Base32");
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: write raw [u8; 26] stack buffer directly.
    for _ in 0..count {
        let buf = next_ulid_bytes(&mut rng);
        handle.write_all(&buf)?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    // Return ExitCode instead of calling process::exit so that all
    // destructors run — in particular Zeroizing<T> drop impls.
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.ulid {
        run_ulid(&args)
    } else if args.typeid || args.typeid_prefix.is_some() {
        run_typeid(&args)
    } else if args.uuid || args.uuid_version.is_some() {
        run_uuid(&args)
    } else {
        run_pass(&args)
    }
}

fn resolve_count(count: Option<usize>) -> Result<usize> {
    match count {
        None => Ok(1),
        Some(0) => bail!("--count must be at least 1."),
        Some(v) if v > MAX_COUNT => bail!("--count {v} exceeds the maximum of {MAX_COUNT}."),
        Some(v) => Ok(v),
    }
}

fn run_pass(args: &Args) -> Result<()> {
    let config = Config::try_from(args)?;

    if config.verbose {
        // Accurate entropy: phase-1 draws MIN_PER_SET chars from each required
        // set (smaller alphabet); phase-2 fills the rest from the full pool.
        // Reporting pool-only entropy overstates by up to ~10 bits.
        #[allow(clippy::cast_precision_loss)]
        let phase1: f64 = config
            .required_sets
            .iter()
            .map(|s| MIN_PER_SET as f64 * (s.len() as f64).log2())
            .sum();
        let remaining = config.length - config.required_sets.len() * MIN_PER_SET;
        #[allow(clippy::cast_precision_loss)]
        let phase2 = remaining as f64 * (config.pool.len() as f64).log2();
        let entropy_bits = phase1 + phase2;
        eprintln!(
            "Estimated entropy: ~{:.1} bits (pool: {}, length: {})",
            entropy_bits,
            config.pool.len(),
            config.length,
        );
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // NOTE: Zeroizing covers the in-process buffer only. Bytes passed to
    // write_all() enter kernel I/O buffers that are outside our control.
    for _ in 0..config.count {
        let bytes = pgen(config.length, &config.required_sets, &config.pool, &mut rng);
        handle.write_all(&bytes)?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;

    Ok(())
}

fn run_uuid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    let version = args.uuid_version.as_ref().unwrap_or(&UuidVersion::V4);

    if args.verbose {
        let name = match version {
            UuidVersion::V4 => "v4 (random, RFC 4122)",
            UuidVersion::V7 => "v7 (timestamp + random, RFC 9562)",
        };
        eprintln!("UUID version: {name}");
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: build each UUID into a stack buffer and write
    // directly — no per-UUID String allocation, matching run_typeid's approach.
    let mut buf = [0u8; 36];
    for _ in 0..count {
        let bytes = match version {
            UuidVersion::V4 => {
                let mut b: [u8; 16] = rng.random();
                b[6] = (b[6] & 0x0f) | 0x40; // version 4
                b[8] = (b[8] & 0x3f) | 0x80; // variant 0b10xxxxxx (RFC 4122)
                b
            }
            UuidVersion::V7 => next_v7_bytes(&mut rng),
        };
        format_uuid_bytes_buf(&bytes, &mut buf);
        handle.write_all(&buf)?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;

    Ok(())
}

fn run_typeid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    let prefix = args.typeid_prefix.as_deref().unwrap_or("");

    // Validate up-front: fail fast before locking stdout or printing verbose
    // output. gen_typeid re-validates on each call, which is negligible (≤63
    // ASCII chars) and keeps gen_typeid independently correct.
    validate_prefix(prefix)?;

    if args.verbose {
        if prefix.is_empty() {
            eprintln!("TypeID: no prefix (bare suffix)");
        } else {
            eprintln!("TypeID prefix: {prefix}");
        }
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: write prefix, separator, and raw base32 suffix
    // directly to the stdout handle — no per-ID String allocation.
    // gen_typeid is used by tests and validates independently; here we
    // skip it since prefix is already validated above.
    let prefix_bytes = prefix.as_bytes();
    for _ in 0..count {
        let suffix = encode_base32(&next_v7_bytes(&mut rng));
        if !prefix_bytes.is_empty() {
            handle.write_all(prefix_bytes)?;
            handle.write_all(b"_")?;
        }
        handle.write_all(&suffix)?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use std::collections::HashSet;
    use std::sync::Mutex;
    use zeroize::Zeroize;

    // All tests that read or write MONO_STATE must hold this guard for the
    // duration of the test. This serialises them against each other without
    // requiring an external crate, matching what `#[serial]` would provide.
    static V7_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that zeros `MONO_STATE` on drop, even when the test panics.
    /// Use in any test that injects synthetic timestamps into `MonotonicState`.
    struct MonotonicStateReset;

    impl Drop for MonotonicStateReset {
        fn drop(&mut self) {
            // Use `lock()` not `expect()`: the mutex may be poisoned if the
            // test panicked while holding it; silently skip in that case.
            if let Ok(mut s) = mono_state().lock() {
                s.last_ms = 0;
                s.counter = 0;
            }
        }
    }

    fn make_test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn config_rejects_empty_char_sets() {
        let args = Args {
            length: Some(16),
            no_upper: true,
            no_lower: true,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_zero() {
        let args = Args {
            length: Some(16),
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: Some(0),
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_over_max() {
        let args = Args {
            length: Some(16),
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: Some(MAX_COUNT + 1),
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_short_length() {
        let args = Args {
            length: Some(4),
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_length_over_max() {
        let args = Args {
            length: Some(MAX_LENGTH + 1),
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_accepts_max_sets_at_min_length() {
        let args = Args {
            length: Some(MIN_LENGTH),
            no_upper: false,
            no_lower: false,
            symbol: true,
            number: true,
            count: None,
            verbose: false,
            uuid: false,
            uuid_version: None,
            typeid: false,
            typeid_prefix: None,
            ulid: false,
        };
        assert!(Config::try_from(&args).is_ok());
    }

    // --- pgen ---

    #[test]
    fn pgen_returns_correct_length() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let result = pgen(16, sets, &pool, &mut make_test_rng());
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn pgen_satisfies_min_per_set() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = make_test_rng();
        for _ in 0..50 {
            let pwd = pgen(16, sets, &pool, &mut rng);
            let upper = pwd.iter().filter(|&&c| U_CHARS.contains(&c)).count();
            let lower = pwd.iter().filter(|&&c| L_CHARS.contains(&c)).count();
            let digit = pwd.iter().filter(|&&c| N_CHARS.contains(&c)).count();
            assert!(upper >= MIN_PER_SET, "not enough uppercase: {upper}");
            assert!(lower >= MIN_PER_SET, "not enough lowercase: {lower}");
            assert!(digit >= MIN_PER_SET, "not enough digits: {digit}");
        }
    }

    #[test]
    fn pgen_satisfies_all_four_sets_at_min_length() {
        // Stress test: 4 sets at minimum length — the scenario that previously
        // required ~15-30 rejection sampling attempts on average.
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, S_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = make_test_rng();
        for _ in 0..200 {
            let pwd = pgen(MIN_LENGTH, sets, &pool, &mut rng);
            assert_eq!(pwd.len(), MIN_LENGTH);
            let upper = pwd.iter().filter(|&&c| U_CHARS.contains(&c)).count();
            let lower = pwd.iter().filter(|&&c| L_CHARS.contains(&c)).count();
            let symbol = pwd.iter().filter(|&&c| S_CHARS.contains(&c)).count();
            let digit = pwd.iter().filter(|&&c| N_CHARS.contains(&c)).count();
            assert!(upper >= MIN_PER_SET, "not enough uppercase: {upper}");
            assert!(lower >= MIN_PER_SET, "not enough lowercase: {lower}");
            assert!(symbol >= MIN_PER_SET, "not enough symbols: {symbol}");
            assert!(digit >= MIN_PER_SET, "not enough digits: {digit}");
        }
    }

    #[test]
    fn pgen_all_chars_from_pool() {
        let sets: &[&[u8]] = &[U_CHARS, S_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = pgen(20, sets, &pool, &mut make_test_rng());
        for &c in pwd.iter() {
            assert!(pool.contains(&c), "unexpected byte '{c}' not in pool");
        }
    }

    #[test]
    fn pgen_all_chars_are_valid_ascii() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, S_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = pgen(20, sets, &pool, &mut make_test_rng());
        assert!(pwd.is_ascii(), "password contains non-ASCII bytes");
    }

    #[test]
    fn pgen_single_set_no_panic() {
        // Edge case: only one active set. Mandatory placement draws from that
        // set, fill draws from the same pool. Must not panic or produce
        // out-of-pool characters.
        let sets: &[&[u8]] = &[N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = pgen(10, sets, &pool, &mut make_test_rng());
        assert_eq!(pwd.len(), 10);
        for &c in pwd.iter() {
            assert!(N_CHARS.contains(&c), "unexpected byte outside digit set");
        }
    }

    #[test]
    fn pgen_uniqueness_smoke_test() {
        // Generate 100 passwords and assert all are unique.
        // Not cryptographic proof, but catches catastrophic RNG failures
        // (e.g., accidentally seeding with a constant).
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = rand::rng();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..100 {
            let pwd = pgen(20, sets, &pool, &mut rng);
            // Clone inner bytes for the HashSet — Zeroizing doesn't impl Hash.
            // The Zeroizing wrapper drops and zeroizes `pwd` at end of iteration.
            assert!(
                seen.insert((*pwd).clone()),
                "duplicate password detected — RNG failure"
            );
        }
        // Zeroize retained copies before the set is dropped.
        // HashSet doesn't support in-place mutation, so drain into
        // owned values and zeroize each one explicitly.
        for mut pwd in seen.drain() {
            pwd.zeroize();
        }
    }

    #[test]
    fn pgen_shuffle_distribution_smoke_test() {
        // Validation of Phase 1 order being randomized by Phase 3 (Shuffle).
        // Without shuffle, Phase 1 fills the buffer deterministically:
        // [set[0], set[0], ..., set[1], set[1], ...]
        //
        // Here we use length=MIN_LENGTH (10) with all 4 sets active.
        // Approx structure without shuffle: [U, U, L, L, S, S, N, N, R, R]
        // Index 0 would ALWAYS be Uppercase (part of set[0]) if shuffle failed.

        // We manually construct sets in a specific order to force U_CHARS first.
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, S_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = make_test_rng();

        let mut uppercase_at_start_count = 0;
        let trials = 100;

        for _ in 0..trials {
            // pgen takes sets slice directly, preserving order for Phase 1
            let pwd = pgen(MIN_LENGTH, sets, &pool, &mut rng);
            if U_CHARS.contains(&pwd[0]) {
                uppercase_at_start_count += 1;
            }
        }

        // With 4 equal-ish sets and length 10:
        // Probability(index 0 allows U) ≈ 25% (roughly 2.5 slots out of 10).
        // Probability(index 0 is U | NO SHUFFLE) = 100%.
        // We set a conservative upper bound of 90% to detect total lack of shuffle.
        assert!(
            uppercase_at_start_count < 90,
            "Shuffle failed? Index 0 was uppercase in {uppercase_at_start_count} of {trials} trials"
        );
    }

    // --- UUID ---

    /// Asserts standard 8-4-4-4-12 hex format, returns (`version_char`, `variant_char`).
    fn check_uuid_format(uuid: &str) -> (char, char) {
        let parts: Vec<&str> = uuid.split('-').collect();
        assert_eq!(
            parts.len(),
            5,
            "expected 5 hyphen-separated groups in '{uuid}'"
        );
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        for part in &parts {
            assert!(
                part.chars().all(|c| c.is_ascii_hexdigit()),
                "non-hex character in UUID '{uuid}'"
            );
        }
        let version = parts[2].chars().next().unwrap();
        let variant = parts[3].chars().next().unwrap();
        (version, variant)
    }

    // ── TypeID tests ──────────────────────────────────────────────────────────

    #[test]
    fn character_sets_are_disjoint() {
        // Unconditional version of the debug_assertions check in Config.
        // Catches accidental overlap if character set constants are modified.
        let mut pool: Vec<u8> = [U_CHARS, L_CHARS, S_CHARS, N_CHARS]
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        pool.sort_unstable();
        assert!(
            pool.windows(2).all(|w| w[0] != w[1]),
            "character sets contain overlapping bytes"
        );
    }

    // ── TypeID encoding: deterministic spec vectors ─────────────────────────

    #[test]
    fn typeid_encode_known_vectors() {
        // Vector 1: From official jetify-com/typeid README
        // `typeid decode prefix_01h2xcejqtf2nbrexx3vqjhp41`
        //  → uuid: 0188bac7-4afa-78aa-bc3b-bd1eef28d881
        let uuid1: [u8; 16] = [
            0x01, 0x88, 0xba, 0xc7, 0x4a, 0xfa, 0x78, 0xaa, 0xbc, 0x3b, 0xbd, 0x1e, 0xef, 0x28,
            0xd8, 0x81,
        ];
        let enc1 = encode_base32(&uuid1);
        assert_eq!(
            std::str::from_utf8(&enc1).unwrap(),
            "01h2xcejqtf2nbrexx3vqjhp41"
        );

        // Vector 2: All-zeros UUID → all-zeros suffix
        let uuid2: [u8; 16] = [0u8; 16];
        let enc2 = encode_base32(&uuid2);
        assert_eq!(
            std::str::from_utf8(&enc2).unwrap(),
            "00000000000000000000000000"
        );

        // Vector 3: Max UUID → max suffix (spec §Base32 Encoding)
        let uuid3: [u8; 16] = [0xFF; 16];
        let enc3 = encode_base32(&uuid3);
        assert_eq!(
            std::str::from_utf8(&enc3).unwrap(),
            "7zzzzzzzzzzzzzzzzzzzzzzzzz"
        );

        // Vector 4: Sequential bytes (from Go reference lib)
        // UUID 00010203-0405-0607-0809-0a0b0c0d0e0f
        //  → suffix: 00041061050r3gg28a1c60t3gf
        let uuid4: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let enc4 = encode_base32(&uuid4);
        assert_eq!(
            std::str::from_utf8(&enc4).unwrap(),
            "00041061050r3gg28a1c60t3gf"
        );
    }

    #[test]
    fn typeid_empty_prefix_no_separator() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = make_test_rng();
        let id = gen_typeid("", &mut rng).expect("empty prefix must be valid");
        assert_eq!(id.len(), 26, "bare typeid must be 26 chars, got: {id}");
        assert!(
            !id.contains('_'),
            "bare typeid must not contain underscore, got: {id}"
        );
    }

    #[test]
    fn typeid_format_prefix_separator_suffix() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = make_test_rng();
        let id = gen_typeid("user", &mut rng).expect("valid prefix");
        assert_eq!(
            id.len(),
            31,
            "typeid with 'user' prefix must be 31 chars, got: {id}"
        );
        assert!(
            id.starts_with("user_"),
            "must start with 'user_', got: {id}"
        );
        let suffix = &id[5..];
        assert_eq!(suffix.len(), 26, "suffix must be 26 chars");
    }

    #[test]
    fn typeid_suffix_chars_in_alphabet() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = make_test_rng();
        let id = gen_typeid("test", &mut rng).expect("valid prefix");
        let suffix = &id[5..]; // skip "test_"
        for ch in suffix.chars() {
            assert!(
                TYPEID_ALPHABET.contains(&(ch as u8)),
                "suffix char {ch:?} is not in the TypeID alphabet"
            );
        }
    }

    #[test]
    fn typeid_first_suffix_char_le_7() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = rand::rng();
        for _ in 0..50 {
            let id = gen_typeid("chk", &mut rng).expect("valid prefix");
            let first = id.chars().nth(4).expect("suffix must exist"); // "chk_X..."
            assert!(
                first <= '7',
                "first suffix char {first:?} exceeds '7' — overflow guard failed"
            );
        }
    }

    #[test]
    fn typeid_invalid_prefix_rejected() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = make_test_rng();
        let long = "a".repeat(64);
        let cases = ["PREFIX", "12345", "_prefix", "prefix_", long.as_str()];
        for bad in &cases {
            assert!(
                gen_typeid(bad, &mut rng).is_err(),
                "expected error for invalid prefix {bad:?}"
            );
        }
    }

    #[test]
    fn typeid_monotonic_suffix_ordering() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = rand::rng();
        let mut prev = String::new();
        for i in 0..50u32 {
            let id = gen_typeid("ord", &mut rng).expect("valid prefix");
            let suffix = id[4..].to_owned(); // skip "ord_"
            assert!(
                suffix > prev,
                "suffix [{i}] {suffix} is not > previous {prev}"
            );
            prev = suffix;
        }
    }

    #[test]
    fn uuid_v4_format_and_bits() {
        let mut rng = make_test_rng();
        for _ in 0..20 {
            let uuid = gen_uuid_v4(&mut rng);
            let (version, variant) = check_uuid_format(&uuid);
            assert_eq!(version, '4', "UUID v4 version nibble must be '4'");
            assert!(
                "89ab".contains(variant),
                "UUID variant nibble must be 8/9/a/b, got '{variant}'"
            );
        }
    }

    #[test]
    fn uuid_v7_format_and_bits() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = make_test_rng();
        for _ in 0..20 {
            let uuid = gen_uuid_v7(&mut rng);
            let (version, variant) = check_uuid_format(&uuid);
            assert_eq!(version, '7', "UUID v7 version nibble must be '7'");
            assert!(
                "89ab".contains(variant),
                "UUID variant nibble must be 8/9/a/b, got '{variant}'"
            );
        }
    }

    #[test]
    fn uuid_v7_timestamp_is_current() {
        let _v7 = V7_LOCK.lock().unwrap();
        // The first 12 hex chars encode a 48-bit Unix timestamp in ms.
        // Strip the hyphen (chars 0..8 + 9..13) and parse as hex.
        let mut rng = rand::rng();
        let uuid = gen_uuid_v7(&mut rng);
        let ts_hex = format!("{}{}", &uuid[..8], &uuid[9..13]);
        let ts_ms = u64::from_str_radix(&ts_hex, 16).expect("timestamp hex must parse");

        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();

        assert!(
            ts_ms <= now_ms && now_ms - ts_ms < 60_000,
            "UUID v7 timestamp {ts_ms} ms is not within 60 s of now ({now_ms} ms)"
        );
    }

    #[test]
    fn uuid_v7_monotonic() {
        let _v7 = V7_LOCK.lock().unwrap();
        // Generate 200 v7 UUIDs rapidly (likely within a single millisecond)
        // and assert strict lexicographic monotonicity across the batch.
        let mut rng = rand::rng();
        let uuids: Vec<String> = (0..200).map(|_| gen_uuid_v7(&mut rng)).collect();
        for w in uuids.windows(2) {
            assert!(
                w[0] < w[1],
                "UUID v7 monotonicity violated: '{}' >= '{}'",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn uuid_v7_monotonic_counter_increments() {
        let _v7 = V7_LOCK.lock().unwrap();
        // Generates 50 UUIDs in a tight loop (very likely within the same ms window)
        // and asserts each is strictly greater than the previous as a 128-bit integer.
        //
        // Proof path: if same-ms → counter increments → rand_a field increases →
        // u128 value increases. If ms advances → timestamp field increases → u128
        // value increases regardless of counter reset.
        let mut rng = rand::rng();
        let mut prev: u128 = 0;

        for i in 0..50u32 {
            let uuid = gen_uuid_v7(&mut rng);
            let hex: String = uuid.chars().filter(|&c| c != '-').collect();
            let value = u128::from_str_radix(&hex, 16).expect("UUID hex must parse as u128");

            assert!(
                value > prev,
                "UUID [{i}] {uuid} (0x{value:032x}) is not strictly greater \
                 than previous (0x{prev:032x})"
            );
            prev = value;
        }
    }

    #[test]
    fn uuid_v7_clock_rollback_clamped() {
        let _v7 = V7_LOCK.lock().unwrap();
        // Simulates a clock rollback by injecting a future timestamp directly into
        // MonotonicState, then asserts:
        //   (a) All generated UUIDs use the clamped (injected) timestamp, not the
        //       real clock — proving rollback does not go backward.
        //   (b) The 5 generated UUIDs are still strictly increasing.
        let mut rng = rand::rng();

        let future_ms = now_ms() + 5_000;
        {
            let mut state = mono_state().lock().expect("mutex poisoned");
            state.last_ms = future_ms;
            state.counter = 0;
        }

        // RAII: resets MONO_STATE to zero on exit, even if assertions panic.
        let _reset = MonotonicStateReset;

        let mut prev: u128 = 0;
        let mut uuids = Vec::with_capacity(5);
        for _ in 0..5 {
            uuids.push(gen_uuid_v7(&mut rng));
        }

        for (i, uuid) in uuids.iter().enumerate() {
            let ts_hex = format!("{}{}", &uuid[..8], &uuid[9..13]);
            let ts_ms = u64::from_str_radix(&ts_hex, 16).expect("timestamp hex must parse");
            assert_eq!(
                ts_ms, future_ms,
                "UUID [{i}] {uuid}: expected clamped timestamp {future_ms} ms, got {ts_ms} ms"
            );

            let hex: String = uuid.chars().filter(|&c| c != '-').collect();
            let value = u128::from_str_radix(&hex, 16).expect("UUID hex must parse as u128");
            assert!(
                value > prev,
                "UUID [{i}] {uuid} is not strictly greater than previous"
            );
            prev = value;
        }
    }

    #[test]
    fn uuid_v4_uniqueness() {
        let mut rng = rand::rng();
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..100 {
            assert!(
                seen.insert(gen_uuid_v4(&mut rng)),
                "duplicate UUID v4 — RNG failure"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // ULID tests
    // ---------------------------------------------------------------------------

    /// Shared serialisation lock for tests that touch `ULID_STATE`.
    static ULID_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard: zeros `ULID_STATE` on drop, even on test panic.
    struct UlidStateReset;
    impl Drop for UlidStateReset {
        fn drop(&mut self) {
            if let Ok(mut s) = ulid_state().lock() {
                s.last_ms = 0;
                s.entropy = [0u8; 10];
            }
        }
    }

    #[test]
    fn ulid_format_26_chars() {
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = make_test_rng();
        let id = gen_ulid(&mut rng);
        assert_eq!(id.len(), 26, "ULID must be 26 characters, got: {id}");
    }

    #[test]
    fn ulid_chars_in_alphabet() {
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = make_test_rng();
        for _ in 0..50 {
            let id = gen_ulid(&mut rng);
            for ch in id.chars() {
                assert!(
                    ULID_ALPHABET.contains(&(ch as u8)),
                    "ULID char {ch:?} not in Crockford alphabet: {id}"
                );
            }
        }
    }

    #[test]
    fn ulid_first_char_le_7() {
        // 48-bit timestamp fits in 10 × 5-bit groups.
        // The first group encodes bits 47..43 of the timestamp.
        // Current Unix time in ms is ~1.7 × 10^12, well below 2^48 (≈ 2.8 × 10^14),
        // so the top 5 bits are always 0b00001 = 1; first char is always '0' or '1'.
        // The spec guarantees first char ≤ '7' (top bit of 48-bit field must be 0).
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = rand::rng();
        for _ in 0..50 {
            let id = gen_ulid(&mut rng);
            let first = id.chars().next().unwrap();
            assert!(first <= '7', "ULID first char {first:?} exceeds '7': {id}");
        }
    }

    #[test]
    fn ulid_monotonic_ordering() {
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = rand::rng();
        let mut prev = String::new();
        for i in 0..200u32 {
            let id = gen_ulid(&mut rng);
            assert!(
                id > prev,
                "ULID monotonicity violated at {i}: {id} <= {prev}"
            );
            prev = id;
        }
    }

    #[test]
    fn ulid_clock_rollback_clamped() {
        // Inject a future timestamp, assert all IDs use it (clamped) and
        // remain strictly increasing — mirrors uuidv7_clock_rollback_clamped.
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = rand::rng();

        let future_ms = now_ms() + 5_000;
        {
            let mut s = ulid_state().lock().unwrap();
            s.last_ms = future_ms;
            s.entropy = [0u8; 10];
        }

        let mut prev = String::new();
        for i in 0..5u32 {
            let id = gen_ulid(&mut rng);
            // Timestamp is first 10 chars; decode it back to ms.
            let mut ts_ms: u64 = 0;
            for ch in id[..10].chars() {
                let idx = ULID_ALPHABET
                    .iter()
                    .position(|&b| b == ch as u8)
                    .expect("char not in alphabet") as u64;
                ts_ms = ts_ms * 32 + idx;
            }
            assert_eq!(
                ts_ms, future_ms,
                "ULID {i} timestamp {ts_ms} != clamped future_ms {future_ms}: {id}"
            );
            assert!(
                id > prev,
                "ULID {i} not strictly greater than previous: {id} <= {prev}"
            );
            prev = id;
        }
    }

    #[test]
    fn ulid_uniqueness_smoke() {
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = rand::rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(
                seen.insert(gen_ulid(&mut rng)),
                "duplicate ULID — RNG failure"
            );
        }
    }

    #[test]
    fn encode_ulid_known_vector() {
        // All-zero inputs must produce all '0' characters.
        let buf = encode_ulid(0, &[0u8; 10]);
        let s = std::str::from_utf8(&buf).unwrap();
        assert_eq!(s, "00000000000000000000000000");
    }
}
