#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pgen` — Fast random password and UUID generator.
use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, seq::IndexedRandom, seq::SliceRandom};
use std::io::Write;
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

const MIN_LENGTH: usize = 10;
const MAX_LENGTH: usize = 4096;
const MAX_COUNT: usize = 10_000;
const MIN_PER_SET: usize = 2;

#[derive(Clone, ValueEnum)]
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
        required_unless_present_any = ["uuid", "uuid_version", "typeid", "typeid_prefix"],
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix"]
    )]
    length: Option<usize>,

    /// Exclude uppercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix"])]
    no_upper: bool,

    /// Exclude lowercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix"])]
    no_lower: bool,

    /// Include symbols: !@#$%^&*-_+=~()[]{};:,.?/
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix"])]
    symbol: bool,

    /// Include digits 2-9 (visually unambiguous)
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix"])]
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
}

struct Config {
    length: usize,
    count: usize,
    required_sets: Vec<&'static [u8]>,
    pool: Vec<u8>,
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

        let count = match args.count {
            None => 1,
            Some(0) => bail!("--count must be at least 1."),
            Some(v) if v > MAX_COUNT => bail!("--count {v} exceeds the maximum of {MAX_COUNT}."),
            Some(v) => v,
        };

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
            pool,
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
// Counter is 12 bits (0x000–0xFFF). On exhaustion within the same millisecond
// the function spin-waits until the system clock advances.
//
// Clock rollback: clamped to `last_ms`; counter keeps incrementing.
// This avoids panicking in production while preserving local monotonicity.

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
/// (lexicographically) than any previously returned value, provided the system
/// clock does not roll back by more than 4096 ticks within one millisecond.
fn next_v7_bytes(rng: &mut impl Rng) -> [u8; 16] {
    let mut state = mono_state().lock().expect("MonotonicState mutex poisoned");

    let (ms, counter) = loop {
        let ms = now_ms().max(state.last_ms); // clamp: never go backward

        if ms > state.last_ms {
            // Clock advanced — reset counter.
            state.last_ms = ms;
            state.counter = 0;
            break (ms, 0u16);
        }

        // Same millisecond (or clamped rollback).
        if state.counter < 0x0FFF {
            state.counter += 1;
            break (ms, state.counter);
        }

        // Counter exhausted — release lock and spin-wait for clock to advance.
        drop(state);
        std::hint::spin_loop();
        state = mono_state().lock().expect("MonotonicState mutex poisoned");
    };
    drop(state); // release ASAP; don't hold the lock while building the UUID bytes
    let ms_be = ms.to_be_bytes(); // [2..8] = lower 48 bits
    let rand_tail: [u8; 8] = rng.random(); // 64 random bits for bytes 8–15

    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&ms_be[2..8]); // 48-bit timestamp
    b[6] = 0x70 | ((counter >> 8) as u8); // ver=7, counter[11..8]
    b[7] = (counter & 0xFF) as u8; // counter[7..0]
    b[8] = 0x80 | (rand_tail[0] & 0x3F); // variant=10, 6 rand bits
    b[9..16].copy_from_slice(&rand_tail[1..8]); // 56 random bits

    b
}

/// Generates a UUID v7 (monotonic, RFC 9562 §6.2 Method 1).
///
/// Strict lexicographic ordering is guaranteed across all calls within the
/// same process, even within the same millisecond (12-bit counter).
#[must_use]
fn gen_uuid_v7(rng: &mut impl Rng) -> String {
    format_uuid_bytes(&next_v7_bytes(rng))
}

fn format_uuid_bytes(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

// ── TypeID encoding / validation / generation ────────────────────────────────

/// Encodes a 16-byte (128-bit) UUID into the 26-character `TypeID` base32 suffix.
///
/// Two zero bits are prepended, giving 130 bits split into 26 × 5-bit groups.
/// The first output character is always ≤ `'7'` (the top 2 bits are zero).
///
/// # Panics
/// Never — all arithmetic is on fixed-size arrays with known bounds.
#[must_use]
fn encode_base32(uuid: &[u8; 16]) -> [u8; 26] {
    let n = u128::from_be_bytes(*uuid);
    // Group i (0 = leftmost): extract 5 bits starting at bit position 125 - 5*i.
    // i=0  → shift 125 → top 5 bits of the 130-bit value (top 2 always zero → ≤ 7).
    // i=25 → shift 0   → bottom 5 bits of n.
    let mut out = [0u8; 26];
    for (i, out_byte) in out.iter_mut().enumerate() {
        let shift = 125u32 - u32::try_from(5 * i).unwrap();
        let index = usize::try_from((n >> shift) & 0x1F).unwrap();
        *out_byte = TYPEID_ALPHABET[index];
    }
    out
}

/// Validates a `TypeID` prefix against the spec (v0.3.0).
///
/// Returns `Ok(())` if the prefix is valid, or a descriptive `Err` otherwise.
fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.len() > 63 {
        bail!(
            "TypeID prefix is {} characters; maximum is 63.",
            prefix.len()
        );
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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.typeid || args.typeid_prefix.is_some() {
        run_typeid(&args)
    } else if args.uuid || args.uuid_version.is_some() {
        run_uuid(&args)
    } else {
        run_pass(&args)
    }
}

fn run_pass(args: &Args) -> Result<()> {
    let config = Config::try_from(args)?;

    if config.verbose {
        #[allow(clippy::cast_precision_loss)]
        let entropy_bits = (config.pool.len() as f64).log2() * config.length as f64;
        eprintln!(
            "Entropy: ~{:.1} bits (pool: {}, length: {})",
            entropy_bits,
            config.pool.len(),
            config.length,
        );
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let mut rng = rand::rng();

    for _ in 0..config.count {
        let bytes = pgen(config.length, &config.required_sets, &config.pool, &mut rng);
        handle.write_all(&bytes)?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;

    Ok(())
}

fn run_uuid(args: &Args) -> Result<()> {
    let count = match args.count {
        None => 1,
        Some(0) => bail!("--count must be at least 1."),
        Some(v) if v > MAX_COUNT => bail!("--count {v} exceeds the maximum of {MAX_COUNT}."),
        Some(v) => v,
    };

    let version = args.uuid_version.as_ref().unwrap_or(&UuidVersion::V4);

    if args.verbose {
        let name = match version {
            UuidVersion::V4 => "v4 (random, RFC 4122)",
            UuidVersion::V7 => "v7 (timestamp + random, RFC 9562)",
        };
        eprintln!("UUID version: {name}");
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let mut rng = rand::rng();

    for _ in 0..count {
        let uuid = match version {
            UuidVersion::V4 => gen_uuid_v4(&mut rng),
            UuidVersion::V7 => gen_uuid_v7(&mut rng),
        };
        handle.write_all(uuid.as_bytes())?;
        handle.write_all(b"\n")?;
    }
    handle.flush()?;

    Ok(())
}

fn run_typeid(args: &Args) -> Result<()> {
    let count = match args.count {
        None => 1,
        Some(0) => bail!("--count must be at least 1."),
        Some(v) if v > MAX_COUNT => bail!("--count {v} exceeds the maximum of {MAX_COUNT}."),
        Some(v) => v,
    };

    let prefix = args.typeid_prefix.as_deref().unwrap_or("");

    // Validate once up-front before generating any output.
    validate_prefix(prefix)?;

    if args.verbose {
        if prefix.is_empty() {
            eprintln!("TypeID: no prefix (bare suffix)");
        } else {
            eprintln!("TypeID prefix: {prefix}");
        }
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let mut rng = rand::rng();

    for _ in 0..count {
        // Prefix already validated; encode_base32 + next_v7_bytes are infallible.
        let uuid_bytes = next_v7_bytes(&mut rng);
        let suffix = encode_base32(&uuid_bytes);
        let suffix_str =
            std::str::from_utf8(&suffix).expect("base32 suffix is always valid ASCII/UTF-8");
        if !prefix.is_empty() {
            handle.write_all(prefix.as_bytes())?;
            handle.write_all(b"_")?;
        }
        handle.write_all(suffix_str.as_bytes())?;
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
    use zeroize::Zeroize;

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
    fn typeid_empty_prefix_no_separator() {
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
        // Simulates a clock rollback by injecting a future timestamp directly into
        // MonotonicState, then asserts:
        //   (a) All generated UUIDs use the clamped (injected) timestamp, not the
        //       real clock — proving rollback does not go backward.
        //   (b) The 5 generated UUIDs are still strictly increasing.
        //
        // NOTE: shares global MONO_STATE. If the test suite runs multi-threaded
        // (`cargo test` default), inject/restore can race with other v7 tests.
        // Run with `cargo test -- --test-threads=1` if flakiness is observed.
        let mut rng = rand::rng();

        let future_ms = now_ms() + 5_000;
        {
            let mut state = mono_state().lock().expect("mutex poisoned");
            state.last_ms = future_ms;
            state.counter = 0;
        }

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

        // Restore state so subsequent tests see a clean slate.
        {
            let mut state = mono_state().lock().expect("mutex poisoned");
            state.last_ms = 0;
            state.counter = 0;
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
}
