#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pgen` — Fast random password and UUID generator.
use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use rand::{Rng, RngExt, seq::IndexedRandom, seq::SliceRandom};
use std::io::Write;
use zeroize::Zeroizing;

// Visually unambiguous character sets, stored as ASCII byte slices.
// Excluded: I, L, O (uppercase) · i, l, o (lowercase) · 0, 1 (digits)
const U_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
const L_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
const S_CHARS: &[u8] = b"!@#$%^&*-_+=~()[]{};:,.?/";
const N_CHARS: &[u8] = b"23456789";

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
        required_unless_present_any = ["uuid", "uuid_version"],
        conflicts_with_all = ["uuid", "uuid_version"]
    )]
    length: Option<usize>,

    /// Exclude uppercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version"])]
    no_upper: bool,

    /// Exclude lowercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version"])]
    no_lower: bool,

    /// Include symbols: !@#$%^&*-_+=~()[]{};:,.?/
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version"])]
    symbol: bool,

    /// Include digits 2-9 (visually unambiguous)
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version"])]
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

/// Generates a UUID v7 (48-bit Unix ms timestamp + random, RFC 9562).
///
/// Layout:
/// - Bytes 0–5 : 48-bit big-endian millisecond timestamp
/// - Byte  6   : version nibble (7) | 4 random bits
/// - Byte  7   : 8 random bits
/// - Byte  8   : variant (0b10) | 6 random bits
/// - Bytes 9–15: 56 random bits
#[must_use]
fn gen_uuid_v7(rng: &mut impl Rng) -> String {
    let ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before the UNIX epoch")
            .as_millis(),
    )
    .expect("timestamp overflows u64 (~584 million years from epoch)");

    let ms_be = ms.to_be_bytes(); // 8 bytes big-endian; [2..8] = lower 48 bits
    let rand_tail: [u8; 10] = rng.random();
    let mut b = [0u8; 16];
    b[0..6].copy_from_slice(&ms_be[2..8]);
    b[6..].copy_from_slice(&rand_tail);
    b[6] = (b[6] & 0x0f) | 0x70; // version 7
    b[8] = (b[8] & 0x3f) | 0x80; // variant 0b10xxxxxx (RFC 4122)
    format_uuid_bytes(&b)
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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.uuid || args.uuid_version.is_some() {
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
        handle.flush()?;
    }

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
        handle.flush()?;
    }

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
