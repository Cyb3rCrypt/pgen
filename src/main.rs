#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pgen` — Fast random password generator.
use anyhow::{Result, bail};
use clap::Parser;
use rand::{Rng, seq::IndexedRandom, seq::SliceRandom};
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

#[derive(Parser)]
#[command(
    author,
    version,
    // clap 4's default template omits {author}; this restores it.
    help_template = "{name} {version}  —  {author} {about-section}\n{usage-heading} {usage}\n\n{all-args}{after-help}",
)]
#[allow(clippy::struct_excessive_bools)] // inherent to a flag-heavy CLI struct
struct Args {
    /// Password length (minimum: 10)
    #[arg(short, long, value_name = "LENGTH")]
    length: usize,

    /// Exclude uppercase letters
    #[arg(long)]
    no_upper: bool,

    /// Exclude lowercase letters
    #[arg(long)]
    no_lower: bool,

    /// Include symbols: !@#$%^&*-_+=~()[]{};:,.?/
    #[arg(short, long)]
    symbol: bool,

    /// Include digits 2-9 (visually unambiguous)
    #[arg(short, long)]
    number: bool,

    /// Number of passwords to generate (max: 10 000)
    #[arg(short, long, value_name = "COUNT")]
    count: Option<usize>,

    /// Show entropy estimate and pool size
    #[arg(short, long)]
    verbose: bool,
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
        if args.length < MIN_LENGTH {
            bail!(
                "--length {} is below the minimum of {MIN_LENGTH}.",
                args.length
            );
        }
        if args.length > MAX_LENGTH {
            bail!(
                "--length {} exceeds the maximum of {MAX_LENGTH}.",
                args.length
            );
        }
        let length = args.length;

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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::try_from(&Args::parse())?;

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
            length: 16,
            no_upper: true,
            no_lower: true,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_zero() {
        let args = Args {
            length: 16,
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: Some(0),
            verbose: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_over_max() {
        let args = Args {
            length: 16,
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: Some(MAX_COUNT + 1),
            verbose: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_short_length() {
        let args = Args {
            length: 4,
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_length_over_max() {
        let args = Args {
            length: MAX_LENGTH + 1,
            no_upper: false,
            no_lower: false,
            symbol: false,
            number: false,
            count: None,
            verbose: false,
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_accepts_max_sets_at_min_length() {
        let args = Args {
            length: MIN_LENGTH,
            no_upper: false,
            no_lower: false,
            symbol: true,
            number: true,
            count: None,
            verbose: false,
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
}
