//! Password generation — character sets, constraints, and the core generator.

use rand::{CryptoRng, seq::IndexedRandom, seq::SliceRandom};
use zeroize::Zeroizing;

// Visually unambiguous character sets, stored as ASCII byte slices.
// Excluded: I, L, O (uppercase) · i, l, o (lowercase) · 0, 1 (digits)
pub const U_CHARS: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ";
pub const L_CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz";
pub const S_CHARS: &[u8] = b"!@#$%^&*-_+=~()[]{};:,.?/";
pub const N_CHARS: &[u8] = b"23456789";

pub const MIN_LENGTH: usize = 10;
pub const MAX_LENGTH: usize = 4096;
pub const MAX_COUNT: usize = 10_000;
pub const MIN_PER_SET: usize = 2;

/// Error returned by [`gen_password`].
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// The requested `length` is less than `set_count * 2` — not enough room
    /// to place the mandatory minimum of 2 characters from each active set.
    #[error(
        "length {length} is too short: {set_count} set(s) each require at least \
             2 characters (minimum needed: {min_required})"
    )]
    LengthTooShort {
        length: usize,
        set_count: usize,
        min_required: usize,
    },
    /// No character set was enabled — the pool is empty.
    #[error("pool is empty — at least one character set must be enabled")]
    EmptyPool,
}

/// Generates a single password of **exactly** `length` ASCII bytes.
///
/// Note on distribution: "Uniform fill" draws uniformly from the *pool*.
/// Since character sets vary in size (e.g., 8 digits vs 25 symbols),
/// a symbol is more likely to appear in a fill slot than a digit. This
/// reflects the natural distribution of the pooled characters.
///
/// Returns a `Zeroizing<Vec<u8>>` (all ASCII). The wrapper guarantees
/// zeroization on drop — no manual cleanup required by the caller.
///
/// # Errors
/// Returns `Err` if:
/// - `length` is less than `required_sets.len() * MIN_PER_SET` (the minimum
///   needed to place at least `MIN_PER_SET` characters from each active set), or
/// - `pool` is empty (no character set is enabled).
///
/// # Panics
/// Does not panic in practice: `required_sets` must contain only non-empty
/// slices, which is guaranteed when using the public character-set constants
/// (`U_CHARS`, `L_CHARS`, `S_CHARS`, `N_CHARS`).
#[must_use = "password bytes must not be discarded — Zeroizing ensures cleanup on drop"]
pub fn gen_password(
    length: usize,
    required_sets: &[&'static [u8]],
    pool: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    let min_required = required_sets.len() * MIN_PER_SET;
    if length < min_required {
        return Err(PasswordError::LengthTooShort {
            length,
            set_count: required_sets.len(),
            min_required,
        });
    }
    if pool.is_empty() {
        return Err(PasswordError::EmptyPool);
    }

    let mut pwd: Vec<u8> = Vec::with_capacity(length);

    for set in required_sets {
        for _ in 0..MIN_PER_SET {
            pwd.push(
                *set.choose(rng)
                    .expect("invariant: required_sets contains only non-empty slices"),
            );
        }
    }

    let remaining = length - pwd.len();
    for _ in 0..remaining {
        pwd.push(
            *pool
                .choose(rng)
                .expect("invariant: pool is non-empty (guarded above)"),
        );
    }

    pwd.shuffle(rng);

    Ok(Zeroizing::new(pwd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use zeroize::Zeroize;

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

    #[test]
    fn passid_returns_correct_length() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let result = gen_password(16, sets, &pool, &mut rand::rng()).expect("valid params");
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn passid_satisfies_min_per_set() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = rand::rng();
        for _ in 0..50 {
            let pwd = gen_password(16, sets, &pool, &mut rng).expect("valid params");
            let upper = pwd.iter().filter(|&&c| U_CHARS.contains(&c)).count();
            let lower = pwd.iter().filter(|&&c| L_CHARS.contains(&c)).count();
            let digit = pwd.iter().filter(|&&c| N_CHARS.contains(&c)).count();
            assert!(upper >= MIN_PER_SET, "not enough uppercase: {upper}");
            assert!(lower >= MIN_PER_SET, "not enough lowercase: {lower}");
            assert!(digit >= MIN_PER_SET, "not enough digits: {digit}");
        }
    }

    #[test]
    fn passid_satisfies_all_four_sets_at_min_length() {
        // Stress test: 4 sets at minimum length — the scenario that previously
        // required ~15-30 rejection sampling attempts on average.
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, S_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = rand::rng();
        for _ in 0..200 {
            let pwd = gen_password(MIN_LENGTH, sets, &pool, &mut rng).expect("valid params");
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
    fn passid_all_chars_from_pool() {
        let sets: &[&[u8]] = &[U_CHARS, S_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = gen_password(20, sets, &pool, &mut rand::rng()).expect("valid params");
        for &c in pwd.iter() {
            assert!(pool.contains(&c), "unexpected byte '{c}' not in pool");
        }
    }

    #[test]
    fn passid_all_chars_are_valid_ascii() {
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, S_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = gen_password(20, sets, &pool, &mut rand::rng()).expect("valid params");
        assert!(pwd.is_ascii(), "password contains non-ASCII bytes");
    }

    #[test]
    fn passid_single_set_no_panic() {
        // Edge case: only one active set. Mandatory placement draws from that
        // set, fill draws from the same pool. Must not panic or produce
        // out-of-pool characters.
        let sets: &[&[u8]] = &[N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let pwd = gen_password(10, sets, &pool, &mut rand::rng()).expect("valid params");
        assert_eq!(pwd.len(), 10);
        for &c in pwd.iter() {
            assert!(N_CHARS.contains(&c), "unexpected byte outside digit set");
        }
    }

    #[test]
    fn gen_password_rejects_empty_pool() {
        // An empty pool with a non-zero length must return Err, not panic.
        let result = gen_password(10, &[], &[], &mut rand::rng());
        assert!(result.is_err(), "expected Err for empty pool, got Ok");
    }

    #[test]
    fn gen_password_rejects_length_below_set_minimum() {
        // 2 sets × MIN_PER_SET(2) = 4 mandatory chars minimum.
        // Passing length=3 must return Err, not panic.
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let result = gen_password(3, sets, &pool, &mut rand::rng());
        assert!(
            result.is_err(),
            "expected Err for length < sets.len() * MIN_PER_SET, got Ok"
        );
    }

    #[test]
    fn passid_uniqueness_smoke_test() {
        // Generate 100 passwords and assert all are unique.
        // Not cryptographic proof, but catches catastrophic RNG failures
        // (e.g., accidentally seeding with a constant).
        let sets: &[&[u8]] = &[U_CHARS, L_CHARS, N_CHARS];
        let pool: Vec<u8> = sets.iter().flat_map(|s| s.iter().copied()).collect();
        let mut rng = rand::rng();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for _ in 0..100 {
            let pwd = gen_password(20, sets, &pool, &mut rng).expect("valid params");
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
    fn passid_shuffle_distribution_smoke_test() {
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
        let mut rng = rand::rng();

        let mut uppercase_at_start_count = 0;
        let trials = 100;

        for _ in 0..trials {
            // gen_password takes sets slice directly, preserving order for Phase 1
            let pwd = gen_password(MIN_LENGTH, sets, &pool, &mut rng).expect("valid params");
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
