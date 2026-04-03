//! `NanoID` generation — URL-safe default and custom-alphabet variants.
//!
//! Spec: <https://github.com/ai/nanoid>

use anyhow::{Result, bail};
use rand::Rng;

// ── NanoID constants ─────────────────────────────────────────────────────────
//
// Default 64-character URL-safe alphabet — identical to upstream NanoID JS:
// `A–Z a–z 0–9 _ -` (scrambled order, not sorted)
pub const NANOID_DEFAULT_SIZE: usize = 21;
pub const NANOID_MIN_SIZE: usize = 1;
pub const NANOID_MAX_SIZE: usize = 4096;
const NANOID_ALPHABET_MIN: usize = 2;
const NANOID_ALPHABET_MAX: usize = 255;

const NANOID_URL_ALPHABET: &[u8; 64] =
    b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

// Compile-time guard: `nanoid_default` uses `b & 63` (equivalent to `b % 64`)
// which is bias-free only when the alphabet length is exactly 64. This assertion
// makes it impossible to silently break the bias guarantee by modifying the constant.
const _: () = assert!(
    NANOID_URL_ALPHABET.len() == 64,
    "NANOID_URL_ALPHABET must be exactly 64 bytes for bias-free b&63 indexing"
);

/// Validates a custom `NanoID` alphabet.
///
/// Rules:
/// - Length in [`NANOID_ALPHABET_MIN`, `NANOID_ALPHABET_MAX`]
/// - All bytes are printable ASCII (0x20–0x7E)
/// - No duplicate characters
///
/// # Errors
/// Returns `Err` with a descriptive message if any rule is violated.
pub fn validate_nanoid_alphabet(alphabet: &[u8]) -> Result<()> {
    let len = alphabet.len();
    if len < NANOID_ALPHABET_MIN {
        bail!("NanoID alphabet is too short ({len} char(s)); minimum is {NANOID_ALPHABET_MIN}.");
    }
    if len > NANOID_ALPHABET_MAX {
        bail!("NanoID alphabet is too long ({len} chars); maximum is {NANOID_ALPHABET_MAX}.");
    }
    for &b in alphabet {
        if !(0x20..=0x7E).contains(&b) {
            bail!("NanoID alphabet contains non-printable or non-ASCII byte 0x{b:02X}.");
        }
    }

    let mut sorted = alphabet.to_vec();
    sorted.sort_unstable();
    if let Some(w) = sorted.windows(2).find(|w| w[0] == w[1]) {
        bail!(
            "NanoID alphabet contains duplicate character {:?}.",
            char::from(w[0])
        );
    }
    Ok(())
}

/// Fast path — default 64-char URL-safe alphabet.
#[must_use]
pub fn nanoid_default(size: usize, rng: &mut impl Rng) -> String {
    let mut bytes = vec![0u8; size];
    rng.fill_bytes(&mut bytes);

    let mut id = String::with_capacity(size);
    for b in bytes {
        id.push(char::from(NANOID_URL_ALPHABET[usize::from(b & 63)]));
    }
    id
}

/// General path — custom alphabet with rejection sampling.
///
/// Mirrors upstream `NanoID` customRandom:
/// - mask = smallest 2^k − 1 where mask >= `alphabet.len()` − 1
/// - step = ceil(1.6 × mask × size / `alphabet.len()`)
/// - sample bytes, keep alphabet[byte & mask] when index is in-range
///
/// # Panics
/// Does not panic in practice: `alphabet.len()` is validated to be ≤ 255
/// before calling this function, so the `u32::try_from` cast always succeeds.
#[must_use]
pub fn nanoid_custom(alphabet: &[u8], size: usize, rng: &mut impl Rng) -> String {
    debug_assert!(!alphabet.is_empty(), "alphabet must be non-empty");
    debug_assert!(size > 0, "size must be > 0");

    let alpha_len = alphabet.len();
    let alpha_len_u32 = u32::try_from(alpha_len).expect("alphabet length <= 255 fits u32");
    let clz = ((alpha_len_u32 - 1) | 1).leading_zeros();
    let mask_u32 = (2u32 << (31 - clz)) - 1;
    let mask = usize::try_from(mask_u32).expect("u32 mask fits usize");

    // Use u64 intermediates to prevent theoretical usize overflow if the size
    // or alphabet limits are ever raised. At current limits (mask ≤ 255,
    // size ≤ 4096) the product is 8,355,840 — safe — but u64 makes it explicit.
    let step_u64 = (8u64 * mask as u64 * size as u64).div_ceil(5 * alpha_len as u64);
    let step = usize::try_from(step_u64)
        .expect("step fits usize: mask ≤ 255 and size ≤ 4096 bound result to ≤ 1,671,168")
        .max(1);
    let mut batch = vec![0u8; step];
    let mut id = String::with_capacity(size);

    while id.len() < size {
        rng.fill_bytes(&mut batch);
        for &b in batch.iter().rev() {
            let index = usize::from(b) & mask;
            if index < alpha_len {
                id.push(char::from(alphabet[index]));
                if id.len() >= size {
                    return id;
                }
            }
        }
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn make_test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    const NANOID_URL_CHARS: &str =
        "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

    #[test]
    fn nanoid_default_correct_length() {
        let mut rng = make_test_rng();
        for size in [1, 21, 36, 128] {
            let id = nanoid_default(size, &mut rng);
            assert_eq!(id.len(), size, "expected length {size}, got {}", id.len());
        }
    }

    #[test]
    fn nanoid_default_chars_in_url_alphabet() {
        let mut rng = make_test_rng();
        for _ in 0..50 {
            let id = nanoid_default(21, &mut rng);
            for ch in id.chars() {
                assert!(
                    NANOID_URL_CHARS.contains(ch),
                    "char {ch:?} is not in the URL-safe alphabet: {id}"
                );
            }
        }
    }

    #[test]
    fn nanoid_default_uniqueness_smoke() {
        let mut rng = rand::rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(
                seen.insert(nanoid_default(21, &mut rng)),
                "duplicate NanoID — RNG failure"
            );
        }
    }

    #[test]
    fn nanoid_custom_correct_length() {
        let alpha = b"abcdefghij";
        let mut rng = make_test_rng();
        for size in [1, 10, 21, 100] {
            let id = nanoid_custom(alpha, size, &mut rng);
            assert_eq!(id.len(), size, "expected length {size}, got {}", id.len());
        }
    }

    #[test]
    fn nanoid_custom_chars_only_from_alphabet() {
        let alpha = b"AEIOU12345";
        let mut rng = make_test_rng();
        for _ in 0..100 {
            let id = nanoid_custom(alpha, 30, &mut rng);
            for ch in id.chars() {
                assert!(
                    alpha.contains(&(ch as u8)),
                    "char {ch:?} not in custom alphabet: {id}"
                );
            }
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss)] // test-only: values ≤ 10_000, well within f64 mantissa
    fn nanoid_custom_no_bias_uniform_distribution() {
        let alpha = b"AB";
        let mut rng = rand::rng();
        let total = 10_000usize;
        let id = nanoid_custom(alpha, total, &mut rng);
        let a_count = id.chars().filter(|&c| c == 'A').count();
        let ratio = a_count as f64 / total as f64;
        assert!(
            (0.45..=0.55).contains(&ratio),
            "distribution bias detected: A appeared {:.1}% of the time (expected ~50%)",
            ratio * 100.0
        );
    }

    #[test]
    fn nanoid_custom_power_of_two_alphabet() {
        let alpha: Vec<u8> = (b'a'..=b'z').chain(b"012345".iter().copied()).collect();
        assert_eq!(alpha.len(), 32);
        let mut rng = make_test_rng();
        let id = nanoid_custom(&alpha, 50, &mut rng);
        assert_eq!(id.len(), 50);
        for ch in id.chars() {
            assert!(
                alpha.contains(&(ch as u8)),
                "char {ch:?} not in 32-char alphabet"
            );
        }
    }

    #[test]
    fn validate_nanoid_alphabet_rejects_empty() {
        assert!(validate_nanoid_alphabet(b"").is_err());
    }

    #[test]
    fn validate_nanoid_alphabet_rejects_single_char() {
        assert!(validate_nanoid_alphabet(b"a").is_err());
    }

    #[test]
    fn validate_nanoid_alphabet_rejects_duplicates() {
        assert!(validate_nanoid_alphabet(b"aab").is_err());
    }

    #[test]
    fn validate_nanoid_alphabet_rejects_non_printable() {
        assert!(validate_nanoid_alphabet(b"ab\x01").is_err());
    }

    #[test]
    fn validate_nanoid_alphabet_accepts_valid() {
        assert!(validate_nanoid_alphabet(b"abcdefghij").is_ok());
        assert!(validate_nanoid_alphabet(b"0123456789").is_ok());
        assert!(validate_nanoid_alphabet(b"!@#$%^&*()").is_ok());
    }

    #[test]
    fn nanoid_mask_correctness_non_power_of_two() {
        let alpha: Vec<u8> = (b'a'..b'a' + 30).collect();
        assert_eq!(alpha.len(), 30);
        let mut rng = rand::rng();
        for _ in 0..200 {
            let id = nanoid_custom(&alpha, 21, &mut rng);
            for ch in id.chars() {
                assert!(
                    alpha.contains(&(ch as u8)),
                    "out-of-alphabet char {ch:?} — mask computation wrong"
                );
            }
        }
    }

    #[test]
    fn nanoid_custom_max_valid_alphabet() {
        // Boundary test: the largest alphabet accepted by validate_nanoid_alphabet.
        // The validator constrains bytes to 0x20..=0x7E (printable ASCII), giving
        // 95 unique bytes — the practical maximum even though NANOID_ALPHABET_MAX=255.
        // This exercises the mask/step formula and rejection-sampling loop at the
        // widest valid alphabet without any out-of-bounds risk.
        let alpha: Vec<u8> = (0x20u8..=0x7E).collect();
        assert_eq!(alpha.len(), 95, "printable ASCII range must be 95 bytes");
        assert!(
            validate_nanoid_alphabet(&alpha).is_ok(),
            "95-char printable ASCII alphabet must be accepted"
        );
        let mut rng = make_test_rng();
        let id = nanoid_custom(&alpha, NANOID_DEFAULT_SIZE, &mut rng);
        assert_eq!(id.len(), NANOID_DEFAULT_SIZE);
        for ch in id.chars() {
            assert!(
                alpha.contains(&(ch as u8)),
                "char {ch:?} not in 95-char alphabet"
            );
        }
    }
}
