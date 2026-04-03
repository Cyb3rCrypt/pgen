//! `TypeID` encoding, prefix validation, and generation (spec v0.3.0).
//!
//! Spec: <https://github.com/jetify-com/typeid>

use anyhow::{Result, bail};
use rand::CryptoRng;

// ── TypeID base32 encoding ──────────────────────────────────────────────────
//
// Spec: https://github.com/jetify-com/typeid (v0.3.0)
//
// Crockford base32 alphabet, lowercase. Index 0 = '0', index 31 = 'z'.
// Characters 'i', 'l', 'o', 'u' are absent (visually ambiguous).
pub(crate) const TYPEID_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Encodes a 16-byte (128-bit) UUID into the 26-character `TypeID` base32 suffix.
///
/// Two zero bits are prepended, giving 130 bits split into 26 × 5-bit groups.
/// The first output character is always ≤ `'7'` (the top 2 bits are zero).
///
/// # Panics
/// Does not panic in practice: the loop index `i` is always 0–25, so
/// `5 * i` is always ≤ 125 and fits `u32`.
#[must_use]
pub fn encode_base32(uuid: &[u8; 16]) -> [u8; 26] {
    let n = u128::from_be_bytes(*uuid);
    // Group i (0 = leftmost): extract 5 bits starting at bit position 125 - 5*i.
    // i=0  → shift 125 → top 5 bits of the 130-bit value (top 2 always zero → ≤ 7).
    // i=25 → shift 0   → bottom 5 bits of n.
    let mut out = [0u8; 26];
    for (i, out_byte) in out.iter_mut().enumerate() {
        let shift = 125u32 - u32::try_from(5 * i).expect("i ≤ 25, so 5*i ≤ 125, fits in u32");
        let index = usize::try_from((n >> shift) & 0x1F)
            .expect("masked 5-bit value 0..=31 always fits usize");
        *out_byte = TYPEID_ALPHABET[index];
    }
    out
}

/// Validates a `TypeID` prefix against the spec (v0.3.0).
///
/// Returns `Ok(())` if the prefix is valid, or a descriptive `Err` otherwise.
///
/// # Errors
/// Returns `Err` if the prefix is non-ASCII, exceeds 63 bytes, does not
/// start and end with a lowercase letter, or contains characters other
/// than `[a-z_]`.
pub fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Ok(());
    }
    if !prefix.is_ascii() {
        bail!("TypeID prefix {prefix:?} must be ASCII.");
    }
    let byte_len = prefix.len();
    if byte_len > 63 {
        bail!("TypeID prefix is {byte_len} bytes; maximum is 63.");
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

/// Generates a `TypeID` string with the given prefix and a fresh monotonic `UUIDv7` suffix.
///
/// Output format: `{prefix}_{suffix}` where suffix is a 26-character Crockford base32
/// encoded `UUIDv7`. When `prefix` is empty the bare 26-character suffix is returned
/// with no underscore separator.
///
/// This is the ergonomic entry point for library consumers. It validates the prefix,
/// generates a cryptographically secure monotonic `UUIDv7`, and formats the result.
/// `run_typeid` in the CLI bypasses this function to avoid per-ID heap allocation.
///
/// # Errors
/// Returns `Err` if `prefix` fails validation (see [`validate_prefix`]).
///
/// # Panics
/// Does not panic in practice: `encode_base32` output is always valid ASCII/UTF-8
/// by construction of `TYPEID_ALPHABET`.
pub fn typeid_string(prefix: &str, rng: &mut impl CryptoRng) -> Result<String> {
    validate_prefix(prefix)?;
    let uuid_bytes = crate::uuid::next_v7_bytes(rng)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uuid::V7_LOCK;

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
        let mut rng = rand::rng();
        let id = typeid_string("", &mut rng).expect("empty prefix must be valid");
        assert_eq!(id.len(), 26, "bare typeid must be 26 chars, got: {id}");
        assert!(
            !id.contains('_'),
            "bare typeid must not contain underscore, got: {id}"
        );
    }

    #[test]
    fn typeid_format_prefix_separator_suffix() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = rand::rng();
        let id = typeid_string("user", &mut rng).expect("valid prefix");
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
        let mut rng = rand::rng();
        let id = typeid_string("test", &mut rng).expect("valid prefix");
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
            let id = typeid_string("chk", &mut rng).expect("valid prefix");
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
        let mut rng = rand::rng();
        let long = "a".repeat(64);
        let cases = ["PREFIX", "12345", "_prefix", "prefix_", long.as_str()];
        for bad in &cases {
            assert!(
                typeid_string(bad, &mut rng).is_err(),
                "expected error for invalid prefix {bad:?}"
            );
        }
    }

    #[test]
    fn typeid_prefix_length_boundaries() {
        // Exactly 63 lowercase letters — the maximum valid length per spec.
        let at_limit = "a".repeat(63);
        assert!(
            validate_prefix(&at_limit).is_ok(),
            "63-char prefix must be valid (at the spec limit)"
        );

        // 64 chars — one over the limit; must be rejected.
        let over_limit = "a".repeat(64);
        assert!(
            validate_prefix(&over_limit).is_err(),
            "64-char prefix must be rejected (exceeds spec limit of 63)"
        );
    }

    #[test]
    fn typeid_prefix_internal_underscores_valid() {
        // Prefixes may contain underscores as long as they start and end with
        // a lowercase letter. Verify a variety of valid internal underscore patterns.
        for valid in &["a_b", "user_account", "foo_bar_baz", "a_b_c_d"] {
            assert!(
                validate_prefix(valid).is_ok(),
                "prefix with internal underscores {valid:?} must be valid"
            );
        }
    }

    #[test]
    fn typeid_monotonic_suffix_ordering() {
        let _v7 = V7_LOCK.lock().unwrap();
        let mut rng = rand::rng();
        let mut prev = String::new();
        for i in 0..50u32 {
            let id = typeid_string("ord", &mut rng).expect("valid prefix");
            let suffix = id[4..].to_owned(); // skip "ord_"
            assert!(
                suffix > prev,
                "suffix [{i}] {suffix} is not > previous {prev}"
            );
            prev = suffix;
        }
    }
}
