//! KSUID (K-Sortable Unique ID) and `KsuidMs` generation.
//!
//! Spec: <https://github.com/segmentio/ksuid>
//! `KsuidMs` variant: <https://github.com/svix/rust-ksuid>

use rand::CryptoRng;

// ── KSUID constants ──────────────────────────────────────────────────────────
//
// Binary layout (20 bytes total):
//   Bytes  0– 3: 32-bit big-endian UTC timestamp, offset from KSUID epoch
//   Bytes  4–19: 128-bit cryptographically random payload  (standard)
//             4: ms_frac = (subsec_ms / 4) as u8           (KsuidMs only)
//   Bytes  5–19: 120-bit cryptographically random payload  (KsuidMs only)
//
// String form: 27-character base62 (digits → uppercase → lowercase),
// lexicographically sortable by timestamp.
//
// KSUID epoch: 2014-05-13T16:53:20Z = 1_400_000_000 Unix seconds.
// Timestamp overflows u32 around the year 2150.
const KSUID_EPOCH_OFFSET: u64 = 1_400_000_000;
const KSUID_TOTAL_BYTES: usize = 20;
pub const KSUID_STRING_LEN: usize = 27;

/// Base62 alphabet: digits → uppercase → lowercase.
/// Identical to Segment's canonical encoding order.
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// ── KSUID base62 codec ───────────────────────────────────────────────────────

/// Encodes a 20-byte KSUID binary into a 27-character base62 ASCII string.
///
/// Treats the 20 bytes as five 32-bit big-endian limbs and performs repeated
/// base-62 division to emit characters MSB-first. Zero heap allocation — output
/// is a stack-allocated `[u8; 27]`.
///
/// Bit-safety of the inner loop:
///   `rem` is always `0..=61` (a base62 digit) before the shift, so
///   `rem << 32` occupies bits 32..=37 and `*limb as u64` occupies bits 0..=31.
///   The regions are disjoint → `|` is equivalent to `+`, with no overflow risk.
#[must_use]
fn ksuid_encode(raw: &[u8; KSUID_TOTAL_BYTES]) -> [u8; KSUID_STRING_LEN] {
    let mut n = [0u32; 5]; // 5 × 32-bit big-endian limbs
    for (i, chunk) in raw.chunks(4).enumerate() {
        n[i] = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }

    let mut out = [0u8; KSUID_STRING_LEN];
    for pos in (0..KSUID_STRING_LEN).rev() {
        let mut rem: u64 = 0;
        for limb in &mut n {
            // Disjoint-bit OR: rem occupies high 32 bits, *limb the low 32.
            // Equivalent to rem * 2^32 + *limb but preferred by clippy::pedantic
            // in encoding paths.
            let cur = (rem << 32) | u64::from(*limb);
            // cur/62 ≤ (61·2^32 + 2^32−1)/62 = 2^32−1: always fits u32.
            *limb = u32::try_from(cur / 62).expect("quotient ≤ u32::MAX");
            rem = cur % 62;
        }
        // rem is 0..=61 after the modulo above: fits usize on all targets.
        out[pos] = BASE62[usize::try_from(rem).expect("rem is 0..=61")];
    }
    out
}

/// Decodes a 27-character base62 ASCII string back to 20 raw KSUID bytes.
///
/// Returns `Err` on invalid length or any non-base62 character.
#[cfg(test)]
fn ksuid_decode(s: &[u8]) -> anyhow::Result<[u8; KSUID_TOTAL_BYTES]> {
    if s.len() != KSUID_STRING_LEN {
        anyhow::bail!(
            "KSUID string must be exactly {KSUID_STRING_LEN} characters, got {}",
            s.len()
        );
    }
    let mut n = [0u32; 5];
    for &byte in s {
        let digit = BASE62
            .iter()
            .position(|&b| b == byte)
            .ok_or_else(|| anyhow::anyhow!("invalid base62 character: {:?}", byte as char))?;
        let mut carry = digit as u64;
        for limb in n.iter_mut().rev() {
            let val = u64::from(*limb) * 62 + carry;
            *limb = (val & 0xFFFF_FFFF) as u32;
            carry = val >> 32;
        }
        // A non-zero carry here means the accumulated value has overflowed
        // 160 bits (> 2^160 - 1). The maximum valid 27-char base62 value is
        // 62^27 - 1 ≈ 3.47 × 10^48, while 2^160 - 1 ≈ 1.46 × 10^48 — so
        // roughly the top 58% of the base62 input space is out-of-range.
        // Without this check those high bits are silently truncated.
        if carry != 0 {
            anyhow::bail!("KSUID string encodes a value that exceeds 2^160 (out of range)");
        }
    }
    let mut raw = [0u8; KSUID_TOTAL_BYTES];
    for (i, limb) in n.iter().enumerate() {
        raw[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_be_bytes());
    }
    Ok(raw)
}

/// Error returned by [`gen_ksuid_bytes`] and [`gen_ksuid_ms_bytes`].
#[derive(Debug, thiserror::Error)]
pub enum KsuidError {
    /// The system clock returned an error (e.g. time went backwards past the
    /// Unix epoch). Wraps [`std::time::SystemTimeError`] with full error chain.
    #[error("system clock error: {0}")]
    Clock(#[from] std::time::SystemTimeError),
    /// The system clock is set before the KSUID epoch (2014-05-13T16:53:20Z).
    #[error("system clock is before the KSUID epoch (2014-05-13)")]
    PreEpoch,
    /// The KSUID timestamp offset overflows `u32` (~year 2150).
    #[error("KSUID timestamp overflows u32 (~year 2150)")]
    EpochOverflow,
}

/// Returns `(ksuid_ts_secs, subsec_ms)` from a single `now()` call, where
/// `ksuid_ts_secs` is seconds since the KSUID epoch (2014-05-13T16:53:20Z)
/// and `subsec_ms` is the sub-second millisecond component (0..=999).
///
/// Both values are derived from the same instant, so there is no race window
/// across a second boundary.
///
/// # Errors
/// - System clock is set before the KSUID epoch (pre-2014)
/// - Resulting offset overflows `u32` (~year 2150)
fn ksuid_timestamp_parts() -> Result<(u32, u32), KsuidError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?; // SystemTimeError → KsuidError::Clock via #[from]
    let ksuid_ts = now
        .as_secs()
        .checked_sub(KSUID_EPOCH_OFFSET)
        .ok_or(KsuidError::PreEpoch)?;
    let ts = u32::try_from(ksuid_ts).map_err(|_| KsuidError::EpochOverflow)?;
    Ok((ts, now.subsec_millis()))
}

/// Returns seconds since the KSUID epoch.
/// Thin wrapper around [`ksuid_timestamp_parts`] for callers that only need seconds.
fn ksuid_timestamp_secs() -> Result<u32, KsuidError> {
    ksuid_timestamp_parts().map(|(ts, _)| ts)
}

/// Generates a standard KSUID: 4-byte timestamp + 16-byte random payload.
///
/// Output is a 27-char base62 ASCII stack buffer — zero heap allocation.
/// The payload is filled directly from the CSPRNG via `fill_bytes`.
///
/// # Errors
/// Returns `Err` if the system clock is set before the KSUID epoch
/// (2014-05-13) or if the timestamp offset overflows `u32` (~year 2150).
pub fn gen_ksuid_bytes(rng: &mut impl CryptoRng) -> Result<[u8; KSUID_STRING_LEN], KsuidError> {
    let ts = ksuid_timestamp_secs()?;
    let mut raw = [0u8; KSUID_TOTAL_BYTES];
    raw[..4].copy_from_slice(&ts.to_be_bytes());
    rng.fill_bytes(&mut raw[4..]); // 128-bit CSPRNG payload
    Ok(ksuid_encode(&raw))
}

/// Generates a `KsuidMs`: 4-byte timestamp + 1-byte sub-second fraction + 15-byte random payload.
///
/// Compatible with the Svix `KsuidMs` binary format (still 20 bytes / 27 chars).
///
/// Layout: `[ts:4][ms_frac:1][random:15]`
/// `ms_frac = (subsec_ms / 4) as u8` → 4ms resolution, range `0..=249`.
///
/// Sacrifices 1 payload byte for ~4ms sub-second precision while preserving
/// the standard 20-byte total and full Segment KSUID binary compatibility.
///
/// # Errors
/// Returns `Err` if the system clock is set before the KSUID epoch
/// (2014-05-13) or if the timestamp offset overflows `u32` (~year 2150).
///
/// # Panics
/// Does not panic in practice: `subsec_millis()` returns 0–999 ms, so
/// `subsec_ms / 4` is always 0–249 which fits `u8`.
pub fn gen_ksuid_ms_bytes(rng: &mut impl CryptoRng) -> Result<[u8; KSUID_STRING_LEN], KsuidError> {
    let (ts, subsec_ms) = ksuid_timestamp_parts()?;

    // 4ms resolution: 0..=999 ms → 0..=249 (fits u8 with no truncation risk).
    let ms_frac = u8::try_from(subsec_ms / 4).expect("subsec_ms/4 is 0..=249, fits u8");

    let mut raw = [0u8; KSUID_TOTAL_BYTES];
    raw[..4].copy_from_slice(&ts.to_be_bytes());
    raw[4] = ms_frac;
    rng.fill_bytes(&mut raw[5..]); // 120-bit CSPRNG payload
    Ok(ksuid_encode(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ksuid_encode_decode_roundtrip() {
        let mut rng = rand::rng();
        let buf = gen_ksuid_bytes(&mut rng).expect("gen ok");
        let raw = ksuid_decode(&buf).expect("decode ok");
        assert_eq!(
            ksuid_encode(&raw),
            buf,
            "encode→decode→encode must be identity"
        );
    }

    #[test]
    fn ksuid_string_len_and_charset() {
        let mut rng = rand::rng();
        for _ in 0..50 {
            let buf = gen_ksuid_bytes(&mut rng).expect("gen ok");
            assert_eq!(buf.len(), KSUID_STRING_LEN);
            for &b in &buf {
                assert!(
                    BASE62.contains(&b),
                    "non-base62 byte 0x{b:02X} in KSUID output"
                );
            }
        }
    }

    #[test]
    fn ksuid_ms_string_len_and_charset() {
        let mut rng = rand::rng();
        for _ in 0..50 {
            let buf = gen_ksuid_ms_bytes(&mut rng).expect("ms gen ok");
            assert_eq!(buf.len(), KSUID_STRING_LEN);
            for &b in &buf {
                assert!(
                    BASE62.contains(&b),
                    "non-base62 byte 0x{b:02X} in KsuidMs output"
                );
            }
        }
    }

    #[test]
    fn ksuid_known_zero_vector() {
        // All-zero raw bytes must encode to all-'0' base62 characters.
        let raw = [0u8; KSUID_TOTAL_BYTES];
        let encoded = ksuid_encode(&raw);
        assert!(
            encoded.iter().all(|&b| b == b'0'),
            "zero input must encode to all '0': {:?}",
            std::str::from_utf8(&encoded).unwrap()
        );
    }

    #[test]
    fn ksuid_decode_rejects_bad_length() {
        assert!(ksuid_decode(b"tooshort").is_err(), "short input must fail");
        assert!(
            ksuid_decode(b"toolongXXXXXXXXXXXXXXXXXXXXXXXXX").is_err(),
            "long input must fail"
        );
    }

    #[test]
    fn ksuid_decode_rejects_invalid_char() {
        // 27 chars with one non-base62 byte ('!')
        let bad = b"0uk1Hbc9dQ9pxyTqJ93IUrfhdG!";
        assert_eq!(bad.len(), KSUID_STRING_LEN, "test vector must be 27 bytes");
        assert!(ksuid_decode(bad).is_err(), "non-base62 char must fail");
    }

    #[test]
    fn ksuid_decode_rejects_out_of_range_value() {
        // The maximum 27-char base62 string "zzzzzzzzzzzzzzzzzzzzzzzzzz" encodes
        // 62^27 - 1 ≈ 3.47 × 10^48, which exceeds 2^160 - 1 ≈ 1.46 × 10^48.
        // Any such input must be rejected rather than silently truncated (B1 fix).
        let all_z = b"zzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(
            all_z.len(),
            KSUID_STRING_LEN,
            "test vector must be 27 bytes"
        );
        assert!(
            ksuid_decode(all_z).is_err(),
            "out-of-range base62 value must be rejected, not silently truncated"
        );
    }
}
