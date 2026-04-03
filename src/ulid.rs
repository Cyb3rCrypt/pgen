//! Monotonic ULID generation (Universally Unique Lexicographically Sortable Identifier).
//!
//! Spec: <https://github.com/ulid/spec>

use anyhow::{Result, bail};
use rand::{CryptoRng, RngExt};
use std::sync::{Mutex, OnceLock};

// ── ULID Crockford Base32 encoding ─────────────────────────────────────────
//
// Spec: https://github.com/ulid/spec
//
// Crockford base32 alphabet, UPPERCASE. Index 0 = '0', index 31 = 'Z'.
// Characters 'I', 'L', 'O', 'U' are absent (visually ambiguous).
const ULID_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

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
// for callers and consistent with the rest of passid.
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

/// Ripple-carry increment on the 80-bit (10-byte) entropy buffer.
/// Carry propagates from the LSB (byte 9) toward the MSB (byte 0) — standard
/// big-endian integer increment. The `rev()` iterator processes byte 9 first.
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
/// bounded to 500 ms (50 sleep cycles); returns an error if the clock does not
/// advance within that window.
///
/// # Errors
/// Returns `Err` if the system clock is before the Unix epoch, the timestamp
/// overflows `u64`, or 80-bit entropy is exhausted and the clock does not
/// advance within ~500 ms (50 sleep cycles).
pub fn next_ulid_bytes(rng: &mut impl CryptoRng) -> Result<[u8; 26]> {
    const MAX_SPIN_CYCLES: u32 = 50;

    let mut state = ulid_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("UlidState mutex poisoned"))?;
    let mut spins: u32 = 0;
    let mut cycles: u32 = 0;

    let (ms, entropy_snapshot) = loop {
        let ms = crate::now_ms()?.max(state.last_ms); // clamp: never go backward

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
            if cycles >= MAX_SPIN_CYCLES {
                bail!(
                    "ULID entropy exhausted: clock did not advance within \
                     {MAX_SPIN_CYCLES} sleep cycles (500 ms)"
                );
            }
        } else {
            std::hint::spin_loop();
        }
        state = ulid_state()
            .lock()
            .map_err(|_| anyhow::anyhow!("UlidState mutex poisoned"))?;
    };

    drop(state); // release ASAP; encoding is pure computation

    Ok(encode_ulid(ms, &entropy_snapshot))
}

/// Encodes a 48-bit timestamp and 80-bit entropy into a 26-byte
/// Crockford Base32 ASCII buffer (stack-allocated, zero heap).
fn encode_ulid(timestamp_ms: u64, entropy: &[u8; 10]) -> [u8; 26] {
    // ULID spec: timestamp field is 48 bits. Values ≥ 2^48 would silently
    // discard the high bits. Current epoch (~1.7 × 10^12 ms) is well below
    // 2^48 (~2.8 × 10^14 ms, year 10889), but the assertion catches clock
    // mocks or future callers passing raw u64 timestamps without bounds checks.
    debug_assert!(
        timestamp_ms < (1u64 << 48),
        "ULID timestamp {timestamp_ms} exceeds 48-bit field (max valid: year ~10889)"
    );

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

#[cfg(test)]
fn gen_ulid(rng: &mut impl CryptoRng) -> String {
    let bytes = next_ulid_bytes(rng).expect("ULID generation failed: monotonic clock stalled");
    // SAFETY: ULID_ALPHABET is pure ASCII; every byte in buf is from it.
    std::str::from_utf8(&bytes)
        .expect("ULID buffer contains only ASCII")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut rng = rand::rng();
        let id = gen_ulid(&mut rng);
        assert_eq!(id.len(), 26, "ULID must be 26 characters, got: {id}");
    }

    #[test]
    fn ulid_chars_in_alphabet() {
        let _guard = ULID_LOCK.lock().unwrap();
        let _reset = UlidStateReset;
        let mut rng = rand::rng();
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

        let future_ms = crate::now_ms().expect("current time must be available") + 5_000;
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

    #[test]
    fn ulid_concurrent_uniqueness() {
        // Spawn 8 threads, each generating 500 ULIDs. Collate all 4 000 IDs
        // and assert zero duplicates — verifying that ULID_STATE's Mutex
        // correctly serialises access under thread contention.
        //
        // Note: ULID_LOCK is NOT held here. The whole point is to exercise
        // concurrent access to the shared ULID_STATE mutex. Other ULID tests
        // (which DO hold ULID_LOCK) are serialised against this test by the
        // test runner's thread model — but this test itself must not hold the
        // lock or it would defeat the concurrency exercise.
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;

        // collect() is required here: all threads must be spawned before any is
        // joined. Fusing into a single iterator (clippy::needless_collect) would
        // spawn and join each thread sequentially, defeating the concurrency test.
        #[allow(clippy::needless_collect)]
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut rng = rand::rng();
                    (0..PER_THREAD)
                        .map(|_| {
                            next_ulid_bytes(&mut rng)
                                .expect("ULID generation failed in concurrent test")
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let all_ids: Vec<[u8; 26]> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread panicked"))
            .collect();

        assert_eq!(all_ids.len(), THREADS * PER_THREAD);

        // All IDs must be unique.
        let mut dedup = all_ids.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(
            dedup.len(),
            all_ids.len(),
            "duplicate ULIDs detected under concurrent generation"
        );
    }
}
