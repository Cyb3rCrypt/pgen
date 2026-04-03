//! UUID v4 and monotonic UUID v7 generation (RFC 4122 / RFC 9562).

use anyhow::{Result, bail};
use rand::{Rng, RngExt};
use std::sync::{Mutex, OnceLock};

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
// NOTE: Identical copy exists in ulid.rs — if you change this, change both.
fn now_ms() -> Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the UNIX epoch"))?;

    u64::try_from(duration.as_millis())
        .map_err(|_| anyhow::anyhow!("timestamp overflows u64 (~584 million years from epoch)"))
}

/// Core monotonic `UUIDv7` byte generator (RFC 9562 §6.2 Method 1).
///
/// For any two calls the returned 16-byte value is strictly greater
/// (lexicographically) than any previously returned value. Clock rollbacks are
/// clamped; counter exhaustion within the same millisecond causes the caller
/// to spin-wait (bounded to ~500 ms) until the clock advances, so monotonicity
/// is unconditional.
///
/// # Errors
/// Returns `Err` if the system clock does not advance within ~500 ms (50 sleep
/// cycles). This indicates a frozen or suspended clock and monotonic `UUIDv7`
/// generation cannot progress safely.
///
/// # Panics
/// Does not panic in practice: the counter is 12 bits so `counter >> 8` always
/// fits `u8`, and `counter & 0xFF` always fits `u8`.
pub fn next_v7_bytes(rng: &mut impl Rng) -> Result<[u8; 16]> {
    // 50 sleep cycles × (10 000 spins + 100 µs sleep each) ≈ 500 ms total.
    // A real clock must advance within this window; if not, the system is broken.
    const MAX_SPIN_CYCLES: u32 = 50;

    let mut state = mono_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("MonotonicState mutex poisoned"))?;
    let mut spins: u32 = 0;
    let mut cycles: u32 = 0;

    let (ms, counter) = loop {
        let ms = now_ms()?.max(state.last_ms); // clamp: never go backward

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
            if cycles >= MAX_SPIN_CYCLES {
                bail!(
                    "UUIDv7 counter exhausted: clock did not advance within \
                     {MAX_SPIN_CYCLES} sleep cycles (~500 ms)"
                );
            }
        }
        state = mono_state()
            .lock()
            .map_err(|_| anyhow::anyhow!("MonotonicState mutex poisoned"))?;
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

    Ok(b)
}

/// Generates a UUID v4 (randomly generated, RFC 4122).
const fn apply_uuid_v4_bits(b: &mut [u8; 16]) {
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 0b10xxxxxx (RFC 4122)
}

#[must_use]
pub fn gen_uuid_v4_bytes(rng: &mut impl Rng) -> [u8; 16] {
    let mut b: [u8; 16] = rng.random();
    apply_uuid_v4_bits(&mut b);
    b
}

/// Encodes 16 UUID bytes into the 36-byte `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// ASCII representation, writing into a caller-supplied stack buffer.
/// No allocation — intended for use in output hot-paths.
pub fn format_uuid_bytes_buf(b: &[u8; 16], out: &mut [u8; 36]) {
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

// ── Test helpers & infrastructure ───────────────────────────────────────────

/// Returns the UUID as an owned `String`. Used by tests only.
/// Output hot-paths use `format_uuid_bytes_buf` instead.
#[cfg(test)]
fn format_uuid_bytes(b: &[u8; 16]) -> String {
    let mut buf = [0u8; 36];
    format_uuid_bytes_buf(b, &mut buf);
    // buf contains only ASCII hex digits and hyphens — always valid UTF-8.
    std::str::from_utf8(&buf)
        .expect("UUID buffer contains only ASCII hex digits and hyphens")
        .to_owned()
}

#[cfg(test)]
fn gen_uuid_v4(rng: &mut impl Rng) -> String {
    format_uuid_bytes(&gen_uuid_v4_bytes(rng))
}

#[cfg(test)]
fn gen_uuid_v7(rng: &mut impl Rng) -> String {
    format_uuid_bytes(&next_v7_bytes(rng).expect("v7 generation failed: monotonic clock stalled"))
}

/// Serialisation lock for tests that touch `MONO_STATE`.
/// Also imported by typeid tests — both call `next_v7_bytes` which mutates `MONO_STATE`.
#[cfg(test)]
pub(crate) static V7_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};
    use std::collections::HashSet;

    fn make_test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

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

        let now_ms_val = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();

        assert!(
            ts_ms <= now_ms_val && now_ms_val - ts_ms < 60_000,
            "UUID v7 timestamp {ts_ms} ms is not within 60 s of now ({now_ms_val} ms)"
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

        let future_ms = now_ms().expect("current time must be available") + 5_000;
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

    #[test]
    fn uuid_v7_concurrent_uniqueness() {
        // Spawn 8 threads, each generating 500 UUIDv7s. Collate all 4 000 IDs
        // and assert zero duplicates — verifying that MONO_STATE's Mutex
        // correctly serialises counter increments under thread contention.
        //
        // V7_LOCK is NOT held here: the test intentionally exercises concurrent
        // access to MONO_STATE. Other tests that mutate MONO_STATE hold V7_LOCK
        // to serialise against each other, but this test is the contention test.
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
                            next_v7_bytes(&mut rng)
                                .expect("UUIDv7 generation failed in concurrent test")
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let all_ids: Vec<[u8; 16]> = handles
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
            "duplicate UUIDv7s detected under concurrent generation"
        );
    }
}
