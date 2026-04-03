#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

pub mod ksuid;
pub mod nanoid;
pub mod password;
pub mod typeid;
pub mod ulid;
pub mod uuid;

// ── Shared time utility ──────────────────────────────────────────────────────

/// Returns the current Unix timestamp in milliseconds.
///
/// Used by both [`uuid`] (`UUIDv7`) and [`ulid`] (ULID) to obtain the
/// millisecond epoch value for their monotonic state machines. A single
/// shared implementation prevents the two modules from diverging in their
/// time semantics (e.g., platform quirks, epoch handling).
pub(crate) fn now_ms() -> anyhow::Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before the UNIX epoch"))?;

    u64::try_from(duration.as_millis())
        .map_err(|_| anyhow::anyhow!("timestamp overflows u64 (~584 million years from epoch)"))
}
