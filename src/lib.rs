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

/// Error returned by [`now_ms`] when the system clock cannot be read.
///
/// Used by [`uuid`] (via [`uuid::UuidError::Clock`]) and [`ulid`] (via
/// [`ulid::UlidError::Clock`]) as the underlying clock-failure variant.
#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    /// The system clock is set to a time before the Unix epoch (1970-01-01).
    #[error("system clock is before the UNIX epoch")]
    BeforeEpoch,
    /// The millisecond timestamp no longer fits in a `u64` (~year 584 556 049).
    #[error("timestamp overflows u64 (~584 million years from epoch)")]
    Overflow,
}

/// Returns the current Unix timestamp in milliseconds.
///
/// Used by both [`uuid`] (`UUIDv7`) and [`ulid`] (ULID) to obtain the
/// millisecond epoch value for their monotonic state machines. A single
/// shared implementation prevents the two modules from diverging in their
/// time semantics (e.g., platform quirks, epoch handling).
pub(crate) fn now_ms() -> Result<u64, TimeError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TimeError::BeforeEpoch)?;

    u64::try_from(duration.as_millis()).map_err(|_| TimeError::Overflow)
}

// ── Error type re-exports ────────────────────────────────────────────────────

/// Re-exported so consumers have a single import path: `passid::KsuidError`.
pub use ksuid::KsuidError;
/// Re-exported so consumers have a single import path: `passid::NanoidError`.
pub use nanoid::NanoidError;
/// Re-exported so consumers have a single import path: `passid::PasswordError`.
pub use password::PasswordError;
/// Re-exported so consumers have a single import path: `passid::TypeIdError`.
pub use typeid::TypeIdError;
/// Re-exported so consumers have a single import path: `passid::UlidError`.
pub use ulid::UlidError;
/// Re-exported so consumers have a single import path: `passid::UuidError`.
pub use uuid::UuidError;
