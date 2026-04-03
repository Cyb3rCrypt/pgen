#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `passid` — Fast, secure, secret-safe CLI for passwords + modern monotonic IDs.

use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use std::io::Write;
use std::process::ExitCode;
use zeroize::Zeroizing;

use passid::ksuid::{gen_ksuid_bytes, gen_ksuid_ms_bytes};
use passid::nanoid::{
    NANOID_DEFAULT_SIZE, NANOID_MAX_SIZE, NANOID_MIN_SIZE, nanoid_custom, nanoid_default,
    validate_nanoid_alphabet,
};
use passid::password::{
    L_CHARS, MAX_COUNT, MAX_LENGTH, MIN_LENGTH, MIN_PER_SET, N_CHARS, S_CHARS, U_CHARS,
    gen_password,
};
use passid::typeid::{encode_base32, validate_prefix};
use passid::ulid::next_ulid_bytes;
use passid::uuid::{format_uuid_bytes_buf, gen_uuid_v4_bytes, next_v7_bytes};

#[derive(Clone, ValueEnum)]
enum UuidVersion {
    /// Randomly generated (RFC 4122)
    V4,
    /// Unix-timestamp + random, lexicographically sortable (RFC 9562)
    V7,
}

#[derive(Parser)]
#[cfg_attr(test, derive(Default))]
#[command(
    author,
    version,
    about,
    // clap 4's default template omits {author}; this restores it.
    help_template = "{name} {version}  —  {author} {about-section}\n{usage-heading} {usage}\n\n{all-args}{after-help}",
    after_help = "Password distribution note: fill characters are sampled uniformly from the pooled alphabet, so larger enabled sets (for example symbols) appear more often than smaller sets (for example digits).",
)]
#[allow(clippy::struct_excessive_bools)] // inherent to a flag-heavy CLI struct
struct Args {
    /// Password length (minimum: 10)
    #[arg(
        short,
        long,
        value_name = "LENGTH",
        required_unless_present_any = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"],
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"]
    )]
    length: Option<usize>,

    /// Exclude uppercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"])]
    no_upper: bool,

    /// Exclude lowercase letters
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"])]
    no_lower: bool,

    /// Include symbols: !@#$%^&*-_+=~()[]{};:,.?/
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"])]
    symbol: bool,

    /// Include digits 2-9 (visually unambiguous)
    #[arg(short, long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"])]
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

    /// Generate a `TypeID` (`UUIDv7` encoded as base32 with a type prefix)
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "ksuid", "ksuid_ms"])]
    typeid: bool,

    /// Type prefix for the `TypeID` (max 63 lowercase [a-z_] chars); implies --typeid
    #[arg(long, value_name = "PREFIX", conflicts_with_all = ["uuid", "uuid_version", "ksuid", "ksuid_ms"])]
    typeid_prefix: Option<String>,

    /// Generate a ULID (monotonic, 48-bit timestamp + 80-bit entropy, Crockford Base32)
    #[arg(long, conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "length", "nanoid", "nanoid_size", "nanoid_alphabet", "ksuid", "ksuid_ms"])]
    ulid: bool,

    /// Generate a `NanoID` (URL-safe, cryptographically random)
    #[arg(
        long,
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "length", "ksuid", "ksuid_ms"]
    )]
    nanoid: bool,

    /// `NanoID` character count [default: 21]
    #[arg(
        long,
        value_name = "SIZE",
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "ksuid", "ksuid_ms"]
    )]
    nanoid_size: Option<usize>,

    /// Custom alphabet for `NanoID` (2–255 unique printable ASCII chars)
    #[arg(
        long,
        value_name = "ALPHABET",
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid", "ksuid", "ksuid_ms"]
    )]
    nanoid_alphabet: Option<String>,

    /// Generate a KSUID (K-Sortable Unique ID, 27-char base62, Segment-compatible)
    #[arg(
        long,
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid",
                              "nanoid", "nanoid_size", "nanoid_alphabet", "length", "ksuid_ms"]
    )]
    ksuid: bool,

    /// Generate a `KsuidMs` (4ms sub-second precision, 15-byte payload, Svix-compatible)
    #[arg(
        long,
        conflicts_with_all = ["uuid", "uuid_version", "typeid", "typeid_prefix", "ulid",
                              "nanoid", "nanoid_size", "nanoid_alphabet", "length", "ksuid"]
    )]
    ksuid_ms: bool,
}

struct Config {
    length: usize,
    count: usize,
    required_sets: Vec<&'static [u8]>,
    // Zeroizing ensures pool bytes are cleared on drop. The pool is not
    // secret, but wiping it is consistent with the tool's security posture.
    pool: Zeroizing<Vec<u8>>,
    verbose: bool,
}

impl TryFrom<&Args> for Config {
    type Error = anyhow::Error;

    fn try_from(args: &Args) -> Result<Self> {
        let length = args.length.ok_or_else(|| {
            anyhow::anyhow!(
                "--length is required in password mode; this should be enforced by clap"
            )
        })?;

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

        let count = resolve_count(args.count)?;

        let pool: Vec<u8> = required_sets
            .iter()
            .flat_map(|set| set.iter().copied())
            .collect();

        Ok(Self {
            length,
            count,
            required_sets,
            pool: Zeroizing::new(pool),
            verbose: args.verbose,
        })
    }
}

fn resolve_count(count: Option<usize>) -> Result<usize> {
    match count {
        None => Ok(1),
        Some(0) => bail!("--count must be at least 1."),
        Some(v) if v > MAX_COUNT => bail!("--count {v} exceeds the maximum of {MAX_COUNT}."),
        Some(v) => Ok(v),
    }
}

fn run_ksuid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;
    let ms_mode = args.ksuid_ms;

    if args.verbose {
        if ms_mode {
            eprintln!("KSUID-Ms | 32-bit ts (4ms precision) + 120-bit random | base62 | 27 chars");
        } else {
            eprintln!("KSUID    | 32-bit ts (1s precision)  + 128-bit random | base62 | 27 chars");
        }
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    for _ in 0..count {
        let buf = if ms_mode {
            gen_ksuid_ms_bytes(&mut rng)?
        } else {
            gen_ksuid_bytes(&mut rng)?
        };
        if let Err(e) = handle.write_all(&buf) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }
    Ok(())
}

fn run_nanoid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    let size = match args.nanoid_size {
        Some(v) if v < NANOID_MIN_SIZE => {
            bail!("--nanoid-size {v} is below the minimum of {NANOID_MIN_SIZE}.")
        }
        Some(v) if v > NANOID_MAX_SIZE => {
            bail!("--nanoid-size {v} exceeds the maximum of {NANOID_MAX_SIZE}.")
        }
        Some(v) => v,
        None => NANOID_DEFAULT_SIZE,
    };

    let custom_alphabet = if let Some(ref s) = args.nanoid_alphabet {
        let bytes = s.as_bytes().to_vec();
        validate_nanoid_alphabet(&bytes)?;
        Some(bytes)
    } else {
        None
    };

    if args.verbose {
        match &custom_alphabet {
            Some(alphabet) => eprintln!(
                "NanoID  size={size}  alphabet={} ({} chars, custom)",
                String::from_utf8_lossy(alphabet),
                alphabet.len(),
            ),
            None => eprintln!("NanoID  size={size}  alphabet=URL-safe (64 chars, default)"),
        }
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    for _ in 0..count {
        let id = match &custom_alphabet {
            Some(alphabet) => nanoid_custom(alphabet, size, &mut rng),
            None => nanoid_default(size, &mut rng),
        };
        if let Err(e) = handle.write_all(id.as_bytes()) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }

    Ok(())
}

fn run_ulid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    if args.verbose {
        eprintln!("ULID  monotonic, 48-bit timestamp + 80-bit entropy, Crockford Base32");
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: write raw [u8; 26] stack buffer directly.
    for _ in 0..count {
        let buf = next_ulid_bytes(&mut rng)?;
        if let Err(e) = handle.write_all(&buf) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }
    Ok(())
}

fn run_pass(args: &Args) -> Result<()> {
    let config = Config::try_from(args)?;

    if config.verbose {
        // Entropy estimate: phase-1 draws MIN_PER_SET chars from each required
        // set (smaller alphabet); phase-2 fills the rest from the full pool.
        // The final shuffle adds permutation entropy not captured here, so this
        // is a slight underestimate — erring on the conservative (safe) side.
        #[allow(clippy::cast_precision_loss)]
        let phase1: f64 = config
            .required_sets
            .iter()
            .map(|s| MIN_PER_SET as f64 * (s.len() as f64).log2())
            .sum();
        let remaining = config.length - config.required_sets.len() * MIN_PER_SET;
        #[allow(clippy::cast_precision_loss)]
        let phase2 = remaining as f64 * (config.pool.len() as f64).log2();
        let entropy_bits = phase1 + phase2;
        eprintln!(
            "Estimated entropy: ~{:.1} bits (pool: {}, length: {})",
            entropy_bits,
            config.pool.len(),
            config.length,
        );
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // NOTE: Zeroizing covers the in-process buffer only. Bytes passed to
    // write_all() enter kernel I/O buffers that are outside our control.
    for _ in 0..config.count {
        let bytes = gen_password(config.length, &config.required_sets, &config.pool, &mut rng);
        if let Err(e) = handle.write_all(&bytes) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }

    Ok(())
}

fn run_uuid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    let version = args.uuid_version.as_ref().unwrap_or(&UuidVersion::V4);

    if args.verbose {
        let name = match version {
            UuidVersion::V4 => "v4 (random, RFC 4122)",
            UuidVersion::V7 => "v7 (timestamp + random, RFC 9562)",
        };
        eprintln!("UUID version: {name}");
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: build each UUID into a stack buffer and write
    // directly — no per-UUID String allocation, matching run_typeid's approach.
    let mut buf = [0u8; 36];
    for _ in 0..count {
        let bytes = match version {
            UuidVersion::V4 => gen_uuid_v4_bytes(&mut rng),
            UuidVersion::V7 => next_v7_bytes(&mut rng)?,
        };
        format_uuid_bytes_buf(&bytes, &mut buf);
        if let Err(e) = handle.write_all(&buf) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }

    Ok(())
}

fn run_typeid(args: &Args) -> Result<()> {
    let count = resolve_count(args.count)?;

    let prefix = args.typeid_prefix.as_deref().unwrap_or("");

    // Validate up-front: fail fast before locking stdout or printing verbose
    // output. gen_typeid re-validates on each call, which is negligible (≤63
    // ASCII chars) and keeps gen_typeid independently correct.
    validate_prefix(prefix)?;

    if args.verbose {
        if prefix.is_empty() {
            eprintln!("TypeID: no prefix (bare suffix)");
        } else {
            eprintln!("TypeID prefix: {prefix}");
        }
    }

    let stdout = std::io::stdout();
    let mut handle = std::io::BufWriter::with_capacity(65_536, stdout.lock());
    let mut rng = rand::rng();

    // Zero-alloc hot path: write prefix, separator, and raw base32 suffix
    // directly to the stdout handle — no per-ID String allocation.
    // gen_typeid is used by tests and validates independently; here we
    // skip it since prefix is already validated above.
    let prefix_bytes = prefix.as_bytes();
    for _ in 0..count {
        let suffix = encode_base32(&next_v7_bytes(&mut rng)?);
        if !prefix_bytes.is_empty() {
            if let Err(e) = handle.write_all(prefix_bytes) {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    break;
                }
                return Err(e.into());
            }
            if let Err(e) = handle.write_all(b"_") {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    break;
                }
                return Err(e.into());
            }
        }
        if let Err(e) = handle.write_all(&suffix) {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
        if let Err(e) = handle.write_all(b"\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                break;
            }
            return Err(e.into());
        }
    }
    if let Err(e) = handle.flush() {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    // Return ExitCode instead of calling process::exit so that all
    // destructors run — in particular Zeroizing<T> drop impls.
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if args.ksuid || args.ksuid_ms {
        run_ksuid(&args)
    } else if args.ulid {
        run_ulid(&args)
    } else if args.nanoid || args.nanoid_size.is_some() || args.nanoid_alphabet.is_some() {
        run_nanoid(&args)
    } else if args.typeid || args.typeid_prefix.is_some() {
        run_typeid(&args)
    } else if args.uuid || args.uuid_version.is_some() {
        run_uuid(&args)
    } else {
        run_pass(&args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passid::password::{MAX_COUNT, MAX_LENGTH, MIN_LENGTH};

    #[test]
    fn config_rejects_empty_char_sets() {
        let args = Args {
            length: Some(16),
            no_upper: true,
            no_lower: true,
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_zero() {
        let args = Args {
            length: Some(16),
            count: Some(0),
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_count_over_max() {
        let args = Args {
            length: Some(16),
            count: Some(MAX_COUNT + 1),
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_short_length() {
        let args = Args {
            length: Some(4),
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_rejects_length_over_max() {
        let args = Args {
            length: Some(MAX_LENGTH + 1),
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_err());
    }

    #[test]
    fn config_accepts_max_sets_at_min_length() {
        let args = Args {
            length: Some(MIN_LENGTH),
            symbol: true,
            number: true,
            ..Default::default()
        };
        assert!(Config::try_from(&args).is_ok());
    }
}
