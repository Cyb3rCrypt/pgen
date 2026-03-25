//! CLI integration tests — `TypeID` and ULID output validation.
//!
//! These tests spawn the compiled `pgen` binary and assert on stdout,
//! stderr, and exit code, giving end-to-end coverage of the `TypeID` and
//! `ULID` code paths that unit tests cannot exercise.

use std::process::Command;

fn pgen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pgen"))
}

const TYPEID_ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";

/// Crockford Base32 alphabet, uppercase (ULID spec).
const ULID_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const NANOID_URL_ALPHABET: &str =
    "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

fn assert_valid_suffix(suffix: &str, context: &str) {
    assert_eq!(
        suffix.len(),
        26,
        "{context}: suffix must be 26 chars, got: {suffix:?}"
    );
    for ch in suffix.chars() {
        assert!(
            TYPEID_ALPHABET.contains(ch),
            "{context}: suffix char {ch:?} is not in the TypeID alphabet"
        );
    }
    let first = suffix.chars().next().unwrap();
    assert!(
        first <= '7',
        "{context}: first suffix char {first:?} exceeds '7' — top 2 bits must be zero"
    );
}

fn assert_valid_ulid(ulid: &str, context: &str) {
    assert_eq!(
        ulid.len(),
        26,
        "{context}: ULID must be 26 chars, got: {ulid:?}"
    );
    for ch in ulid.chars() {
        assert!(
            ULID_ALPHABET.contains(ch),
            "{context}: ULID char {ch:?} is not in the Crockford uppercase alphabet"
        );
    }
    let first = ulid.chars().next().unwrap();
    assert!(
        first <= '7',
        "{context}: first ULID char {first:?} exceeds '7' — top bit of 48-bit field must be 0"
    );
}

fn assert_valid_nanoid(id: &str, expected_size: usize, context: &str) {
    assert_eq!(
        id.len(),
        expected_size,
        "{context}: NanoID must be {expected_size} chars, got: {id:?}"
    );
    for ch in id.chars() {
        assert!(
            NANOID_URL_ALPHABET.contains(ch),
            "{context}: NanoID char {ch:?} is not in the default URL-safe alphabet"
        );
    }
}

/// `--typeid-prefix <prefix>` produces a line of the form `<prefix>_<26-char-suffix>`.
#[test]
fn run_typeid_named_prefix_output() {
    let output = pgen()
        .args(["--typeid-prefix", "user"])
        .output()
        .expect("failed to spawn pgen");

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');

    assert_eq!(
        line.len(),
        31,
        "expected 31 chars (4 prefix + 1 underscore + 26 suffix), got: {line:?}"
    );
    assert!(
        line.starts_with("user_"),
        "expected line to start with 'user_', got: {line:?}"
    );

    let suffix = &line[5..]; // skip "user_"
    assert_valid_suffix(suffix, "named-prefix");
}

/// `--typeid` (no prefix) produces a single bare 26-character base32 suffix with no underscore.
#[test]
fn run_typeid_empty_prefix_bare_suffix() {
    let output = pgen()
        .arg("--typeid")
        .output()
        .expect("failed to spawn pgen");

    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');

    assert!(
        !line.contains('_'),
        "bare typeid must not contain underscore, got: {line:?}"
    );
    assert_valid_suffix(line, "bare-suffix");
}

/// An invalid prefix exits non-zero and writes nothing to stdout.
///
/// This also verifies the early-validation guarantee: `run_typeid` calls
/// `validate_prefix` before the generation loop, so no partial output is
/// produced on error.
#[test]
fn run_typeid_rejects_invalid_prefix_before_any_output() {
    let long = "a".repeat(64);
    let cases: &[&str] = &[
        "PREFIX", // uppercase letters
        "12345",  // digits only
        "_bad",   // leading underscore
        "bad_",   // trailing underscore
        &long,    // exceeds 63-char limit
    ];

    for bad in cases {
        let output = pgen()
            .args(["--typeid-prefix", bad])
            .output()
            .expect("failed to spawn pgen");

        assert!(
            !output.status.success(),
            "expected non-zero exit for prefix {bad:?}, got {:?}",
            output.status,
        );
        assert!(
            output.stdout.is_empty(),
            "expected no stdout for invalid prefix {bad:?}, got: {:?}",
            String::from_utf8_lossy(&output.stdout),
        );
    }
}
// ---------------------------------------------------------------------------
// --ulid integration tests
// ---------------------------------------------------------------------------

/// --ulid produces a single 26-character Crockford Base32 line.
#[test]
fn run_ulid_single_output() {
    let output = pgen().arg("--ulid").output().expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_eq!(line.len(), 26, "ULID must be 26 chars, got: {line:?}");
    assert_valid_ulid(line, "run_ulid_single_output");
}

/// --ulid --count 5 produces exactly 5 lines, each a valid ULID,
/// and the sequence is strictly lexicographically increasing.
#[test]
fn run_ulid_count_monotonic() {
    let output = pgen()
        .args(["--ulid", "--count", "5"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "expected 5 ULIDs, got {}", lines.len());
    for (i, &line) in lines.iter().enumerate() {
        assert_valid_ulid(line, &format!("run_ulid_count_monotonic[{i}]"));
    }
    for w in lines.windows(2) {
        assert!(
            w[0] < w[1],
            "ULID monotonicity violated: {} >= {}",
            w[0],
            w[1]
        );
    }
}

/// --ulid --verbose writes a descriptor line to stderr, not stdout.
#[test]
fn run_ulid_verbose_to_stderr() {
    let output = pgen()
        .args(["--ulid", "--verbose"])
        .output()
        .expect("failed to spawn pgen");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ULID"),
        "expected ULID descriptor in stderr, got: {stderr}"
    );
    // stdout must still be exactly one ULID line
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout.trim_end_matches('\n');
    assert_eq!(
        line.len(),
        26,
        "stdout must be a single 26-char ULID: {line:?}"
    );
    assert_valid_ulid(line, "run_ulid_verbose_to_stderr");
}

/// --ulid conflicts with --length (password mode).
#[test]
fn run_ulid_conflicts_with_length() {
    let output = pgen()
        .args(["--ulid", "--length", "20"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when --ulid combined with --length"
    );
}

// ---------------------------------------------------------------------------
// --nanoid integration tests
// ---------------------------------------------------------------------------

/// --nanoid emits one default-length (21) URL-safe `NanoID`.
#[test]
fn run_nanoid_single_default_output() {
    let output = pgen()
        .arg("--nanoid")
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_nanoid(line, 21, "run_nanoid_single_default_output");
}

/// --nanoid-size changes the output length and implies `NanoID` mode.
#[test]
fn run_nanoid_size_implies_mode() {
    let output = pgen()
        .args(["--nanoid-size", "32"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}",
        output.status
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_nanoid(line, 32, "run_nanoid_size_implies_mode");
}

/// --nanoid --count 5 prints exactly 5 valid `NanoID`s.
#[test]
fn run_nanoid_count_five() {
    let output = pgen()
        .args(["--nanoid", "--count", "5"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}",
        output.status
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "expected 5 NanoIDs, got {}", lines.len());
    for (i, line) in lines.iter().enumerate() {
        assert_valid_nanoid(line, 21, &format!("run_nanoid_count_five[{i}]"));
    }
}

/// --nanoid-alphabet constrains output to the provided alphabet.
#[test]
fn run_nanoid_custom_alphabet() {
    let output = pgen()
        .args([
            "--nanoid",
            "--nanoid-alphabet",
            "ABC123",
            "--nanoid-size",
            "40",
        ])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_eq!(line.len(), 40, "expected 40-char NanoID, got: {line:?}");
    for ch in line.chars() {
        assert!(
            "ABC123".contains(ch),
            "custom NanoID char {ch:?} is outside provided alphabet"
        );
    }
}

/// Invalid custom alphabet should fail and not emit output.
#[test]
fn run_nanoid_rejects_invalid_alphabet() {
    let output = pgen()
        .args(["--nanoid", "--nanoid-alphabet", "AAB"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit for duplicate alphabet characters"
    );
    assert!(
        output.stdout.is_empty(),
        "expected no stdout on invalid alphabet"
    );
}

/// --nanoid --verbose prints `NanoID` descriptor to stderr.
#[test]
fn run_nanoid_verbose_to_stderr() {
    let output = pgen()
        .args(["--nanoid", "--verbose"])
        .output()
        .expect("failed to spawn pgen");
    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NanoID"),
        "expected NanoID descriptor in stderr, got: {stderr}"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_nanoid(line, 21, "run_nanoid_verbose_to_stderr");
}

/// --help includes a distribution warning for pooled password generation.
#[test]
fn help_mentions_pool_weighting_note() {
    let output = pgen().arg("--help").output().expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(
        stdout.contains("sampled uniformly from the pooled alphabet"),
        "help output is missing pool-weighting warning:\n{stdout}"
    );
}

/// Running without mode flags and without `--length` should fail (password mode requires length).
#[test]
fn run_requires_length_in_password_mode() {
    let output = pgen().output().expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when no arguments are provided"
    );
}

/// `--length` below minimum should fail with a validation error.
#[test]
fn run_rejects_length_below_minimum() {
    let output = pgen()
        .args(["--length", "9"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit for length below minimum"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("below the minimum"),
        "expected minimum-length error, got: {stderr}"
    );
}

/// `--length` above maximum should fail with a validation error.
#[test]
fn run_rejects_length_above_maximum() {
    let output = pgen()
        .args(["--length", "4097"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit for length above maximum"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum"),
        "expected maximum-length error, got: {stderr}"
    );
}

/// Disabling upper and lower without enabling symbols/numbers should fail.
#[test]
fn run_rejects_no_active_character_sets() {
    let output = pgen()
        .args(["--length", "16", "--no-upper", "--no-lower"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when no character sets are active"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No character sets are active"),
        "expected no-active-set error, got: {stderr}"
    );
}

/// `--count 0` should fail consistently in every generation mode.
#[test]
fn run_rejects_count_zero_in_all_modes() {
    let cases: &[&[&str]] = &[
        &["--length", "16", "--count", "0"],
        &["--uuid", "--count", "0"],
        &["--typeid", "--count", "0"],
        &["--ulid", "--count", "0"],
        &["--nanoid", "--count", "0"],
        &["--ksuid", "--count", "0"],
        &["--ksuid-ms", "--count", "0"],
    ];

    for args in cases {
        let output = pgen().args(*args).output().expect("failed to spawn pgen");
        assert!(
            !output.status.success(),
            "expected non-zero exit for args: {args:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--count must be at least 1"),
            "expected count validation error for {args:?}, got: {stderr}"
        );
    }
}

/// `--count` over the hard maximum should fail.
#[test]
fn run_rejects_count_above_maximum() {
    let output = pgen()
        .args(["--uuid", "--count", "10001"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit for count over maximum"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum"),
        "expected maximum-count error, got: {stderr}"
    );
}

/// Mutually exclusive mode flags should be rejected by clap.
#[test]
fn run_rejects_conflicting_modes() {
    let output = pgen()
        .args(["--uuid", "--nanoid"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit for conflicting mode flags"
    );
}

// ---------------------------------------------------------------------------
// --ksuid / --ksuid-ms integration tests
// ---------------------------------------------------------------------------

const BASE62_CHARS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn assert_valid_ksuid(id: &str, context: &str) {
    assert_eq!(
        id.len(),
        27,
        "{context}: KSUID must be 27 chars, got: {id:?}"
    );
    for ch in id.chars() {
        assert!(
            BASE62_CHARS.contains(ch),
            "{context}: KSUID char {ch:?} is not in the base62 alphabet"
        );
    }
}

/// --ksuid produces a single valid 27-character base62 KSUID.
#[test]
fn run_ksuid_single_output() {
    let output = pgen()
        .arg("--ksuid")
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_ksuid(line, "run_ksuid_single_output");
}

/// --ksuid-ms produces a single valid 27-character base62 KSUID (`KsuidMs` variant).
#[test]
fn run_ksuid_ms_single_output() {
    let output = pgen()
        .arg("--ksuid-ms")
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_ksuid(line, "run_ksuid_ms_single_output");
}

/// --ksuid --count 5 produces exactly 5 valid KSUIDs.
#[test]
fn run_ksuid_count_five() {
    let output = pgen()
        .args(["--ksuid", "--count", "5"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        output.status.success(),
        "expected exit 0, got {:?}",
        output.status
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 5, "expected 5 KSUIDs, got {}", lines.len());
    for (i, line) in lines.iter().enumerate() {
        assert_valid_ksuid(line, &format!("run_ksuid_count_five[{i}]"));
    }
}

/// --ksuid --verbose writes a descriptor to stderr and a valid KSUID to stdout.
#[test]
fn run_ksuid_verbose_to_stderr() {
    let output = pgen()
        .args(["--ksuid", "--verbose"])
        .output()
        .expect("failed to spawn pgen");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KSUID"),
        "expected KSUID descriptor in stderr, got: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let line = stdout.trim_end_matches('\n');
    assert_valid_ksuid(line, "run_ksuid_verbose_to_stderr");
}

/// --ksuid conflicts with --length (password mode).
#[test]
fn run_ksuid_conflicts_with_length() {
    let output = pgen()
        .args(["--ksuid", "--length", "20"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when --ksuid combined with --length"
    );
}

/// --ksuid conflicts with --uuid.
#[test]
fn run_ksuid_conflicts_with_uuid() {
    let output = pgen()
        .args(["--ksuid", "--uuid"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when --ksuid combined with --uuid"
    );
}

/// --ksuid and --ksuid-ms are mutually exclusive.
#[test]
fn run_ksuid_conflicts_with_ksuid_ms() {
    let output = pgen()
        .args(["--ksuid", "--ksuid-ms"])
        .output()
        .expect("failed to spawn pgen");
    assert!(
        !output.status.success(),
        "expected non-zero exit when --ksuid combined with --ksuid-ms"
    );
}
