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
