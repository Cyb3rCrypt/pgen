//! CLI integration tests — Unit 5: `run_typeid` output validation.
//!
//! These tests spawn the compiled `pgen` binary and assert on stdout,
//! stderr, and exit code, giving end-to-end coverage of the `TypeID` code path
//! that unit tests (which call `gen_typeid` directly) cannot exercise.

use std::process::Command;

fn pgen() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pgen"))
}

const TYPEID_ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";

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
