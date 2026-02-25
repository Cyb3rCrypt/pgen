# TODO — Known Limitations & Future Work

| Item | Notes |
|------|-------|
| Single-file layout | All code is in `src/main.rs` (~1 073 lines). Consider splitting into `cli.rs` (`Args`, `Config`), `gen.rs` (`pgen`, UUID, TypeID), and `main.rs` (`main`, `run_*`) |
| `set.contains(&c)` is O(n) in tests | Acceptable for current set sizes (≤ 25). If sets grow large, replace `&[u8]` with `HashSet<u8>` in test validation loops |
| No clipboard output | A future `--clip` flag could write to the system clipboard via the `arboard` crate, zeroing after a configurable timeout |
| No passphrase mode | A future `--words <N>` flag with a bundled wordlist would complement the character-based password mode |
| No UUID namespace support | UUID v3/v5 (name-based) are not implemented |
