//! Parsing cargo's test output: the `test result:` lines and the verdict
//! they decide.
//!
//! Cargo prints one line per test binary, of the shape
//! `test result: ok. 12 passed; 0 failed; 2 ignored; 0 measured; 0 filtered
//! out; finished in 3.00s` (the `measured`/`filtered out`/`finished` parts
//! come and go between cargo versions). The parser reads ONLY these lines —
//! prose around them, including anything a test prints, is never a result —
//! and the summary fails closed: a run whose log names no `test result:`
//! line at all is "no results", which is a failure, never a pass.

/// One `test result:` line, i.e. one test binary's tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteResult {
    /// Tests that passed.
    pub passed: u64,
    /// Tests that failed.
    pub failed: u64,
    /// Tests skipped as `#[ignore]`.
    pub ignored: u64,
    /// True iff cargo said `ok` for this binary (no failure, no abort).
    pub ok: bool,
}

/// The verdict over a whole log (every suite's line summed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// How many `test result:` lines the log carried.
    pub suites: usize,
    /// Sum of `passed` over all suites.
    pub passed: u64,
    /// Sum of `failed` over all suites.
    pub failed: u64,
    /// Sum of `ignored` over all suites.
    pub ignored: u64,
    /// True iff at least one suite ran, no suite failed, and every suite
    /// cargo called `ok` was `ok`. Zero suites is NEVER ok: nothing
    /// examined can be a pass (INV-18's posture, held here too).
    pub all_ok: bool,
}

/// Extract every `test result:` tally from cargo output, in order.
pub fn cargo_test_results(output: &str) -> Vec<SuiteResult> {
    let mut found = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.trim_start().strip_prefix("test result: ") else {
            continue;
        };
        // The verdict is the first token, ended by `. `: `ok. 12 passed; …`
        // or `FAILED. 3 passed; 1 failed; …`.
        let (verdict, tallies) = match rest.split_once(". ") {
            Some(pair) => pair,
            None => continue,
        };
        let ok = match verdict {
            "ok" => true,
            "FAILED" => false,
            // An unknown verdict word is not a line this parser can judge;
            // skip it rather than guess (fail closed at the summary, which
            // then sees fewer suites than the run printed).
            _ => continue,
        };
        let mut passed = 0;
        let mut failed = 0;
        let mut ignored = 0;
        for field in tallies.split(';') {
            let Some((n, key)) = field.trim().split_once(' ') else {
                continue;
            };
            // The number is first, the name second; a field cargo does not
            // number (`finished in 3.00s`) fails to parse and is ignored.
            if let Ok(n) = n.parse::<u64>() {
                match key {
                    "passed" => passed = n,
                    "failed" => failed = n,
                    "ignored" => ignored = n,
                    _ => {}
                }
            }
        }
        found.push(SuiteResult {
            passed,
            failed,
            ignored,
            ok,
        });
    }
    found
}

/// Reduce a log's suite results to the run's verdict.
pub fn summarize(results: &[SuiteResult]) -> Summary {
    let mut summary = Summary {
        suites: results.len(),
        passed: 0,
        failed: 0,
        ignored: 0,
        all_ok: !results.is_empty(),
    };
    for r in results {
        summary.passed += r.passed;
        summary.failed += r.failed;
        summary.ignored += r.ignored;
        summary.all_ok &= r.ok && r.failed == 0;
    }
    summary
}

/// Summarise a whole log: [`cargo_test_results`] then [`summarize`].
pub fn summarize_output(output: &str) -> Summary {
    summarize(&cargo_test_results(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK_LINE: &str =
        "test result: ok. 12 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; \
         finished in 3.00s";
    const FAILED_LINE: &str =
        "test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; \
         finished in 1.00s";

    #[test]
    fn rh_dev_linux_parses_cargo_test_result_lines() {
        let log = format!(
            "running 14 tests\ntest a ... ok\n{OK_LINE}\n\ndoc-tests harness-sandbox\n\
             running 4 tests\n{FAILED_LINE}\nwarning: some prose mentioning \
             `test result:` without the shape\n"
        );
        let results = cargo_test_results(&log);
        assert_eq!(
            results,
            vec![
                SuiteResult {
                    passed: 12,
                    failed: 0,
                    ignored: 2,
                    ok: true
                },
                SuiteResult {
                    passed: 3,
                    failed: 1,
                    ignored: 0,
                    ok: false
                },
            ]
        );
        let summary = summarize(&results);
        assert_eq!(summary.suites, 2);
        assert_eq!(summary.passed, 15);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.ignored, 2);
        assert!(!summary.all_ok);
    }

    #[test]
    fn parse_reads_the_indented_and_prefixed_forms() {
        // A leading `warning:` block or indentation must not hide a result
        // line; leading whitespace is trimmed before the prefix is matched.
        let log = format!("  {OK_LINE}");
        assert_eq!(cargo_test_results(&log).len(), 1);
        let log = format!("\t{FAILED_LINE}");
        assert_eq!(cargo_test_results(&log).len(), 1);
    }

    #[test]
    fn parse_refuses_prose_and_unknown_verdicts() {
        // A truncated line, an unknown verdict word, and a result quoted in
        // test output (which does not START the line): none may count as a
        // judged suite.
        for line in [
            "test result: unexpected-shape",
            "test result: aborted. 1 passed; 0 failed",
            "some test said: test result: ok. 9 passed",
        ] {
            assert!(
                cargo_test_results(line).is_empty(),
                "prose parsed as a result: {line}"
            );
        }
    }

    #[test]
    fn empty_log_is_no_results_and_never_a_pass() {
        let summary = summarize_output("compiling harness-sandbox\nnothing else\n");
        assert_eq!(summary.suites, 0);
        assert!(!summary.all_ok);
        assert!(!summarize(&[]).all_ok);
    }
}
