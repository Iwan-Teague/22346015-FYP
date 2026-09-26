//! The `datecalc` family (category `calendar`) — proleptic-Gregorian
//! calendar queries over one seeded `(year, month, day)` triple.
//!
//! Where `modpow` works in cyclic arithmetic, this family walks the civil
//! calendar: the leap rule, the length of a month, the ordinal day within
//! the year, whole days from the Unix epoch, and the day of week. The
//! domain is a triple `(year, month, day)` with `year` positive and
//! `month`/`day` in range; every op is a pure function of it. The seed
//! prunes which two of five query ops are required: `is_leap`,
//! `days_in_month`, `day_of_year`, `days_since_epoch`, `weekday`.
//! C(5,2) = **10 distinct skills**, above the diversity floor; op names
//! are semantic.
//!
//! The canonical date is constructed so its anchor facts hold by
//! arithmetic rather than luck: it is February 29 of a sampled leap
//! year whose epoch distance and weekday both move when leap days are
//! ignored. Those make `const-zero` fail on every op and keep the
//! `never-leap` cheat exact only on `day_of_year` itself (February
//! precedes the adjustment point); any pair containing it is caught by
//! its partner, and pairs without it are wrong twice over.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! and the emitted reference share the same bodies; the differential
//! fuzzes 3000 random dates against the model.
//!
//! Trivial baselines: `const-zero` (fails outright on the canonical
//! date) and `never-leap` (every query answered as if no year were leap).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    IsLeap,
    DaysInMonth,
    DayOfYear,
    DaysSinceEpoch,
    Weekday,
}

const OP_ALL: [Op; 5] = [
    Op::IsLeap,
    Op::DaysInMonth,
    Op::DayOfYear,
    Op::DaysSinceEpoch,
    Op::Weekday,
];

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::IsLeap => "is_leap",
            Op::DaysInMonth => "days_in_month",
            Op::DayOfYear => "day_of_year",
            Op::DaysSinceEpoch => "days_since_epoch",
            Op::Weekday => "weekday",
        }
    }

    fn prose(self) -> &'static str {
        match self {
            Op::IsLeap => {
                "whether the year follows the Gregorian leap rule \
                 (every fourth year, except centuries, which must \
                 complete four hundred)"
            }
            Op::DaysInMonth => {
                "how many days the month holds, with February \
                 following the leap rule"
            }
            Op::DayOfYear => {
                "the ordinal position of the date within its year, \
                 counting January first as day one"
            }
            Op::DaysSinceEpoch => {
                "the number of whole days between 1970-01-01 and this \
                 date (negative before the epoch)"
            }
            Op::Weekday => {
                "the day of week as zero through six, counting \
                 Thursday (the Unix epoch day) as zero"
            }
        }
    }

    /// Return type used in signatures, stubs, and the prompt fence.
    fn ret(self) -> &'static str {
        match self {
            Op::IsLeap => "bool",
            _ => "i64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Spec {
    ops: [Op; 2],
}

fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let i1 = rng.below(5);
    let mut i2 = rng.below(5);
    while i2 == i1 {
        i2 = rng.below(5);
    }
    Spec {
        ops: [OP_ALL[i1 as usize], OP_ALL[i2 as usize]],
    }
}
// ---- native mirror (the answer; identical shape to the emitted code) ------

/// The Gregorian leap rule on the year alone.
fn leap_year(year: u32) -> bool {
    let y = year as u64;
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

fn b_is_leap(year: u32, month: u8, day: u8) -> bool {
    let _ = (month, day);
    leap_year(year)
}

fn b_days_in_month(year: u32, month: u8, day: u8) -> i64 {
    let _ = day;
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn b_day_of_year(year: u32, month: u8, day: u8) -> i64 {
    const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let idx = match month {
        1..=12 => (month - 1) as usize,
        _ => return 0,
    };
    let mut doy = CUM[idx] + day as i64;
    // Days before March in a leap year include Feb 29.
    if month > 2 && leap_year(year) {
        doy += 1;
    }
    doy
}

/// Howard Hinnant's days_from_civil shifted to the Unix epoch. With
/// `count_leaps` cleared, the partial-era leap-day corrections are
/// dropped — that is exactly the `never-leap` cheat's arithmetic.
fn civil_days(year: u32, month: u8, day: u8, count_leaps: bool) -> i64 {
    const CIVIL_EPOCH_OFFSET: i64 = 719_468;
    let y_i = year as i64;
    let yy = if month <= 2 { y_i - 1 } else { y_i };
    let era = yy.div_euclid(400);
    let yoe = (yy - era * 400) as u64;
    let mp = ((month as u64) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day as u64 - 1;
    let extra = if count_leaps { yoe / 4 - yoe / 100 } else { 0 };
    let doe = yoe * 365 + extra + doy;
    era * 146_097 + doe as i64 - CIVIL_EPOCH_OFFSET
}

fn b_days_since_epoch(year: u32, month: u8, day: u8) -> i64 {
    civil_days(year, month, day, true)
}

fn b_weekday(year: u32, month: u8, day: u8) -> i64 {
    b_days_since_epoch(year, month, day).rem_euclid(7)
}

// ---- never-leap answers (anchors and cheat-separation tests only) ---------

fn nl_answer(op: Op, year: u32, month: u8, day: u8) -> Out {
    match op {
        Op::IsLeap => Out::Flag(false),
        Op::DaysInMonth => Out::Num(match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => 28,
            _ => 0,
        }),
        Op::DayOfYear => Out::Num({
            const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
            match month {
                1..=12 => CUM[(month - 1) as usize] + day as i64,
                _ => 0,
            }
        }),
        Op::DaysSinceEpoch => Out::Num(civil_days(year, month, day, false)),
        Op::Weekday => Out::Num(civil_days(year, month, day, false).rem_euclid(7)),
    }
}

/// One op's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Out {
    Num(i64),
    Flag(bool),
}

impl Out {
    /// The literal rendered into an emitted assertion.
    fn lit(self) -> String {
        match self {
            Out::Num(v) => v.to_string(),
            Out::Flag(b) => b.to_string(),
        }
    }
}

fn op_eval(op: Op, year: u32, month: u8, day: u8) -> Out {
    match op {
        Op::IsLeap => Out::Flag(b_is_leap(year, month, day)),
        Op::DaysInMonth => Out::Num(b_days_in_month(year, month, day)),
        Op::DayOfYear => Out::Num(b_day_of_year(year, month, day)),
        Op::DaysSinceEpoch => Out::Num(b_days_since_epoch(year, month, day)),
        Op::Weekday => Out::Num(b_weekday(year, month, day)),
    }
}

// ---- canonical input --------------------------------------------------------

/// The canonical date, constructed so the anchors hold by arithmetic:
/// February 29 of a sampled leap year whose epoch distance and weekday
/// both move when leap days are ignored. Guaranteed for every seed:
/// `is_leap` true, every scalar answer nonzero and pairwise distinct,
/// and `never-leap` wrong everywhere but `day_of_year`.
const CANONICAL_SEED: u64 = 0xDA7E_CA1C;

fn canonical(seed: u64) -> (u32, u8, u8) {
    let mut rng = Rng::new(seed ^ CANONICAL_SEED);
    for _ in 0..100_000 {
        let year = 1600 + rng.below(800) as u32;
        let (month, day) = (2u8, 29u8);
        if anchors_hold(year, month, day) {
            return (year, month, day);
        }
    }
    unreachable!("canonical input sampling failed to satisfy anchors");
}

fn anchors_hold(year: u32, month: u8, day: u8) -> bool {
    b_is_leap(year, month, day)
        && b_weekday(year, month, day) != 0
        && b_days_in_month(year, month, day) != 0
        && b_day_of_year(year, month, day) != 0
        && b_days_since_epoch(year, month, day) != 0
        && op_eval(Op::DaysSinceEpoch, year, month, day)
            != nl_answer(Op::DaysSinceEpoch, year, month, day)
        && op_eval(Op::Weekday, year, month, day) != nl_answer(Op::Weekday, year, month, day)
}
// ---- worked examples --------------------------------------------------------

type ExampleCase = ((u32, u8, u8), Vec<(Op, Out)>);

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0130;

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    let mut cases: Vec<ExampleCase> = Vec::new();
    let push = |cases: &mut Vec<ExampleCase>, y: u32, m: u8, d: u8| {
        cases.push((
            (y, m, d),
            spec.ops.map(|op| (op, op_eval(op, y, m, d))).to_vec(),
        ));
    };
    // Canonical leap-day date first.
    let can = canonical(seed);
    push(&mut cases, can.0, can.1, can.2);
    // The Unix epoch itself: zero conventions.
    push(&mut cases, 1970, 1, 1);
    // One day before the epoch goes negative.
    push(&mut cases, 1969, 12, 31);
    // Century corner: 1900 is not a leap year.
    push(&mut cases, 1900, 2, 28);
    for _ in 0..3 {
        let y = 1950 + rng.below(80) as u32;
        let m = 1 + rng.below(12) as u8;
        let d = 1 + rng.below(28) as u8;
        push(&mut cases, y, m, d);
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Emitted literal for a call site; the first element carries a suffix
/// and the rest are inferred at the typed call sites.
fn render_triple(t: &(u32, u8, u8)) -> String {
    format!("({}u32, {}, {})", t.0, t.1, t.2)
}

/// The civil-days walk shared by the two epoch-shaped bodies.
/// Self-contained on purpose: a seed's pair may not select
/// `days_since_epoch`, so `weekday` inlines the whole walk too.
fn epoch_walk_src() -> String {
    [
        "const CIVIL_EPOCH_OFFSET: i64 = 719_468;",
        "let y_i = year as i64;",
        "let yy = if month <= 2 { y_i - 1 } else { y_i };",
        "let era = yy.div_euclid(400);",
        "let yoe = (yy - era * 400) as u64;",
        "let mp = ((month as u64) + 9) % 12;",
        "let doy = (153 * mp + 2) / 5 + day as u64 - 1;",
        "let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;",
        "let total = era * 146_097 + doe as i64 - CIVIL_EPOCH_OFFSET;",
    ]
    .join("\n    ")
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let sig = match op.ret() {
        "bool" => "(year: u32, month: u8, day: u8) -> bool",
        _ => "(year: u32, month: u8, day: u8) -> i64",
    };
    let body = match op {
        Op::IsLeap => [
            "let y = year as u64;",
            "y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)",
        ]
        .join("\n    "),
        Op::DaysInMonth => [
            "match month {",
            "    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,",
            "    4 | 6 | 9 | 11 => 30,",
            "    2 => {",
            "        let y = year as u64;",
            "        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {",
            "            29",
            "        } else {",
            "            28",
            "        }",
            "    }",
            "    _ => 0,",
            "}",
        ]
        .join("\n    "),
        Op::DayOfYear => [
            "const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];",
            "let idx = match month {",
            "    1..=12 => (month - 1) as usize,",
            "    _ => return 0,",
            "};",
            "let mut doy = CUM[idx] + day as i64;",
            "let y = year as u64;",
            "let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);",
            "if month > 2 && leap {",
            "    doy += 1;",
            "}",
            "doy",
        ]
        .join("\n    "),
        Op::DaysSinceEpoch | Op::Weekday => {
            let tail = match op {
                Op::DaysSinceEpoch => "total",
                _ => "total.rem_euclid(7)",
            };
            format!("{}\n    {}", epoch_walk_src(), tail)
        }
    };
    format!("pub fn {name}{sig} {{\n    {body}\n}}\n")
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    format!(
        "pub fn {}(year: u32, month: u8, day: u8) -> {} {{\n    todo!()\n}}\n",
        op.name(),
        op.ret()
    )
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    format!(
        "pub fn {}(year: u32, month: u8, day: u8) -> {}",
        op.name(),
        op.ret()
    )
}

fn reference_src(spec: &Spec) -> String {
    spec.ops.iter().map(|op| op_fn_src(*op)).collect()
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, var: &str) -> String {
    format!("{}({})", op.name(), var)
}
fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (triple, outs) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "  date (year {}, month {}, day {})  ->  {}\n",
            triple.0, triple.1, triple.2, results
        ));
    }
    s
}

fn skeleton_src(spec: &Spec, seed: u64) -> String {
    let doc = worked_examples_prose(spec, seed)
        .lines()
        .map(|l| format!("//! {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    let fns = spec.ops.map(op_stub_src).concat();
    format!(
        "//! Implement the two query functions below.\n\
         //!\n\
         //! Examples:\n\
         {doc}\n\
         {fns}",
        doc = doc,
        fns = fns,
    )
}

fn prompt(spec: &Spec, seed: u64, canary: &str) -> String {
    let mut reqs = String::new();
    for op in spec.ops {
        reqs.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    format!(
        "Implement the two query functions in `src/lib.rs`. The input is \
         given as three integers: `year` of type `u32` (always positive), \
         and `month`/`day` of types `u8` with `month` from one to twelve \
         and `day` valid for that month; queries are proleptic-Gregorian \
         calendar properties of the date. The Gregorian leap rule and the \
         Unix epoch convention described below must be followed exactly.\n\
         \n\
         Implement exactly these two functions:\n\
         {reqs}\
         Any correct implementation is fine.\n\
         \n\
         Constraints:\n\
         - Do not use `unsafe`.\n\
         \n\
         Signatures:\n\
         ```rust\n\
         {signatures}\
         ```\n\
         \n\
         Examples:\n\
         {examples}\
         Return the complete contents of `src/lib.rs` as a single ```rust code block. \
         (ref: {canary})\n",
        reqs = reqs,
        signatures = spec
            .ops
            .iter()
            .map(|op| format!("{}\n", op_sig_src(*op)))
            .collect::<Vec<_>>()
            .join(""),
        examples = worked_examples_prose(spec, seed),
        canary = canary,
    )
}

fn cargo_toml() -> String {
    "[package]\n\
     name = \"task\"\n\
     version = \"0.0.0\"\n\
     edition = \"2021\"\n\
     \n\
     [lib]\n\
     path = \"src/lib.rs\"\n\
     \n\
     [workspace]\n"
        .to_string()
}
fn behavior_test_src(spec: &Spec, seed: u64) -> String {
    let imports = spec
        .ops
        .iter()
        .map(|op| op.name())
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!("use task::{{{imports}}};\n\n");
    for (i, (triple, outs)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n    let (year, month, day) = {};\n",
            render_triple(triple),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({}, {});\n",
                call_src(*op, "year, month, day"),
                out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the two selected ops, pasted into the test
/// file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen(
            &format!("pub fn {}", spec.ops[0].name()),
            &format!("fn ref_{}", spec.ops[0].name()),
            1,
        )
        .replacen(
            &format!("pub fn {}", spec.ops[1].name()),
            &format!("fn ref_{}", spec.ops[1].name()),
            1,
        );
    let asserts = spec
        .ops
        .iter()
        .map(|op| {
            let call = call_src(*op, "year, month, day");
            format!("        assert_eq!({call}, ref_{call});\n")
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0130;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       // Always-valid dates: months run one through twelve and\n\
         \x20       // days stay within the shortest month, so every draw\n\
         \x20       // lands inside the calendar.\n\
         \x20       let year = (nx(&mut state) % 80 + 1950) as u32;\n\
         \x20       let month = (nx(&mut state) % 12 + 1) as u8;\n\
         \x20       let day = (nx(&mut state) % 28 + 1) as u8;\n\
         {asserts}\
         \x20   }}\n\
         }}\n",
        imports = spec
            .ops
            .iter()
            .map(|op| op.name())
            .collect::<Vec<_>>()
            .join(", "),
        reference = reference,
        asserts = asserts,
    )
}
/// Degenerate: everything zero (and a hardcoded `false` on the booleans).
fn const_zero(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op.ret() {
                "bool" => {
                    format!("{sig} {{\n    let _ = (year, month, day);\n    false\n}}\n")
                }
                _ => format!("{sig} {{\n    let _ = (year, month, day);\n    0\n}}\n"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The structural cheat: answer every query as if no year were ever
/// leap. The canonical anchors make it wrong on both epoch-shaped ops
/// and on the leap flag itself; it is exact only on `day_of_year`
/// (February precedes the adjustment point), so any pair carrying
/// that op is caught by its partner.
fn never_leap(spec: &Spec) -> String {
    spec.ops
        .iter()
        .map(|op| {
            let sig = op_sig_src(*op);
            match op {
                Op::IsLeap => {
                    format!("{sig} {{\n    let _ = (year, month, day);\n    false\n}}\n")
                }
                Op::DaysInMonth => format!(
                    "{sig} {{\n    {}\n}}\n",
                    [
                        "match month {",
                        "    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,",
                        "    4 | 6 | 9 | 11 => 30,",
                        "    2 => 28,",
                        "    _ => 0,",
                        "}"
                    ]
                    .join("\n    ")
                ),
                Op::DayOfYear => format!(
                    "{sig} {{\n    {}\n}}\n",
                    [
                        "const CUM: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];",
                        "let idx = match month {",
                        "    1..=12 => (month - 1) as usize,",
                        "    _ => return 0,",
                        "};",
                        "CUM[idx] + day as i64"
                    ]
                    .join("\n    ")
                ),
                Op::DaysSinceEpoch => format!(
                    "{sig} {{\n    {}\n}}\n",
                    [
                        "const CIVIL_EPOCH_OFFSET: i64 = 719_468;",
                        "let y_i = year as i64;",
                        "let yy = if month <= 2 { y_i - 1 } else { y_i };",
                        "let era = yy.div_euclid(400);",
                        "let yoe = (yy - era * 400) as u64;",
                        "let mp = ((month as u64) + 9) % 12;",
                        "let doy = (153 * mp + 2) / 5 + day as u64 - 1;",
                        "let doe = yoe * 365 + doy;",
                        "era * 146_097 + doe as i64 - CIVIL_EPOCH_OFFSET"
                    ]
                    .join("\n    ")
                ),
                Op::Weekday => format!(
                    "{sig} {{\n    {}\n}}\n",
                    [
                        "const CIVIL_EPOCH_OFFSET: i64 = 719_468;",
                        "let y_i = year as i64;",
                        "let yy = if month <= 2 { y_i - 1 } else { y_i };",
                        "let era = yy.div_euclid(400);",
                        "let yoe = (yy - era * 400) as u64;",
                        "let mp = ((month as u64) + 9) % 12;",
                        "let doy = (153 * mp + 2) / 5 + day as u64 - 1;",
                        "let doe = yoe * 365 + doy;",
                        "let total = era * 146_097 + doe as i64 - CIVIL_EPOCH_OFFSET;",
                        "total.rem_euclid(7)"
                    ]
                    .join("\n    ")
                ),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct DateCalcFamily;

impl Generator for DateCalcFamily {
    fn id(&self) -> &str {
        "datecalc"
    }
    fn category(&self) -> &str {
        "calendar"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("datecalc", seed);

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(PathBuf::from("src/lib.rs"), skeleton_src(&spec, seed));

        let mut hidden = BTreeMap::new();
        hidden.insert(
            PathBuf::from("tests/behavior.rs"),
            behavior_test_src(&spec, seed),
        );
        hidden.insert(
            PathBuf::from("tests/differential.rs"),
            differential_test_src(&spec),
        );

        GeneratedTask {
            id: format!("datecalc/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure calendar bookkeeping — no unsafe anywhere near it.
            max_unsafe: None,
            forbidden_paths: Vec::new(),
            check_clippy: false,
            clippy_allow: Vec::new(),
            // Default oracle weights (docs/04).
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        reference_src(&sample(seed))
    }
    fn skeleton_code(&self, seed: u64) -> String {
        skeleton_src(&sample(seed), seed)
    }
    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero(&spec)),
            ("never-leap".to_string(), never_leap(&spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<&str> = sample(seed).ops.iter().map(|op| op.name()).collect();
        names.sort_unstable();
        vec![format!("q:{}/{}", names[0], names[1])]
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let g = DateCalcFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Leap rule.
        assert!(b_is_leap(2024, 1, 1));
        assert!(!b_is_leap(2023, 1, 1));
        assert!(!b_is_leap(1900, 6, 15));
        assert!(b_is_leap(2000, 2, 28));
        assert!(b_is_leap(1600, 12, 31));
        assert!(!b_is_leap(2100, 3, 1));
        // Month lengths.
        for m in [1u8, 3, 5, 7, 8, 10, 12] {
            assert_eq!(b_days_in_month(2023, m, 1), 31);
        }
        for m in [4u8, 6, 9, 11] {
            assert_eq!(b_days_in_month(2023, m, 1), 30);
        }
        assert_eq!(b_days_in_month(2023, 2, 1), 28);
        assert_eq!(b_days_in_month(2024, 2, 1), 29);
        assert_eq!(b_days_in_month(2000, 2, 1), 29);
        assert_eq!(b_days_in_month(1900, 2, 1), 28);
        assert_eq!(b_days_in_month(2023, 13, 1), 0);
        // Ordinal day.
        assert_eq!(b_day_of_year(2023, 1, 1), 1);
        assert_eq!(b_day_of_year(2023, 2, 28), 59);
        assert_eq!(b_day_of_year(2024, 2, 28), 59);
        assert_eq!(b_day_of_year(2023, 3, 1), 60);
        assert_eq!(b_day_of_year(2024, 3, 1), 61);
        assert_eq!(b_day_of_year(2023, 12, 31), 365);
        assert_eq!(b_day_of_year(2024, 12, 31), 366);
        assert_eq!(b_day_of_year(2023, 0, 5), 0);
        // Epoch distances.
        assert_eq!(b_days_since_epoch(1970, 1, 1), 0);
        assert_eq!(b_days_since_epoch(1970, 1, 2), 1);
        assert_eq!(b_days_since_epoch(1969, 12, 31), -1);
        assert_eq!(b_days_since_epoch(2000, 3, 1), 11_017);
        assert_eq!(b_days_since_epoch(2024, 1, 1), 19_723);
        // Weekday, Thursday-epoch convention.
        assert_eq!(b_weekday(1970, 1, 1), 0);
        assert_eq!(b_weekday(1970, 1, 2), 1);
        assert_eq!(b_weekday(1970, 1, 4), 3);
        assert_eq!(b_weekday(2000, 1, 1), 2); // Saturday
        assert_eq!(b_weekday(2024, 1, 1), 4); // Monday
        assert_eq!(b_weekday(1969, 12, 31), 6); // Wednesday
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut sigs = std::collections::HashSet::new();
        for seed in 0..300u64 {
            sigs.insert(sample(seed));
        }
        // C(5,2) = 10 unordered pairs; demand near-full coverage.
        assert!(
            sigs.len() >= 9,
            "expected wide query-pair variety, got {}",
            sigs.len()
        );
    }

    #[test]
    fn canonical_answers_are_non_degenerate_for_every_op() {
        // Both baselines must fail under EVERY pair. The canonical date is
        // a Feb 29 whose epoch distance and weekday both move when leap
        // days are ignored: `const-zero` separates on every op, and
        // `never-leap` is exact only on `day_of_year` — pairs carrying it
        // are caught by their partner.
        for seed in 0..200u64 {
            let (year, month, day) = canonical(seed);
            assert!(leap_year(year), "seed {seed}");
            assert_ne!(b_weekday(year, month, day), 0, "seed {seed}");
            assert_ne!(
                op_eval(Op::DaysSinceEpoch, year, month, day),
                nl_answer(Op::DaysSinceEpoch, year, month, day),
                "never-leap survives days_since_epoch seed {seed}"
            );
            assert_ne!(
                op_eval(Op::Weekday, year, month, day),
                nl_answer(Op::Weekday, year, month, day),
                "never-leap survives weekday seed {seed}"
            );
            for op in OP_ALL {
                match op_eval(op, year, month, day) {
                    Out::Num(v) => {
                        assert_ne!(v, 0, "const-zero survives {op:?} seed {seed}");
                        if !matches!(op, Op::DayOfYear) {
                            assert_ne!(
                                op_eval(op, year, month, day),
                                nl_answer(op, year, month, day),
                                "never-leap survives {op:?} seed {seed}"
                            );
                        }
                    }
                    Out::Flag(b) => {
                        assert!(b, "const-zero survives {op:?} seed {seed}");
                    }
                }
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for ((y, m, d), outs) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, y, m, d), out, "seed {seed}");
                }
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let src = reference_src(&spec);
            for op in OP_ALL {
                // Match the `pub fn` line so no bare-name substring leaks.
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{op:?} leaked");
                }
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            // Solution-shaped leak tokens must stay out of the skeleton.
            assert!(!sk.contains("% 4"));
            assert!(!sk.contains("% 100"));
            assert!(!sk.contains("% 400"));
            assert!(!sk.contains("719_468"));
            assert!(!sk.contains("146_097"));
            assert!(!sk.contains("rem_euclid"));
            assert!(!sk.contains("div_euclid"));
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("% 4"));
            assert!(!p.contains("% 100"));
            assert!(!p.contains("% 400"));
            assert!(!p.contains("719_468"));
            assert!(!p.contains("146_097"));
            assert!(!p.contains("rem_euclid"));
            assert!(!p.contains("div_euclid"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Every op is ternary here, so each call site carries exactly two
        // commas — the same count as its signature.
        for op in OP_ALL {
            let call = call_src(op, "year, month, day");
            assert_eq!(
                call.matches(',').count(),
                op_sig_src(op).matches(',').count(),
                "{op:?}: call site `{call}` vs signature `{}`",
                op_sig_src(op)
            );
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        let g = DateCalcFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
