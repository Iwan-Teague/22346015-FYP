//! The `token-bucket` family (category `rate-limiting`) — deterministic
//! refill puzzles where *elapsed time* is the data structure.
//!
//! Every puzzle mirrors a real token bucket driven by discrete ticks:
//! `take` refills for the elapsed ticks before deciding, `advance`
//! credits the clamp-limited refill explicitly, `put` returns how many
//! tokens actually fit, and `bucket_cap`/`peek_tokens` expose state any
//! shortcut distorts. The seed picks which two of five ops are
//! required: `bucket_cap`, `take`, `peek_tokens`, `advance`, `put`.
//! Refill must be capped by capacity — every cheat overflows or leaks.

/// One token bucket over integer ticks. Refill credits `rate` tokens
/// per elapsed tick but never pushes the balance above `cap`.
#[derive(Clone)]
pub struct TokenBucketInstance {
    cap: u64,
    rate: u64,
    tokens: u64,
    tick: u64,
}

impl TokenBucketInstance {
    /// A fresh bucket that starts full at tick zero.
    ///
    /// # Panics
    /// Panics when `capacity` or `rate` is zero — a bucket that holds
    /// nothing or refills nothing cannot rate-limit, so it is rejected
    /// up front.
    pub fn new(capacity: u64, rate: u64) -> Self {
        assert!(capacity >= 1, "bucket needs capacity");
        assert!(rate >= 1, "bucket needs a refill rate");
        TokenBucketInstance {
            cap: capacity,
            rate,
            tokens: capacity,
            tick: 0,
        }
    }

    /// The fixed capacity the balance is clamped to.
    pub fn bucket_cap(&self) -> u64 {
        self.cap
    }

    /// The current balance without consuming time.
    pub fn peek_tokens(&self) -> u64 {
        self.tokens
    }

    /// Refills up to `to_tick` (clamped by capacity), moves the clock,
    /// and answers how many tokens the refill actually credited.
    pub fn advance(&mut self, to_tick: u64) -> u64 {
        assert!(to_tick >= self.tick, "time only moves forward");
        let before = self.tokens;
        let gained = (to_tick - self.tick).saturating_mul(self.rate);
        self.tokens = self.cap.min(before.saturating_add(gained));
        self.tick = to_tick;
        self.tokens - before
    }

    /// Refills for the ticks elapsed since the last touch, then tries
    /// to draw `n` tokens: true and deducted when affordable, false
    /// with the balance untouched otherwise.
    pub fn take(&mut self, now: u64, n: u64) -> bool {
        assert!(now >= self.tick, "time only moves forward");
        let gained = (now - self.tick).saturating_mul(self.rate);
        self.tokens = self.cap.min(self.tokens.saturating_add(gained));
        self.tick = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Tops the bucket up manually; answers how many tokens actually
    /// fit (the rest overflow and are discarded).
    pub fn put(&mut self, n: u64) -> u64 {
        let space = self.cap - self.tokens;
        let accepted = space.min(n);
        self.tokens += accepted;
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_full_and_roundtrips() {
        let mut b = TokenBucketInstance::new(10, 2);
        assert_eq!(b.bucket_cap(), 10);
        assert_eq!(b.peek_tokens(), 10);
        assert!(b.take(0, 3));
        assert_eq!(b.peek_tokens(), 7);
        assert!(b.take(0, 7));
        assert_eq!(b.peek_tokens(), 0);
    }

    #[test]
    fn take_refills_with_elapsed_ticks() {
        let mut b = TokenBucketInstance::new(10, 2);
        assert!(b.take(0, 10));
        // One tick elapsed since the drain: two tokens dripped back.
        assert!(b.take(1, 1));
        assert_eq!(b.peek_tokens(), 1);
        // A long sleep refills fully (clamped at ten).
        assert!(b.take(50, 10));
        assert!(!b.take(50, 1));
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let mut b = TokenBucketInstance::new(10, 3);
        assert!(b.take(0, 4));
        assert_eq!(b.advance(1000), 4);
        assert_eq!(b.peek_tokens(), 10);
        assert_eq!(b.advance(2000), 0);
    }

    #[test]
    fn put_discards_overflow_and_reports_accepted() {
        let mut b = TokenBucketInstance::new(8, 1);
        assert_eq!(b.put(100), 0);
        assert!(b.take(0, 6));
        assert_eq!(b.put(100), 6);
        assert_eq!(b.peek_tokens(), 8);
    }

    #[test]
    fn failed_take_leaves_the_balance_untouched() {
        let mut b = TokenBucketInstance::new(10, 2);
        assert!(b.take(0, 8));
        assert_eq!(b.peek_tokens(), 2);
        assert!(!b.take(0, 5));
        assert_eq!(b.peek_tokens(), 2);
        // The failed probe still moved the clock and refilled first
        // (two per tick for three ticks: two plus six is eight), but
        // nine remains unaffordable.
        assert!(!b.take(3, 9));
        assert_eq!(b.peek_tokens(), 8);
    }

    #[test]
    fn soak_matches_a_shadow_bucket_under_random_traffic() {
        let mut b = TokenBucketInstance::new(12, 2);
        let (mut s_tok, mut s_tick) = (12u64, 0u64);
        const CAP: u64 = 12;
        const RATE: u64 = 2;
        let mut st: u64 = 0x5EED_70BE;
        for _ in 0..600u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let draw = st >> 33;
            match draw % 4 {
                0 => {
                    let to = s_tick + (draw >> 2) % 40;
                    let gained = CAP.min(s_tok + to.saturating_sub(s_tick) * RATE) - s_tok;
                    s_tick = to;
                    s_tok += gained;
                    assert_eq!(b.advance(to), gained);
                }
                1 | 2 => {
                    let now = s_tick + (draw >> 2) % 6;
                    let n = (draw >> 8) % 9;
                    s_tok = CAP.min(s_tok + now.saturating_sub(s_tick) * RATE);
                    s_tick = now;
                    let ok = s_tok >= n;
                    if ok {
                        s_tok -= n;
                    }
                    assert_eq!(b.take(now, n), ok);
                }
                _ => {
                    let accepted = (CAP - s_tok).min((draw >> 2) % 15);
                    s_tok += accepted;
                    assert_eq!(b.put((draw >> 2) % 15), accepted);
                }
            }
            assert_eq!(b.peek_tokens(), s_tok);
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    BucketCap,
    Take,
    PeekTokens,
    Advance,
    Put,
}

pub const OP_ALL: [Op; 5] = [
    Op::BucketCap,
    Op::Take,
    Op::PeekTokens,
    Op::Advance,
    Op::Put,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::BucketCap => "bucket_cap",
            Op::Take => "take",
            Op::PeekTokens => "peek_tokens",
            Op::Advance => "advance",
            Op::Put => "put",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::BucketCap => "answers the fixed capacity the balance is clamped to",
            Op::Take => "refills for the elapsed ticks, then answers whether the full draw of n tokens was affordable and deducts it",
            Op::PeekTokens => "answers the current balance without consuming time",
            Op::Advance => "moves the clock forward and answers how many tokens its refill actually credited",
            Op::Put => "tops the bucket up manually and answers how many tokens actually fit",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::BucketCap => "pub fn bucket_cap(&self) -> u64",
            Op::Take => "pub fn take(&mut self, now: u64, n: u64) -> bool",
            Op::PeekTokens => "pub fn peek_tokens(&self) -> u64",
            Op::Advance => "pub fn advance(&mut self, to_tick: u64) -> u64",
            Op::Put => "pub fn put(&mut self, n: u64) -> u64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0x70BE_FA11;

pub fn sample(seed: u64) -> Spec {
    let mut rng = Rng::new(seed);
    let mut idx = [rng.below(5), rng.below(5)];
    while idx[0] == idx[1] {
        idx[1] = rng.below(5);
    }
    idx.sort_unstable();
    Spec {
        ops: [OP_ALL[idx[0] as usize], OP_ALL[idx[1] as usize]],
    }
}

/// Take is the fill primitive every scenario needs — without draws
/// there is nothing to rate-limit; when the seed did not sample it, it
/// ships as given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Take) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Take];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: dozens of pseudo-random draws interleaved
/// with idle stretches, so any solution that forgets the capacity clamp
/// or mis-credits elapsed ticks is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical token-bucket scenario");
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub cap: u64,
    pub rate: u64,
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01B4;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            cap: 8,
            rate: 2,
            warmup: canonical(seed),
        },
        ExampleCase {
            cap: 4,
            rate: 1,
            warmup: 3,
        },
        ExampleCase {
            cap: 6,
            rate: 3,
            warmup: 4,
        },
        ExampleCase {
            cap: 16,
            rate: 5,
            warmup: 17,
        },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..8 {
        let cap = 4u64 << rng.below(3);
        out.push(ExampleCase {
            cap,
            rate: 1 + rng.below(6),
            warmup: rng.below(30) + 1,
        });
    }
    out
}

const NX_MUL: u64 = 6364136223846793005;
const NX_ADD: u64 = 1442695040888963407;

/// One LCG draw.
fn nxt(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    *state >> 33
}

fn drive_init(cap: u64, rate: u64, warmup: u64) -> u64 {
    0x70BE_CAFE
        ^ cap
            .wrapping_mul(0x9E37)
            .wrapping_add(rate.wrapping_mul(0x85E_BCA7))
            .wrapping_add(warmup)
}

/// The drive's LCG state after `warmup` draws. Emitted tests re-derive
/// this to probe one step past the end of the warmup.
fn drive_base(cap: u64, rate: u64, warmup: u64) -> u64 {
    let mut s = drive_init(cap, rate, warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random draws into a fresh bucket; draws both
/// consume tokens and move the clock, so plain take traffic keeps every
/// emitted method inside the ops the seed actually requested.
fn driven_bucket(cap: u64, rate: u64, warmup: u64) -> (TokenBucketInstance, u64) {
    let mut b = TokenBucketInstance::new(cap, rate);
    let mut st = drive_init(cap, rate, warmup);
    let mut tick = 0u64;
    for _ in 0..warmup {
        let v = nxt(&mut st);
        let now = tick + (v >> 2) % 6;
        let n = (v >> 8) % 9;
        b.take(now, n);
        tick = now;
    }
    (b, tick)
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone)]\npub struct Bucket {\n    cap: u64,\n    rate: u64,\n    tokens: u64,\n    tick: u64,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::BucketCap => &["self.cap"],
        Op::PeekTokens => &["self.tokens"],
        Op::Advance => &[
            "assert!(to_tick >= self.tick, \"time only moves forward\");",
            "let before = self.tokens;",
            "let gained = (to_tick - self.tick).saturating_mul(self.rate);",
            "self.tokens = self.cap.min(before.saturating_add(gained));",
            "self.tick = to_tick;",
            "self.tokens - before",
        ],
        Op::Take => &[
            "assert!(now >= self.tick, \"time only moves forward\");",
            "let gained = (now - self.tick).saturating_mul(self.rate);",
            "self.tokens = self.cap.min(self.tokens.saturating_add(gained));",
            "self.tick = now;",
            "if self.tokens >= n {",
            "    self.tokens -= n;",
            "    true",
            "} else {",
            "    false",
            "}",
        ],
        Op::Put => &[
            "let space = self.cap - self.tokens;",
            "let accepted = space.min(n);",
            "self.tokens += accepted;",
            "accepted",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const BUCKET_NEW_SRC: &str = "impl Bucket {\n    pub fn new(capacity: u64, rate: u64) -> Self {\n        assert!(capacity >= 1 && rate >= 1);\n        Bucket {\n            cap: capacity,\n            rate,\n            tokens: capacity,\n            tick: 0,\n        }\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Bucket {", "pub struct BucketRef {", 1);
    s.push_str(
        &BUCKET_NEW_SRC
            .replace("impl Bucket {", "impl BucketRef {")
            .replace("Bucket {\n", "BucketRef {\n"),
    );
    s.push_str("impl BucketRef {\n");
    for &op in &ops {
        let body = op_fn_src(op);
        let renamed = body.replacen(
            &format!("pub fn {}(", op.name()),
            &format!("fn ref_{}(", op.name()),
            1,
        );
        assert!(renamed != body, "rename failed");
        s.push_str(&renamed);
    }
    s.push_str("}\n");
    s
}

pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        let (b, tick) = driven_bucket(ex.cap, ex.rate, ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: capacity {c} at {r} tokens per tick, then {n} pseudo-random operations -> balance {b} at tick {t}\n",
            i = i,
            c = ex.cap,
            r = ex.rate,
            n = ex.warmup,
            b = b.peek_tokens(),
            t = tick
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested token-bucket operations over one\n\
         //! integer-tick bucket. Draws consume the balance, idle ticks\n\
         //! drip it back up to capacity, and every returned value must\n\
         //! match exactly. The hidden tests drive thousands of\n\
         //! interleaved operations and compare every result.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BUCKET_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested token-bucket operations with exact refill accounting.\n\nRequirements:\n- `Bucket::new(capacity, rate)` starts full at tick zero; both arguments are always at least 1.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Time is discrete ticks and moves forward only; each elapsed tick drips `rate` tokens back into the bucket.\n- The balance never rises above capacity: surplus refill credit and manual top-up overflow are discarded, and callers observe exactly how many tokens landed.\n- A failed draw still consumes the elapsed time (the refill lands first), but leaves the balance otherwise untouched.\n- No floating point, no unsafe code; standard library only.\n\nSignatures:\n```rust\n");
    for &op in &effective_ops(spec) {
        s.push_str(op.sig());
        s.push('\n');
    }
    s.push_str("```\n");
    s.push_str(&format!(
        "\nYour answer must still contain the canary string \"{can}\" in its doc comment.\n",
        can = canary
    ));
    s
}

pub fn cargo_toml() -> String {
    "[package]\nname = \"task\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"
        .to_string()
}

pub fn behavior_test_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "use task::Bucket;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let (h, tick_end) = driven_bucket(ex.cap, ex.rate, ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.cap, ex.rate, ex.warmup);
        let tok_now = h.peek_tokens();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Bucket::new({c}, {r});\n    let mut st: u64 = {init};\n    let mut tick: u64 = 0;\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let draw = st >> 33;\n        let now = tick + (draw >> 2) % 6;\n        let want_n = (draw >> 8) % 9;\n        let _ = drive.take(now, want_n);\n        tick = now;\n    }}\n",
            i = i,
            c = ex.cap,
            r = ex.rate,
            init = drive_init(ex.cap, ex.rate, ex.warmup),
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::BucketCap => {
                    s.push_str(&format!("    assert_eq!(r.bucket_cap(), {});\n", ex.cap));
                }
                Op::PeekTokens => {
                    s.push_str(&format!("    assert_eq!(r.peek_tokens(), {tok_now});\n"));
                }
                Op::Take => {
                    let v = nxt(&mut ps);
                    let now = tick_end + (v >> 2) % 6;
                    let n = (v >> 8) % 9;
                    let want = h.clone().take(now, n);
                    s.push_str(&format!("    assert_eq!(r.take({now}, {n}), {want});\n"));
                }
                Op::Advance => {
                    let v = nxt(&mut ps);
                    let to = tick_end + (v >> 2) % 40;
                    let want = h.clone().advance(to);
                    s.push_str(&format!("    assert_eq!(r.advance({to}), {want});\n"));
                }
                Op::Put => {
                    let v = nxt(&mut ps);
                    let n = (v >> 2) % 15;
                    let want = h.clone().put(n);
                    s.push_str(&format!("    assert_eq!(r.put({n}), {want});\n"));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted failed-draw probe: a rejected draw must still land the
    // refill for the elapsed ticks — a solution that skips the clock
    // update on failure freezes the bucket forever.
    if spec.ops.contains(&Op::Take) && spec.ops.contains(&Op::PeekTokens) {
        s.push_str("#[test]\nfn scripted_failed_take_still_moves_the_clock_and_refills() {\n    let mut r = Bucket::new(10, 2);\n    assert!(r.take(0, 8));\n    assert_eq!(r.peek_tokens(), 2);\n    assert!(!r.take(0, 5));\n    assert_eq!(r.peek_tokens(), 2);\n    assert!(!r.take(3, 9));\n    assert_eq!(r.peek_tokens(), 8);\n}\n");
    }
    // Refill soak: alternating idle stretches and draws must keep the
    // balance pinned to a shadow model; only take/advance are called so
    // it ships whenever both ops are present.
    if spec.ops.contains(&Op::Take) && spec.ops.contains(&Op::Advance) {
        s.push_str("#[test]\nfn refill_soak_keeps_the_shadow_balance_clamped() {\n    let mut r = Bucket::new(16, 3);\n    let mut shadow: u64 = 16;\n    let mut tick: u64 = 0;\n    let mut st: u64 = 0x5EED_0000_0000_01B6;\n    for _ in 0..400u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let draw = st >> 33;\n        if draw % 2 == 0 {\n            let to = tick + (draw >> 2) % 30;\n            let gained = 16u64.min(shadow + to.saturating_sub(tick) * 3) - shadow;\n            shadow += gained;\n            tick = to;\n            assert_eq!(r.advance(to), gained);\n        } else {\n            let now = tick + (draw >> 2) % 6;\n            let n = (draw >> 8) % 11;\n            shadow = 16u64.min(shadow + now.saturating_sub(tick) * 3);\n            tick = now;\n            let ok = shadow >= n;\n            if ok {\n                shadow -= n;\n            }\n            assert_eq!(r.take(now, n), ok);\n        }\n        assert!(shadow <= 16);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Bucket;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Bucket::new(24, 3);\n    let mut refr = BucketRef::new(24, 3);\n    let mut tick: u64 = 0;\n");
    if ops.contains(&Op::Take) {
        s.push_str("    assert_eq!(cand.take(4, 6), refr.ref_take(4, 6));\n    tick = 4;\n");
    }
    if ops.contains(&Op::Advance) {
        s.push_str("    assert_eq!(cand.advance(33), refr.ref_advance(33));\n    tick = 33;\n");
    }
    if ops.contains(&Op::Put) {
        s.push_str("    assert_eq!(cand.put(50), refr.ref_put(50));\n");
    }
    if ops.contains(&Op::PeekTokens) {
        s.push_str("    assert_eq!(cand.peek_tokens(), refr.ref_peek_tokens());\n");
    }
    if ops.contains(&Op::BucketCap) {
        s.push_str("    assert_eq!(cand.bucket_cap(), refr.ref_bucket_cap());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01B4;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Take => "{ let now = tick + arg % 6; let n = (arg >> 8) % 9; let a = cand.take(now, n); let b = refr.ref_take(now, n); assert_eq!(a, b); tick = now; }".to_string(),
            Op::Advance => "{ let to = tick + arg % 40; assert_eq!(cand.advance(to), refr.ref_advance(to)); tick = to; }".to_string(),
            Op::Put => "assert_eq!(cand.put(arg % 25), refr.ref_put(arg % 25));".to_string(),
            Op::PeekTokens => "assert_eq!(cand.peek_tokens(), refr.ref_peek_tokens());".to_string(),
            Op::BucketCap => "assert_eq!(cand.bucket_cap(), refr.ref_bucket_cap());".to_string(),
        };
        s.push_str(&format!("            {} => {{ {} }}\n", i, body));
    }
    s.push_str("            _ => { unreachable!() }\n        }\n    }\n}\n");
    s
}

pub fn const_zero_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BUCKET_NEW_SRC);
    s.push_str("impl Bucket {\n");
    for &op in &ops {
        let body = match op {
            Op::BucketCap | Op::PeekTokens | Op::Advance | Op::Put => "0",
            Op::Take => "false",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible unbounded-refill cheat: identical API and clock, but
/// the refill skips the capacity clamp — idle stretches inflate the
/// balance without bound. Singleton draws look right; the balance, the
/// overflow accounting, and every rejection threshold drift afterward.
pub fn unbounded_refill_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(BUCKET_NEW_SRC);
    s.push_str("impl Bucket {\n");
    for &op in &ops {
        if op == Op::Take {
            let body = &[
                "assert!(now >= self.tick, \"time only moves forward\");",
                "let gained = (now - self.tick).saturating_mul(self.rate);",
                "self.tokens = self.tokens.saturating_add(gained);",
                "self.tick = now;",
                "if self.tokens >= n {",
                "    self.tokens -= n;",
                "    true",
                "} else {",
                "    false",
                "}",
            ];
            s.push_str(&format!(
                "{} {{\n    {}\n}}\n",
                op_sig_src(op),
                body.join("\n    ")
            ));
        } else {
            s.push_str(&op_fn_src(op));
        }
    }
    s.push_str("}\n");
    s
}

pub struct TokenBucketFamily;

impl Generator for TokenBucketFamily {
    fn id(&self) -> &'static str {
        "token-bucket"
    }

    fn category(&self) -> &'static str {
        "rate-limiting"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("token-bucket", seed);
        let mut files = std::collections::BTreeMap::new();
        files.insert(std::path::PathBuf::from("Cargo.toml"), cargo_toml());
        files.insert(
            std::path::PathBuf::from("src/lib.rs"),
            skeleton_src(spec, &examples),
        );
        let mut hidden = std::collections::BTreeMap::new();
        hidden.insert(
            std::path::PathBuf::from("tests/behavior.rs"),
            behavior_test_src(spec, &examples),
        );
        hidden.insert(
            std::path::PathBuf::from("tests/differential.rs"),
            differential_test_src(spec),
        );
        GeneratedTask {
            id: format!("token-bucket/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt_src(spec, &canary),
            canary,
            answer_path: String::from("src/lib.rs"),
            files,
            hidden,
            behavior_test: String::from("behavior"),
            differential_test: String::from("differential"),
            alloc_test: String::new(),
            max_unsafe: None,
            forbidden_paths: vec![],
            check_clippy: false,
            clippy_allow: vec![],
            weights: (0.70, 0.20, 0.10),
        }
    }

    fn reference_code(&self, seed: u64) -> String {
        let mut s = String::from(STRUCT_SRC);
        s.push('\n');
        s.push_str(BUCKET_NEW_SRC);
        s.push_str("impl Bucket {\n");
        for &op in &effective_ops(sample(seed)) {
            s.push_str(&op_fn_src(op));
        }
        s.push_str("}\n");
        s
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(spec, &worked_examples(seed))
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero_src(spec)),
            ("unbounded-refill".to_string(), unbounded_refill_src(spec)),
        ]
    }

    fn spec_signature(&self, seed: u64) -> Vec<String> {
        let mut names: Vec<String> = sample(seed)
            .ops
            .iter()
            .map(|op| format!("q:{}", op.name()))
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod gen_tests {
    use super::*;

    const HOUSE_SEEDS: [u64; 7] = [1, 2, 3, 7, 42, 99, 2024];

    #[test]
    fn generation_is_deterministic() {
        let a = TokenBucketFamily.generate(55);
        let b = TokenBucketFamily.generate(55);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(a.files, b.files);
        assert_eq!(a.hidden, b.hidden);
    }

    #[test]
    fn seeds_vary_query_pairs() {
        let mut seen = std::collections::HashSet::new();
        for seed in 0..300u64 {
            seen.insert(sample(seed));
        }
        assert!(seen.len() >= 9, "only {} distinct pairs", seen.len());
    }

    #[test]
    fn canonical_scenarios_stay_bounded() {
        for seed in 0..200u64 {
            let warmup = canonical(seed);
            assert!(warmup >= 24 && warmup.is_multiple_of(8));
            let (b, tick) = driven_bucket(8, 2, warmup);
            assert!(b.peek_tokens() <= 8);
            assert_eq!(b.bucket_cap(), 8);
            assert!(b.clone().take(tick + 3, 1));
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let (b, tick) = driven_bucket(ex.cap, ex.rate, ex.warmup);
                assert!(b.peek_tokens() <= ex.cap);
                assert!(b.clone().take(tick + 1, 0));
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct BucketRef"));
            assert!(!src.contains("pub fn take"));
            assert!(src.contains("pub fn new"));
            let eff = effective_ops(spec);
            for op in OP_ALL {
                let want = eff.contains(&op);
                assert_eq!(
                    src.contains(&format!("fn ref_{}(", op.name())),
                    want,
                    "{:?} misaligned for seed {seed}",
                    op.name()
                );
            }
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let sk = skeleton_src(spec, &worked_examples(seed));
            let canary = mint_canary("token-bucket", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["saturating_mul", ".min(", "self.tick"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("refill"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("BucketRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Take) && spec.ops.contains(&Op::PeekTokens);
            let pins = spec.ops.contains(&Op::Take) && spec.ops.contains(&Op::Advance);
            assert_eq!(
                behavior.contains("scripted_failed_take_still_moves_the_clock_and_refills"),
                scripted,
                "seed {seed}: failed-take soak misaligned"
            );
            assert_eq!(
                behavior.contains("refill_soak_keeps_the_shadow_balance_clamped"),
                pins,
                "seed {seed}: clamp soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_bucket_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = unbounded_refill_src(spec);
        assert!(!cz.contains("saturating"));
        let tk = single.find("fn take").unwrap();
        let te = tk + single[tk..].find("\n}\n").unwrap();
        let tb = &single[tk..te];
        assert!(
            tb.contains("saturating_add(gained)"),
            "cheat must still refill"
        );
        assert!(!tb.contains(".min("), "cheat must skip the capacity clamp");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("token-bucket", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
