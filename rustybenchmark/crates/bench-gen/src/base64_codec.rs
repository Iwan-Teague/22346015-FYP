//! The `base64-codec` family (category `wire-encoding`) — streaming
//! bit-packing puzzles where *leftover bits* are the data structure.
//!
//! Every puzzle mirrors a real streaming base64 encoder: `feed` packs
//! bytes into a six-bit-wide pipe and emits one character whenever it
//! fills, `finish` pads the tail with the exact '=' count the fed-byte
//! remainder demands, `char_at`/`out_len` expose the output stream, and
//! `alphabet_at` pins the table itself. The seed picks which two of
//! five ops are required: `out_len`, `feed`, `finish`, `char_at`,
//! `alphabet_at`. Padding must follow the byte remainder mod three —
//! every cheat guesses it from leftover bits or forgets the reset.

/// One streaming base64 encoder over the standard table. Bytes pack
/// into the accumulator six bits at a time; finished output is never
/// rewritten.
#[derive(Clone, Default)]
pub struct Base64Instance {
    out: Vec<u8>,
    acc: u32,
    bits: u32,
    fed: u64,
}

impl Base64Instance {
    pub fn new() -> Self {
        Base64Instance {
            out: Vec::new(),
            acc: 0,
            bits: 0,
            fed: 0,
        }
    }

    /// How many characters the output stream holds so far (padding
    /// included once emitted).
    pub fn out_len(&self) -> u64 {
        self.out.len() as u64
    }

    /// The character at absolute position `index` of the emitted
    /// stream, or None past its end.
    pub fn char_at(&self, index: u64) -> Option<char> {
        self.out.get(index as usize).copied().map(|b| b as char)
    }

    /// The standard-table character for residue `index` (reduced modulo
    /// 64), always in `A-Za-z0-9+/`.
    pub fn alphabet_at(&self, index: u64) -> char {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        TABLE[(index % 64) as usize] as char
    }

    /// Packs one more byte and drains every sextet it completed;
    /// answers how many characters landed in the output (one, two
    /// after a group boundary, or zero).
    pub fn feed(&mut self, byte: u8) -> u64 {
        self.acc = (self.acc << 8) | byte as u32;
        self.bits += 8;
        self.fed += 1;
        let mut emitted = 0u64;
        while self.bits >= 6 {
            self.bits -= 6;
            let sextet = (self.acc >> self.bits) & 0x3F;
            let ch = Self::table(sextet);
            self.out.push(ch as u8);
            emitted += 1;
        }
        emitted
    }

    /// Pads the tail for the bytes fed since the last finish and resets
    /// that remainder counter. Answers how many characters were
    /// appended (a leftover-bits character plus '=' runs) so the whole
    /// segment lands on the four-character boundary.
    pub fn finish(&mut self) -> u64 {
        let mut padded = 0u64;
        if self.bits > 0 {
            let sextet = (self.acc << (6 - self.bits)) & 0x3F;
            let ch = Self::table(sextet);
            self.out.push(ch as u8);
            padded += 1;
            self.bits = 0;
        }
        let pads = match self.fed % 3 {
            1 => 2,
            2 => 1,
            _ => 0,
        };
        for _ in 0..pads {
            self.out.push(b'=');
        }
        padded += pads;
        self.fed = 0;
        padded
    }

    fn table(value: u32) -> char {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        TABLE[value as usize] as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feeds_pack_six_bits_at_a_time() {
        let mut e = Base64Instance::new();
        assert_eq!(e.out_len(), 0);
        assert_eq!(e.feed(b'M'), 1);
        assert_eq!(e.char_at(0), Some('T'));
        assert_eq!(e.feed(b'a'), 1);
        assert_eq!(e.char_at(1), Some('W'));
        // The third byte completes the group: two sextets drain at once.
        assert_eq!(e.feed(b'n'), 2);
        assert_eq!(e.char_at(2), Some('F'));
        assert_eq!(e.char_at(3), Some('u'));
        assert_eq!(e.out_len(), 4);
    }

    #[test]
    fn finish_pads_by_the_fed_remainder() {
        let mut e = Base64Instance::new();
        e.feed(b'a'); // remainder 1 mod 3 -> one tail char + '=='
        assert_eq!(e.finish(), 3);
        assert_eq!(e.out_len(), 4);
        assert_eq!(e.char_at(1), Some('Q'));
        assert_eq!(e.char_at(2), Some('='));
        assert_eq!(e.char_at(3), Some('='));
        // The remainder reset: finishing again appends nothing.
        assert_eq!(e.finish(), 0);
    }

    #[test]
    fn whole_triplets_need_no_padding() {
        let mut e = Base64Instance::new();
        for b in b"Man" {
            e.feed(*b);
        }
        assert_eq!(e.finish(), 0);
        assert_eq!(e.out_len(), 4);
        let word: String = (0..4).map(|i| e.char_at(i).unwrap()).collect();
        assert_eq!(word, "TWFu");
    }

    #[test]
    fn char_at_bounds_and_stream_positions() {
        let mut e = Base64Instance::new();
        assert_eq!(e.char_at(0), None);
        assert_eq!(e.feed(0xFF), 1);
        assert_eq!(e.char_at(0), Some('/'));
        assert_eq!(e.feed(0xFE), 1);
        assert_eq!(e.out_len(), 2);
        assert!(e.char_at(1).is_some());
        assert_eq!(e.char_at(2), None);
        assert_eq!(e.char_at(u64::MAX), None);
    }

    #[test]
    fn alphabet_table_is_standard_and_wraps() {
        let e = Base64Instance::new();
        assert_eq!(e.alphabet_at(0), 'A');
        assert_eq!(e.alphabet_at(25), 'Z');
        assert_eq!(e.alphabet_at(26), 'a');
        assert_eq!(e.alphabet_at(51), 'z');
        assert_eq!(e.alphabet_at(52), '0');
        assert_eq!(e.alphabet_at(61), '9');
        assert_eq!(e.alphabet_at(62), '+');
        assert_eq!(e.alphabet_at(63), '/');
        assert_eq!(e.alphabet_at(64), 'A');
        assert_eq!(e.alphabet_at(127), '/');
    }

    #[test]
    fn soak_matches_a_whole_buffer_encode_under_random_traffic() {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        // Canonical encoding of `raw`: padded to the four-character
        // boundary when `pad`, otherwise the partial group contributes
        // only the whole sextets already flushed by feeds.
        fn canon(raw: &[u8], pad: bool) -> Vec<u8> {
            let mut want = Vec::new();
            for chunk in raw.chunks(3) {
                let word = ((chunk[0] as u32) << 16)
                    | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
                    | (*chunk.get(2).unwrap_or(&0) as u32);
                match chunk.len() {
                    3 => {
                        want.push(TABLE[(word >> 18) as usize & 0x3F]);
                        want.push(TABLE[((word >> 12) & 0x3F) as usize]);
                        want.push(TABLE[((word >> 6) & 0x3F) as usize]);
                        want.push(TABLE[(word & 0x3F) as usize]);
                    }
                    2 => {
                        want.push(TABLE[(word >> 18) as usize & 0x3F]);
                        want.push(TABLE[((word >> 12) & 0x3F) as usize]);
                        if pad {
                            want.push(TABLE[((chunk[1] & 0x0F) << 2) as usize]);
                            want.push(b'=');
                        }
                    }
                    _ => {
                        want.push(TABLE[(word >> 18) as usize & 0x3F]);
                        if pad {
                            want.push(TABLE[((chunk[0] & 0x03) << 4) as usize]);
                            want.push(b'=');
                            want.push(b'=');
                        }
                    }
                }
            }
            want
        }

        let mut e = Base64Instance::new();
        let mut raw: Vec<u8> = Vec::new();
        let mut base = 0u64;
        let mut st: u64 = 0x5EED_BA5E;
        for _ in 0..700u64 {
            st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let draw = st >> 33;
            let mut just_finished = false;
            if draw.is_multiple_of(7) {
                e.finish();
                raw.clear();
                base = e.out_len();
                just_finished = true;
            } else {
                let byte = (draw >> 3) as u8;
                e.feed(byte);
                raw.push(byte);
            }
            // The stream since the last finish must equal the canonical
            // encoding of everything fed in this segment.
            let want = canon(&raw, just_finished);
            assert_eq!(e.out_len() - base, want.len() as u64);
            for (i, &ch) in want.iter().enumerate() {
                assert_eq!(e.char_at(base + i as u64), Some(ch as char));
            }
        }
    }
}

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    OutLen,
    Feed,
    Finish,
    CharAt,
    AlphabetAt,
}

pub const OP_ALL: [Op; 5] = [Op::OutLen, Op::Feed, Op::Finish, Op::CharAt, Op::AlphabetAt];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::OutLen => "out_len",
            Op::Feed => "feed",
            Op::Finish => "finish",
            Op::CharAt => "char_at",
            Op::AlphabetAt => "alphabet_at",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::OutLen => "answers how many characters the emitted stream holds so far",
            Op::Feed => "packs one byte into the pipe and answers how many characters it completed",
            Op::Finish => "pads the tail so the segment lands on the four-character boundary and answers how many characters were appended",
            Op::CharAt => "answers the character at absolute position index of the stream, or None past its end",
            Op::AlphabetAt => "answers the standard-table character for residue index, reduced modulo 64",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::OutLen => "pub fn out_len(&self) -> u64",
            Op::Feed => "pub fn feed(&mut self, byte: u8) -> u64",
            Op::Finish => "pub fn finish(&mut self) -> u64",
            Op::CharAt => "pub fn char_at(&self, index: u64) -> Option<char>",
            Op::AlphabetAt => "pub fn alphabet_at(&self, index: u64) -> char",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

pub const CANONICAL_SEED: u64 = 0xBA5E_FA11;

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

/// Feed is the fill primitive every scenario needs — without bytes
/// there is no stream; when the seed did not sample it, it ships as
/// given infrastructure alongside the pair.
pub fn effective_ops(spec: Spec) -> Vec<Op> {
    if spec.ops.contains(&Op::Feed) {
        spec.ops.to_vec()
    } else {
        let mut v = vec![Op::Feed];
        v.extend_from_slice(&spec.ops);
        v
    }
}

/// The canonical scenario: dozens of pseudo-random feeds punctuated by
/// finishes, so any solution that stalls a group boundary or guesses
/// the '=' count is wrong before the first probe.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let warmup = 16 + rng.below(33);
        if warmup >= 24 && warmup.is_multiple_of(8) {
            return warmup;
        }
    }
    unreachable!("canonical base64-codec scenario");
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub warmup: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_01B8;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase {
            warmup: canonical(seed),
        },
        ExampleCase { warmup: 3 },
        ExampleCase { warmup: 4 },
        ExampleCase { warmup: 17 },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..3 {
        out.push(ExampleCase {
            warmup: rng.below(40) + 1,
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

fn drive_init(warmup: u64) -> u64 {
    0xBA5E_CAFE ^ warmup.wrapping_mul(0x9E37)
}

/// The drive's LCG state after `warmup` draws. Emitted tests re-derive
/// this to probe one step past the end of the warmup.
fn drive_base(warmup: u64) -> u64 {
    let mut s = drive_init(warmup);
    for _ in 0..warmup {
        s = s.wrapping_mul(NX_MUL).wrapping_add(NX_ADD);
    }
    s
}

/// Drives `warmup` pseudo-random feeds; answers the encoder. Plain
/// feed traffic keeps every emitted method inside the ops the seed
/// actually requested (finishes ship only when sampled).
fn driven_encoder(warmup: u64) -> Base64Instance {
    let mut e = Base64Instance::new();
    let mut st = drive_init(warmup);
    for _ in 0..warmup {
        let v = nxt(&mut st);
        e.feed((v >> 3) as u8);
    }
    e
}

// ---- emitted-source fragments -----------------------------------------------

pub const STRUCT_SRC: &str = "#[derive(Clone, Default)]\npub struct Encoder {\n    out: Vec<u8>,\n    acc: u32,\n    bits: u32,\n    fed: u64,\n}\n";

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::OutLen => &["self.out.len() as u64"],
        Op::CharAt => &["self.out.get(index as usize).copied().map(|byte| byte as char)"],
        Op::AlphabetAt => &[
            "const TABLE: &[u8; 64] = b\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";",
            "TABLE[(index % 64) as usize] as char",
        ],
        Op::Feed => &[
            "self.acc = (self.acc << 8) | byte as u32;",
            "self.bits += 8;",
            "self.fed += 1;",
            "let mut emitted = 0u64;",
            "while self.bits >= 6 {",
            "    self.bits -= 6;",
            "    let sextet = (self.acc >> self.bits) & 0x3F;",
            "    let ch = Self::table(sextet);",
            "    self.out.push(ch as u8);",
            "    emitted += 1;",
            "}",
            "emitted",
        ],
        Op::Finish => &[
            "let mut padded = 0u64;",
            "if self.bits > 0 {",
            "    let sextet = (self.acc << (6 - self.bits)) & 0x3F;",
            "    let ch = Self::table(sextet);",
            "    self.out.push(ch as u8);",
            "    padded += 1;",
            "    self.bits = 0;",
            "}",
            "let pads = match self.fed % 3 {",
            "    1 => 2,",
            "    2 => 1,",
            "    _ => 0,",
 "};",
            "for _ in 0..pads {",
            "    self.out.push(b'=');",
            "}",
            "padded += pads;",
            "self.fed = 0;",
            "padded",
        ],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub const ENCODER_NEW_SRC: &str = "impl Encoder {\n    pub fn new() -> Self {\n        Encoder {\n            out: Vec::new(),\n            acc: 0,\n            bits: 0,\n            fed: 0,\n        }\n    }\n\n    fn table(value: u32) -> char {\n        const TABLE: &[u8; 64] = b\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";\n        TABLE[value as usize] as char\n    }\n}\n\n";

pub fn reference_src(spec: Spec) -> String {
    let ops = effective_ops(spec);
    let mut s = STRUCT_SRC.replacen("pub struct Encoder {", "pub struct EncoderRef {", 1);
    s.push_str(
        &ENCODER_NEW_SRC
            .replace("impl Encoder {", "impl EncoderRef {")
            .replace("Encoder {\n", "EncoderRef {\n"),
    );
    s.push_str("impl EncoderRef {\n");
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
        let e = driven_encoder(ex.warmup);
        s.push_str(&format!(
            "//! ex{i}: {n} pseudo-random feeds -> stream of {l} characters\n",
            i = i,
            n = ex.warmup,
            l = e.out_len()
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement the requested streaming base64 operations over one\n\
         //! growing output stream. Bytes pack most-significant-first\n\
         //! through a six-bit-wide pipe, padding follows the fed-byte\n\
         //! remainder exactly, and finished output is never rewritten.\n\
         //! The hidden tests drive thousands of interleaved operations\n\
         //! and compare every returned value and character.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(ENCODER_NEW_SRC);
    for &op in &effective_ops(spec) {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested streaming base64 operations with exact bit-packing and padding.\n\nRequirements:\n- `Encoder::new()` starts with an empty stream; nothing else is preallocated.\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}` {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Use the standard table A-Za-z0-9+/. Bytes enter most-significant-first; every full six-bit group drains immediately as one character, and a single byte can complete two groups across a multiple-of-three boundary.\n- Padding follows the fed-byte remainder since the last finish, never the leftover bits alone: one byte tail pads with two '=', a two-byte tail with one '='. The final partial character carries the remaining bits zero-filled on the right.\n- Finishing resets the remainder counter, so finishing twice appends nothing; already-emitted characters are never rewritten.\n- No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
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
        "use task::Encoder;\n\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n\n",
    );
    for (i, ex) in examples.iter().enumerate() {
        let h = driven_encoder(ex.warmup);
        // Draw the probe arguments exactly one step past the warmup.
        let mut ps = drive_base(ex.warmup);
        let total_out = h.out_len();
        s.push_str(&format!(
            "#[test]\nfn ex{i}_drive() {{\n    let mut drive = Encoder::new();\n    let mut st: u64 = {init};\n    for _ in 0..{n} {{\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let _ = drive.feed(((st >> 33) >> 3) as u8);\n    }}\n",
            i = i,
            init = drive_init(ex.warmup),
            n = ex.warmup
        ));
        for &op in &spec.ops {
            s.push_str("    let mut r = drive.clone();\n");
            match op {
                Op::OutLen => {
                    s.push_str(&format!("    assert_eq!(r.out_len(), {total_out});\n"));
                }
                Op::Feed => {
                    let v = nxt(&mut ps);
                    let b = (v >> 3) as u8;
                    let want = h.clone().feed(b);
                    s.push_str(&format!("    assert_eq!(r.feed({b}), {want});\n"));
                }
                Op::Finish => {
                    let want = h.clone().finish();
                    s.push_str(&format!("    assert_eq!(r.finish(), {want});\n"));
                }
                Op::CharAt => {
                    let v = nxt(&mut ps);
                    let idx = v % 128;
                    let want = h
                        .char_at(idx)
                        .map_or_else(|| "None".to_string(), |c| format!("Some('{c}')"));
                    s.push_str(&format!("    assert_eq!(r.char_at({idx}), {want});\n"));
                    s.push_str(&format!("    assert_eq!(r.char_at({total_out}), None);\n"));
                }
                Op::AlphabetAt => {
                    let v = nxt(&mut ps);
                    let idx = v % 100;
                    let ch = h.alphabet_at(idx);
                    s.push_str(&format!("    assert_eq!(r.alphabet_at({idx}), '{ch}');\n"));
                }
            }
        }
        s.push_str("}\n\n");
    }
    // Scripted padding probe: the '=' count follows the fed-byte
    // remainder — one byte tail pads twice, two bytes once, and a
    // second finish must append nothing at all.
    if spec.ops.contains(&Op::Feed) && spec.ops.contains(&Op::Finish) {
        s.push_str("#[test]\nfn scripted_padding_follows_the_fed_byte_remainder() {\n    let mut r = Encoder::new();\n    assert_eq!(r.finish(), 0);\n    assert_eq!(r.feed(b'a'), 1);\n    assert_eq!(r.finish(), 3);\n    assert_eq!(r.finish(), 0);\n    assert_eq!(r.feed(b'M'), 1);\n    assert_eq!(r.feed(b'a'), 1);\n    assert_eq!(r.finish(), 2);\n    assert_eq!(r.finish(), 0);\n}\n");
    }
    // Fill soak: pure feed traffic must keep the stream length pinned
    // to the running sextet count floor(4k/3).
    if spec.ops.contains(&Op::Feed) && spec.ops.contains(&Op::OutLen) {
        s.push_str("#[test]\nfn fill_soak_tracks_the_stream_length() {\n    let mut r = Encoder::new();\n    let mut fed: u64 = 0;\n    let mut st: u64 = 0x5EED_0000_0000_01BA;\n    for _ in 0..600u64 {\n        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n        let _ = r.feed((st >> 33) as u8);\n        fed += 1;\n        assert_eq!(r.out_len(), 4 * fed / 3);\n    }\n}\n");
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let mut s = String::from("use task::Encoder;\n\n");
    s.push_str(&reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    let ops = effective_ops(spec);
    s.push_str("\n#[test]\nfn differential_tracks_reference_through_identical_op_streams() {\n    let mut cand = Encoder::new();\n    let mut refr = EncoderRef::new();\n");
    if ops.contains(&Op::Feed) {
        s.push_str("    assert_eq!(cand.feed(63), refr.ref_feed(63));\n    assert_eq!(cand.feed(200), refr.ref_feed(200));\n");
    }
    if ops.contains(&Op::Finish) {
        s.push_str("    assert_eq!(cand.finish(), refr.ref_finish());\n    assert_eq!(cand.finish(), refr.ref_finish());\n");
    }
    if ops.contains(&Op::CharAt) {
        s.push_str("    assert_eq!(cand.char_at(0), refr.ref_char_at(0));\n    assert_eq!(cand.char_at(u64::MAX), refr.ref_char_at(u64::MAX));\n");
    }
    if ops.contains(&Op::AlphabetAt) {
        s.push_str("    assert_eq!(cand.alphabet_at(70), refr.ref_alphabet_at(70));\n");
    }
    if ops.contains(&Op::OutLen) {
        s.push_str("    assert_eq!(cand.out_len(), refr.ref_out_len());\n");
    }
    let arm_count = ops.len();
    s.push_str(&format!("    const ARMS: usize = {arm_count};\n    let mut state: u64 = 0xE7EE_ED00_0000_01B8;\n    for _ in 0..3000 {{\n        let arg = nx(&mut state);\n        let pick = (nx(&mut state) as usize) % ARMS;\n        match pick {{\n"));
    for (i, &op) in ops.iter().enumerate() {
        let body = match op {
            Op::Feed => "assert_eq!(cand.feed(arg as u8), refr.ref_feed(arg as u8));".to_string(),
            Op::Finish => "assert_eq!(cand.finish(), refr.ref_finish());".to_string(),
            Op::CharAt => {
                "assert_eq!(cand.char_at(arg % 96), refr.ref_char_at(arg % 96));".to_string()
            }
            Op::AlphabetAt => {
                "assert_eq!(cand.alphabet_at(arg % 128), refr.ref_alphabet_at(arg % 128));"
                    .to_string()
            }
            Op::OutLen => "assert_eq!(cand.out_len(), refr.ref_out_len());".to_string(),
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
    s.push_str(ENCODER_NEW_SRC);
    s.push_str("impl Encoder {\n");
    for &op in &ops {
        let body = match op {
            Op::OutLen | Op::Feed | Op::Finish => "0",
            Op::CharAt => "None",
            Op::AlphabetAt => "'\\0'",
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s.push_str("}\n");
    s
}

/// The plausible lazy-flush cheat: identical API and state, but `feed`
/// emits at most one character per call — a byte that completes a
/// group boundary leaves its second sextet stuck in the accumulator.
/// Singleton feeds look right; every boundary feed and all downstream
/// positions drift from then on.
pub fn lazy_flush_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    let ops = effective_ops(spec);
    s.push_str(STRUCT_SRC);
    s.push('\n');
    s.push_str(ENCODER_NEW_SRC);
    s.push_str("impl Encoder {\n");
    for &op in &ops {
        if op == Op::Feed {
            let body = &[
                "self.acc = (self.acc << 8) | byte as u32;",
                "self.bits += 8;",
                "self.fed += 1;",
                "if self.bits >= 6 {",
                "    self.bits -= 6;",
                "    let sextet = (self.acc >> self.bits) & 0x3F;",
                "    let ch = Self::table(sextet);",
                "    self.out.push(ch as u8);",
                "    return 1;",
                "}",
                "0",
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

pub struct Base64CodecFamily;

impl Generator for Base64CodecFamily {
    fn id(&self) -> &'static str {
        "base64-codec"
    }

    fn category(&self) -> &'static str {
        "wire-encoding"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("base64-codec", seed);
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
            id: format!("base64-codec/{seed:016x}"),
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
        s.push_str(ENCODER_NEW_SRC);
        s.push_str("impl Encoder {\n");
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
            ("lazy-flush".to_string(), lazy_flush_src(spec)),
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
        let a = Base64CodecFamily.generate(55);
        let b = Base64CodecFamily.generate(55);
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
            let e = driven_encoder(warmup);
            assert!(e.out_len() >= 1 && e.out_len() <= 4 * warmup.div_ceil(3));
            assert!(e.clone().finish() <= 3);
        }
    }

    #[test]
    fn worked_examples_agree_with_the_natives() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                let e = driven_encoder(ex.warmup);
                assert!(e.out_len() <= 4 * ex.warmup.div_ceil(3));
                assert!(e.clone().finish() <= 3);
            }
        }
    }

    #[test]
    fn emitted_reference_is_renamed_and_specialized() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            assert!(src.contains("struct EncoderRef"));
            assert!(!src.contains("pub fn feed"));
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
            let canary = mint_canary("base64-codec", seed);
            let prompt = prompt_src(spec, &canary);
            assert_eq!(sk.matches("todo!()").count(), effective_ops(spec).len());
            for token in ["div_ceil", "sextet", "<< 8"] {
                assert!(!sk.contains(token), "leak {token} for seed {seed}");
                assert!(!prompt.contains(token));
            }
            assert!(prompt.contains("padding"));
            assert!(prompt.contains(&canary));
        }
    }

    #[test]
    fn differential_drives_both_types_without_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak seed {seed}");
            assert!(src.contains("EncoderRef::new"));
            assert!(src.contains("differential_tracks_reference_through_identical_op_streams"));
        }
    }

    #[test]
    fn behavior_ships_the_consistency_soaks() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let behavior = behavior_test_src(spec, &worked_examples(seed));
            let scripted = spec.ops.contains(&Op::Feed) && spec.ops.contains(&Op::Finish);
            let pins = spec.ops.contains(&Op::Feed) && spec.ops.contains(&Op::OutLen);
            assert_eq!(
                behavior.contains("scripted_padding_follows_the_fed_byte_remainder"),
                scripted,
                "seed {seed}: padding soak misaligned"
            );
            assert_eq!(
                behavior.contains("fill_soak_matches_the_canonical_stream_length"),
                pins,
                "seed {seed}: canonical soak misaligned"
            );
        }
    }

    #[test]
    fn baselines_mimic_plausible_codec_bugs() {
        let spec = sample(7);
        let cz = const_zero_src(spec);
        let single = lazy_flush_src(spec);
        assert!(!cz.contains("div_ceil"));
        let fd = single.find("fn feed").unwrap();
        let de = fd + single[fd..].find("\n}\n").unwrap();
        let fb = &single[fd..de];
        assert!(fb.contains("if self.bits"), "cheat must still flush");
        assert!(!fb.contains("while self.bits"), "cheat must flush lazily");
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("base64-codec", seed);
            assert!(prompt_src(sample(seed), &canary).contains(&canary));
        }
    }
}
