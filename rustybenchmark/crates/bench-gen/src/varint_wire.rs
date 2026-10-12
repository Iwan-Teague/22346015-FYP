//! The `varint-wire` family (category `wire-format`) — byte-level
//! encoding puzzles over one growing output buffer.
//!
//! Every query mirrors a real wire-format primitive over unsigned 64-bit
//! integers: LEB128 varints (seven payload bits per byte, high bit as the
//! continuation flag, little-endian groups) and zigzag (signed values
//! folded onto unsigned so small magnitudes stay short). The seed picks
//! which two of five query ops are required: `encoded_len`,
//! `encode_varint`, `decode_varint`, `zigzag_encode`, `zigzag_decode`.
//! The skill is bit-level layout reasoning — shift/mask discipline,
//! continuation bits, and the sign-fold identity `z = (n << 1) ^ (n >>
//! 63)` — none of which any other family exercises.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops
//! live on [`WireInstance`] over a plain `Vec<u8>` so they are
//! deterministic; the generator built on top of them emits signatures
//! over byte slices where decode must report both the value and how many
//! bytes it consumed, erroring cleanly on truncation.

/// One output buffer mirroring wire state.
pub struct WireInstance(pub Vec<u8>);

impl WireInstance {
    /// Byte length the varint encoding of `v` will occupy: seven bits per
    /// byte, so zero still costs exactly one.
    pub fn encoded_len(&self, v: u64) -> usize {
        let mut v = v;
        let mut len = 1usize;
        while v >= 0x80 {
            v >>= 7;
            len += 1;
        }
        len
    }

    /// Appends the LEB128 varint for `v`: seven little-endian payload
    /// bits per byte, high bit set on every byte but the last. Hands back
    /// the number of bytes appended.
    pub fn encode_varint(&mut self, v: u64) -> u64 {
        let mut v = v;
        let mut written: u64 = 0;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(byte);
                written += 1;
                break;
            }
            self.0.push(byte | 0x80);
            written += 1;
        }
        written
    }

    /// Decodes one varint from the front of the buffer, draining the
    /// consumed bytes; hands back `(value, consumed)`. Truncated input
    /// (a dangling continuation bit) leaves the buffer untouched and
    /// answers `None`.
    pub fn decode_varint(&mut self) -> Option<(u64, usize)> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        for (i, &byte) in self.0.iter().enumerate() {
            value |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                self.0.drain(..=i);
                return Some((value, i + 1));
            }
            shift += 7;
            if shift >= 70 {
                return None;
            }
        }
        None
    }

    /// Folds a signed value onto unsigned: `z = (n << 1) ^ (n >> 63)` —
    /// non-negatives map to even numbers, negatives to odd.
    pub fn zigzag_encode(&self, n: i64) -> u64 {
        ((n << 1) ^ (n >> 63)) as u64
    }

    /// Inverse fold: `n = (z >> 1) as i64 ^ -((z & 1) as i64)`.
    pub fn zigzag_decode(&self, z: u64) -> i64 {
        ((z >> 1) as i64) ^ -((z & 1) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_len_costs_one_byte_per_seven_bits() {
        let w = WireInstance(Vec::new());
        assert_eq!(w.encoded_len(0), 1);
        assert_eq!(w.encoded_len(1), 1);
        assert_eq!(w.encoded_len(127), 1);
        assert_eq!(w.encoded_len(128), 2);
        assert_eq!(w.encoded_len(u64::MAX), 10);
        assert_eq!(w.encoded_len(1 << 63), 10);
    }

    #[test]
    fn encode_appends_leb128_groups() {
        let mut w = WireInstance(Vec::new());
        w.encode_varint(0);
        assert_eq!(w.0, vec![0x00]);
        let mut w = WireInstance(Vec::new());
        w.encode_varint(300);
        assert_eq!(w.0, vec![0xAC, 0x02]);
        let mut w = WireInstance(Vec::new());
        w.encode_varint(u64::MAX);
        assert_eq!(
            w.0,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
        );
    }

    #[test]
    fn decode_drains_exactly_the_consumed_prefix() {
        let mut w = WireInstance(vec![0xAC, 0x02, 0x07]);
        assert_eq!(w.decode_varint(), Some((300, 2)));
        assert_eq!(w.0, vec![0x07]);
        assert_eq!(w.decode_varint(), Some((7, 1)));
        assert!(w.0.is_empty());
    }

    #[test]
    fn truncated_input_answers_none_and_keeps_the_buffer() {
        let mut w = WireInstance(vec![0xAC]);
        assert_eq!(w.decode_varint(), None);
        assert_eq!(w.0, vec![0xAC]);
        // A bare continuation byte never terminates either.
        let mut w = WireInstance(vec![0x80, 0x80]);
        assert_eq!(w.decode_varint(), None);
        assert_eq!(w.0, vec![0x80, 0x80]);
    }

    #[test]
    fn zigzag_folds_non_negatives_even_and_negatives_odd() {
        let w = WireInstance(Vec::new());
        assert_eq!(w.zigzag_encode(0), 0);
        assert_eq!(w.zigzag_encode(-1), 1);
        assert_eq!(w.zigzag_encode(1), 2);
        assert_eq!(w.zigzag_encode(-2), 3);
        assert_eq!(w.zigzag_decode(0), 0);
        assert_eq!(w.zigzag_decode(1), -1);
        assert_eq!(w.zigzag_decode(2), 1);
        assert_eq!(w.zigzag_decode(3), -2);
        assert_eq!(w.zigzag_encode(i64::MIN), u64::MAX);
        assert_eq!(w.zigzag_encode(i64::MAX), u64::MAX - 1);
        assert_eq!(w.zigzag_decode(u64::MAX), i64::MIN);
        assert_eq!(w.zigzag_decode(u64::MAX - 1), i64::MAX);
    }

    #[test]
    fn encode_then_decode_round_trips_every_value() {
        for v in [0u64, 1, 127, 128, 300, 1 << 20, u64::MAX] {
            let mut w = WireInstance(Vec::new());
            w.encode_varint(v);
            assert_eq!(w.0.len(), w.encoded_len(v));
            let (got, used) = w.decode_varint().unwrap();
            assert_eq!((got, used), (v, w.encoded_len(v)));
        }
    }

    #[test]
    fn fresh_buffer_starts_empty() {
        let mut w = WireInstance(Vec::new());
        assert!(w.0.is_empty());
        assert_eq!(w.decode_varint(), None);
    }
}

// ---- generator: op menu, spec, canonical, examples, emitters ---------------

use crate::{mint_canary, GeneratedTask, Generator, Rng};

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    EncodedLen,
    EncodeVarint,
    DecodeVarint,
    ZigzagEncode,
    ZigzagDecode,
}

pub const OP_ALL: [Op; 5] = [
    Op::EncodedLen,
    Op::EncodeVarint,
    Op::DecodeVarint,
    Op::ZigzagEncode,
    Op::ZigzagDecode,
];

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::EncodedLen => "encoded_len",
            Op::EncodeVarint => "encode_varint",
            Op::DecodeVarint => "decode_varint",
            Op::ZigzagEncode => "zigzag_encode",
            Op::ZigzagDecode => "zigzag_decode",
        }
    }

    pub fn prose(self) -> &'static str {
        match self {
            Op::EncodedLen => "the number of bytes the varint for v occupies (seven payload bits per byte; zero costs one)",
            Op::EncodeVarint => "appends the LEB128 varint for v to the buffer — seven little-endian payload bits per byte, high bit set on every byte but the last — and hands back how many bytes it appended",
            Op::DecodeVarint => "decodes one varint from the front of the buffer and drains exactly those bytes, answering Some((value, bytes_consumed)); None when a continuation bit dangles with no terminator",
            Op::ZigzagEncode => "folds a signed value onto unsigned so that non-negatives land on even numbers and negatives land on odd ones, keeping small magnitudes small",
            Op::ZigzagDecode => "unfolds one of those even-or-odd folded values back to its signed form",
        }
    }

    pub fn sig(self) -> &'static str {
        match self {
            Op::EncodedLen => "pub fn encoded_len(v: u64) -> u64",
            Op::EncodeVarint => "pub fn encode_varint(buf: &mut Vec<u8>, v: u64) -> u64",
            Op::DecodeVarint => "pub fn decode_varint(buf: &mut Vec<u8>) -> Option<(u64, usize)>",
            Op::ZigzagEncode => "pub fn zigzag_encode(n: i64) -> u64",
            Op::ZigzagDecode => "pub fn zigzag_decode(z: u64) -> i64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub ops: [Op; 2],
}

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

/// Applies `op` to a fresh wire instance seeded from `input` and returns
/// the (returned, after-buffer) pair the emitted function must produce.
/// For the pure ops the buffer stays empty and `input` is the operand.
fn eval_pair(op: Op, input: u64) -> (u64, Vec<u8>) {
    match op {
        Op::EncodedLen => {
            let w = WireInstance(Vec::new());
            (w.encoded_len(input) as u64, Vec::new())
        }
        Op::EncodeVarint => {
            let mut w = WireInstance(Vec::new());
            let ret = w.encode_varint(input);
            (ret, w.0)
        }
        Op::DecodeVarint => {
            // `input` names a pinned value; decode drains its encoding.
            let mut w = WireInstance(encode_bytes(input));
            let (value, consumed) = w.decode_varint().expect("canonical encoding decodes");
            debug_assert_eq!(value, input);
            (consumed as u64, w.0)
        }
        Op::ZigzagEncode => {
            let w = WireInstance(Vec::new());
            (w.zigzag_encode(input as i64), Vec::new())
        }
        Op::ZigzagDecode => {
            let w = WireInstance(Vec::new());
            (w.zigzag_decode(input) as u64, Vec::new())
        }
    }
}

/// Byte length of `v`'s varint, straight off the native.
fn eval_len(v: u64) -> u64 {
    WireInstance(Vec::new()).encoded_len(v) as u64
}

/// The canonical LEB128 encoding of `v`, off-thread reference bytes.
fn encode_bytes(v: u64) -> Vec<u8> {
    let mut w = WireInstance(Vec::new());
    w.encode_varint(v);
    w.0
}

// ---- canonical case --------------------------------------------------------

const CANONICAL_SEED: u64 = 0x571E_FA11;

/// The canonical value: multi-byte varint (three bytes or more) so
/// single-byte cheats die, zigzag-folded away from the identity cast,
/// and non-zero so const-zero dies everywhere.
pub fn canonical(seed: u64) -> u64 {
    for attempt in 0..100_000u64 {
        let mut rng = Rng::new(seed ^ CANONICAL_SEED.wrapping_add(attempt));
        let v = 16_384 + rng.below(1 << 24);
        if eval_pair(Op::EncodedLen, v).0 >= 3 && eval_pair(Op::ZigzagEncode, v).0 != v && v != 0 {
            return v;
        }
    }
    unreachable!("canonical varint case");
}

fn w_zigzag_encode(n: i64) -> u64 {
    WireInstance(Vec::new()).zigzag_encode(n)
}

// ---- worked examples ---------------------------------------------------------

#[derive(Clone)]
pub struct ExampleCase {
    pub v: u64,
}

const EXAMPLES_SEED: u64 = 0xE7EE_0000_0000_0194;

pub fn worked_examples(seed: u64) -> Vec<ExampleCase> {
    let mut out = vec![
        ExampleCase { v: canonical(seed) },
        ExampleCase { v: 0 },
        ExampleCase { v: 127 },
        ExampleCase { v: 128 },
        ExampleCase { v: 300 },
        ExampleCase { v: u64::MAX },
    ];
    let mut rng = Rng::new(seed ^ EXAMPLES_SEED);
    for _ in 0..3 {
        out.push(ExampleCase {
            v: rng.below(1 << 32),
        });
    }
    out
}

// ---- emitted-source fragments -----------------------------------------------

pub fn op_sig_src(op: Op) -> String {
    op.sig().to_string()
}

pub fn op_stub_src(op: Op) -> String {
    format!("{} {{\n    todo!()\n}}\n", op_sig_src(op))
}

pub fn op_fn_src(op: Op) -> String {
    let body: &[&str] = match op {
        Op::EncodedLen => &[
            "let mut v = v;",
            "let mut len = 1u64;",
            "while v >= 0x80 {",
            "    v >>= 7;",
            "    len += 1;",
            "}",
            "len",
        ],
        Op::EncodeVarint => &[
            "let mut v = v;",
            "let mut written = 0u64;",
            "loop {",
            "    let byte = (v & 0x7F) as u8;",
            "    v >>= 7;",
            "    if v == 0 {",
            "        buf.push(byte);",
            "        written += 1;",
            "        break;",
            "    }",
            "    buf.push(byte | 0x80);",
            "    written += 1;",
            "}",
            "written",
        ],
        Op::DecodeVarint => &[
            "let mut value: u64 = 0;",
            "let mut shift: u32 = 0;",
            "for (i, &byte) in buf.iter().enumerate() {",
            "    value |= ((byte & 0x7F) as u64) << shift;",
            "    if byte & 0x80 == 0 {",
            "        buf.drain(..=i);",
            "        return Some((value, i + 1));",
            "    }",
            "    shift += 7;",
            "    if shift >= 70 {",
            "        return None;",
            "    }",
            "}",
            "None",
        ],
        Op::ZigzagEncode => &["((n << 1) ^ (n >> 63)) as u64"],
        Op::ZigzagDecode => &["((z >> 1) as i64) ^ -((z & 1) as i64)"],
    };
    format!("{} {{\n    {}\n}}\n", op_sig_src(op), body.join("\n    "))
}

pub fn reference_src(spec: Spec) -> String {
    let mut s = String::new();
    for &op in &spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

pub fn worked_examples_prose(examples: &[ExampleCase]) -> String {
    let mut s = String::new();
    for (i, ex) in examples.iter().enumerate() {
        let bytes = encode_bytes(ex.v)
            .iter()
            .map(|b| format!("{:#04x}", b))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!(
            "//! ex{i}: v = {v}; varint bytes [{b}]; encoded_len {l}; zigzag {z}\n",
            i = i,
            v = ex.v,
            b = bytes,
            l = eval_len(ex.v),
            z = w_zigzag_encode(ex.v as i64)
        ));
    }
    s
}

pub fn skeleton_src(spec: Spec, examples: &[ExampleCase]) -> String {
    let mut s = String::from(
        "//! Implement each wire-format function below exactly as specified.\n\
         //! The hidden tests round-trip values through your encoder and\n\
         //! decoder and check every returned byte.\n\
         //!\n",
    );
    s.push_str(&worked_examples_prose(examples));
    s.push('\n');
    for &op in &spec.ops {
        s.push_str(&op_stub_src(op));
    }
    s
}

pub fn prompt_src(spec: Spec, canary: &str) -> String {
    let mut s = String::from(
        "Implement the requested wire-format helpers over unsigned 64-bit integers.\n\nRequirements:\n",
    );
    for &op in &spec.ops {
        s.push_str(&format!("- `{}`: {}.\n", op.name(), op.prose()));
    }
    s.push_str("\nConstraints:\n- Keep the exact function signatures.\n- No unsafe code; standard library only.\n\nSignatures:\n```rust\n");
    for &op in &spec.ops {
        s.push_str(&op_sig_src(op));
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
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    let mut s = format!("use task::{{{}}};\n\n", names.join(", "));
    for (i, ex) in examples.iter().enumerate() {
        let v = ex.v;
        let bytes = encode_bytes(v)
            .iter()
            .map(|b| format!("{:#04x}", b))
            .collect::<Vec<_>>()
            .join(", ");
        s.push_str(&format!("#[test]\nfn ex{i}() {{\n    // v = {v}\n", i = i));
        for &op in &spec.ops {
            match op {
                Op::EncodedLen => s.push_str(&format!(
                    "    assert_eq!(encoded_len({v}u64), {l});\n",
                    l = eval_len(v)
                )),
                Op::EncodeVarint => s.push_str(&format!(
                    "    let mut buf: Vec<u8> = Vec::new();\n    assert_eq!(encode_varint(&mut buf, {v}u64), {l});\n    assert_eq!(buf, vec![{bytes}]);\n",
                    l = eval_len(v)
                )),
                Op::DecodeVarint => s.push_str(&format!(
                    "    let mut buf: Vec<u8> = vec![{bytes}, 0x01];\n    assert_eq!(decode_varint(&mut buf), Some(({v}, {l})));\n    assert_eq!(buf, vec![0x01]);\n",
                    l = eval_len(v)
                )),
                Op::ZigzagEncode => s.push_str(&format!(
                    "    assert_eq!(zigzag_encode({v}u64 as i64), {z});\n",
                    z = w_zigzag_encode(v as i64)
                )),
                Op::ZigzagDecode => s.push_str(&format!(
                    "    assert_eq!(zigzag_decode({z}), {v}u64 as i64);\n",
                    z = w_zigzag_encode(v as i64)
                )),
            }
        }
        s.push_str("}\n\n");
    }
    s
}

/// The reference implementation pasted into the differential target under
/// `ref_*` names, one function per selected op.
fn differential_reference_src(spec: Spec) -> String {
    let mut s = String::new();
    if spec.ops.contains(&Op::DecodeVarint) {
        s.push_str("fn ref_bytes_of(v: u64) -> Vec<u8> {\n    let mut v = v;\n    let mut out = Vec::new();\n    loop {\n        let byte = (v & 0x7F) as u8;\n        v >>= 7;\n        if v == 0 {\n            out.push(byte);\n            break;\n        }\n        out.push(byte | 0x80);\n    }\n    out\n}\n\n");
    }
    for &op in &spec.ops {
        let body = op_fn_src(op);
        let renamed = body.replacen(
            &format!("pub fn {}(", op.name()),
            &format!("fn ref_{}(", op.name()),
            1,
        );
        assert!(renamed != body, "rename failed");
        s.push_str(&renamed);
    }
    s
}

pub fn differential_test_src(spec: Spec) -> String {
    let names: Vec<&str> = spec.ops.iter().map(|o| o.name()).collect();
    let mut s = format!("use task::{{{}}};\n\n", names.join(", "));
    s.push_str(&differential_reference_src(spec));
    s.push_str("\nfn nx(state: &mut u64) -> u64 {\n    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n    *state >> 33\n}\n");
    s.push_str("\n#[test]\nfn differential_vs_reference() {\n    let mut state: u64 = 0xE7EE_ED00_0000_0194;\n    for _ in 0..3000 {\n        let v = nx(&mut state) | (nx(&mut state) << 32);\n");
    for &op in &spec.ops {
        match op {
            Op::EncodedLen => s.push_str("        assert_eq!(encoded_len(v), ref_encoded_len(v));\n"),
            Op::EncodeVarint => s.push_str("        let mut cb: Vec<u8> = Vec::new();\n        let mut rb: Vec<u8> = Vec::new();\n        assert_eq!(encode_varint(&mut cb, v), ref_encode_varint(&mut rb, v));\n        assert_eq!(cb, rb);\n        // Append mode: callers own existing bytes — clobbering them\n        // (or miscounting the appended length) must surface here.\n        let mut cs: Vec<u8> = vec![0x55];\n        let mut rs: Vec<u8> = vec![0x55];\n        assert_eq!(encode_varint(&mut cs, v), ref_encode_varint(&mut rs, v));\n        assert_eq!(cs, rs);\n        assert_eq!(cs.first(), Some(&0x55));\n"),
            Op::DecodeVarint => s.push_str("        let mut cb: Vec<u8> = ref_bytes_of(v);\n        let mut rb: Vec<u8> = ref_bytes_of(v);\n        assert_eq!(decode_varint(&mut cb), ref_decode_varint(&mut rb));\n        assert_eq!(cb, rb);\n        // Truncated prefixes must answer None on both sides and leave\n        // every byte in place — no fabricated values, no silent drain.\n        let full = ref_bytes_of(v);\n        if full.len() > 1 {\n            let cut = full.len() - 1;\n            let mut ct: Vec<u8> = full[..cut].to_vec();\n            let mut rt: Vec<u8> = full[..cut].to_vec();\n            assert_eq!(decode_varint(&mut ct), None);\n            assert_eq!(ref_decode_varint(&mut rt), None);\n            assert_eq!(ct, rt);\n            assert_eq!(ct, full[..cut]);\n        }\n        // Overlong runs of continuation bytes must also answer None\n        // and leave every byte in place — the guarded rejection path.\n        let mut co: Vec<u8> = vec![0x80; 12];\n        let mut ro: Vec<u8> = vec![0x80; 12];\n        assert_eq!(decode_varint(&mut co), None);\n        assert_eq!(ref_decode_varint(&mut ro), None);\n        assert_eq!(co, vec![0x80u8; 12]);\n        assert_eq!(ro, co);\n"),
            Op::ZigzagEncode => s.push_str("        assert_eq!(zigzag_encode(v as i64), ref_zigzag_encode(v as i64));\n"),
            Op::ZigzagDecode => s.push_str("        assert_eq!(zigzag_decode(v), ref_zigzag_decode(v));\n"),
        }
    }
    s.push_str("    }\n}\n");

    // Boundary sweep: every seven-bit edge, both u64 extremes, and the
    // zigzag fold points — probed against the reference in one pass.
    s.push_str("\n#[test]\nfn boundary_sweep_matches_reference() {\n");
    s.push_str("    let bounds: Vec<u64> = vec![0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, u32::MAX as u64, 1u64 << 32, 1u64 << 56, (1u64 << 63) - 1, 1u64 << 63, u64::MAX - 1, u64::MAX];\n");
    s.push_str("    let folds: Vec<i64> = vec![i64::MIN, -1, 0, 1, i64::MAX];\n");
    for &op in &spec.ops {
        match op {
            Op::EncodedLen => s.push_str("    for &v in &bounds {\n        assert_eq!(encoded_len(v), ref_encoded_len(v), \"len drift at {v}\");\n    }\n"),
            Op::EncodeVarint => s.push_str("    for &v in &bounds {\n        let mut cb: Vec<u8> = Vec::new();\n        let mut rb: Vec<u8> = Vec::new();\n        assert_eq!(encode_varint(&mut cb, v), ref_encode_varint(&mut rb, v), \"encode drift at {v}\");\n        assert_eq!(cb, rb);\n    }\n"),
            Op::DecodeVarint => s.push_str("    for &v in &bounds {\n        let mut cb: Vec<u8> = ref_bytes_of(v);\n        let mut rb: Vec<u8> = ref_bytes_of(v);\n        assert_eq!(decode_varint(&mut cb), ref_decode_varint(&mut rb), \"decode drift at {v}\");\n        assert_eq!(cb, rb);\n    }\n"),
            Op::ZigzagEncode => s.push_str("    for &n in &folds {\n        assert_eq!(zigzag_encode(n), ref_zigzag_encode(n), \"fold drift at {n}\");\n    }\n"),
            Op::ZigzagDecode => s.push_str("    for &n in &folds {\n        let z = ref_zigzag_bytes(n);\n        assert_eq!(zigzag_decode(z), n, \"unfold drift at {z}\");\n    }\n"),
        }
    }
    if spec.ops.contains(&Op::ZigzagDecode) {
        s.push_str(
            "\nfn ref_zigzag_bytes(n: i64) -> u64 {\n    ((n << 1) ^ (n >> 63)) as u64\n}\n",
        );
    }
    s.push_str("}\n");

    if spec.ops.contains(&Op::EncodeVarint) && spec.ops.contains(&Op::DecodeVarint) {
        s.push_str("\n#[test]\nfn round_trip_through_candidate_only() {\n    let mut state: u64 = 0x5EED_0000_0000_0194;\n    for _ in 0..1000 {\n        let v = nx(&mut state);\n        let mut buf: Vec<u8> = Vec::new();\n        let written = encode_varint(&mut buf, v);\n        assert_eq!(written as usize, buf.len());\n        let before = buf.clone();\n        let (got, used) = decode_varint(&mut buf).expect(\"round trip decodes\");\n        assert_eq!(got, v);\n        assert_eq!(used, written as usize);\n        assert_eq!(buf.len() + used, before.len());\n        assert!(buf.is_empty());\n    }\n}\n");
    }
    s
}

pub fn const_zero_src(spec: Spec) -> String {
    let mut s = String::from("#![allow(dead_code)]\n\n");
    for &op in &spec.ops {
        let body = match op {
            Op::EncodedLen => "0".to_string(),
            Op::EncodeVarint => "let _ = buf;\n    0".to_string(),
            Op::DecodeVarint => "let _ = buf;\n    None".to_string(),
            Op::ZigzagEncode => "0".to_string(),
            Op::ZigzagDecode => "0".to_string(),
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s
}

/// The plausible truncation cheat: encodes only the low seven bits as a
/// single byte, decodes at most one byte, and casts instead of folding.
/// Exact on tiny values, wrong on the canonical multi-byte case and on
/// every negative zigzag.
pub fn single_byte_src(spec: Spec) -> String {
    let mut s = String::new();
    for &op in &spec.ops {
        let body = match op {
            Op::EncodedLen => "1".to_string(),
            Op::EncodeVarint => "buf.push((v & 0x7F) as u8);\n    1".to_string(),
            Op::DecodeVarint => "if let Some(&b) = buf.first() {\n        buf.clear();\n        Some((b as u64, 1))\n    } else {\n        None\n    }"
                .to_string(),
            Op::ZigzagEncode => "n as u64".to_string(),
            Op::ZigzagDecode => "z as i64".to_string(),
        };
        s.push_str(&format!("{} {{\n    {}\n}}\n", op_sig_src(op), body));
    }
    s
}

pub struct VarintWireFamily;

impl Generator for VarintWireFamily {
    fn id(&self) -> &'static str {
        "varint-wire"
    }

    fn category(&self) -> &'static str {
        "wire-format"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let examples = worked_examples(seed);
        let canary = mint_canary("varint-wire", seed);
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
            id: format!("varint-wire/{seed:016x}"),
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
        reference_src(sample(seed))
    }

    fn skeleton_code(&self, seed: u64) -> String {
        let spec = sample(seed);
        skeleton_src(spec, &worked_examples(seed))
    }

    fn trivial_baselines(&self, seed: u64) -> Vec<(String, String)> {
        let spec = sample(seed);
        vec![
            ("const-zero".to_string(), const_zero_src(spec)),
            ("single-byte".to_string(), single_byte_src(spec)),
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
        let a = VarintWireFamily.generate(33);
        let b = VarintWireFamily.generate(33);
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
    fn canonical_is_multi_byte_and_zigzag_away_from_identity() {
        for seed in 0..200u64 {
            let v = canonical(seed);
            assert!(v >= 16_384);
            assert!(eval_len(v) >= 3, "seed {seed}: canonical too short");
            assert_ne!(
                w_zigzag_encode(v as i64),
                v,
                "seed {seed}: identity cast survives"
            );
            // Round trip through the natives must hold.
            assert_eq!(encode_bytes(v).len() as u64, eval_len(v));
            let mut w = WireInstance(encode_bytes(v));
            assert_eq!(w.decode_varint(), Some((v, eval_len(v) as usize)));
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in HOUSE_SEEDS {
            for ex in worked_examples(seed) {
                assert_eq!(eval_len(ex.v), encode_bytes(ex.v).len() as u64);
            }
        }
    }

    #[test]
    fn emitted_reference_contains_exactly_the_selected_queries() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = reference_src(spec);
            for op in OP_ALL {
                let fn_line = format!("pub fn {}(", op.name());
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
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let sk = skeleton_src(spec, &worked_examples(seed));
            let prompt = prompt_src(spec, &mint_canary("varint-wire", seed));
            assert!(sk.matches("todo!()").count() == spec.ops.len());
            for token in ["0x7F", ">>= 7", ">> 63", "drain(..="] {
                assert!(
                    !sk.contains(token) && !prompt.contains(token),
                    "leak token {token} escaped for seed {seed}"
                );
            }
            for &op in &spec.ops {
                assert!(prompt.contains(op.sig()));
            }
            assert!(prompt.contains(&mint_canary("varint-wire", seed)));
        }
    }

    #[test]
    fn differential_specializes_both_ops_without_generator_leakage() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert!(!src.contains("spec."), "generator leak for seed {seed}");
            for &op in &spec.ops {
                assert!(src.contains(&format!("fn ref_{}(", op.name())));
            }
            for op in OP_ALL {
                if !spec.ops.contains(&op) {
                    assert!(
                        !src.contains(&format!("ref_{}(", op.name())),
                        "unselected {op:?} leaked"
                    );
                }
            }
        }
    }

    #[test]
    fn round_trip_probe_ships_only_when_both_halves_selected() {
        let mut saw_pair = false;
        for seed in 0..300u64 {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            let both = spec.ops.contains(&Op::EncodeVarint) && spec.ops.contains(&Op::DecodeVarint);
            assert_eq!(src.contains("round_trip_through_candidate_only"), both);
            assert_eq!(
                src.contains("Append mode: callers own existing bytes"),
                spec.ops.contains(&Op::EncodeVarint),
                "seed {seed}: append-mode probe misaligned"
            );
            saw_pair |= both;
        }
        assert!(saw_pair);
    }

    #[test]
    fn baselines_mimic_the_classic_wire_misuses() {
        for seed in HOUSE_SEEDS {
            let spec = sample(seed);
            let cz = const_zero_src(spec);
            let sb = single_byte_src(spec);
            assert!(cz.contains("None") || cz.contains("0"));
            // single-byte truncates: never emits a continuation byte.
            if spec.ops.contains(&Op::EncodeVarint) {
                assert!(!sb.contains("| 0x80"));
            }
            if spec.ops.contains(&Op::ZigzagDecode) || spec.ops.contains(&Op::ZigzagEncode) {
                assert!(sb.contains(" as "));
            }
        }
    }

    #[test]
    fn canary_is_in_the_prompt() {
        for seed in HOUSE_SEEDS {
            let canary = mint_canary("varint-wire", seed);
            let prompt = prompt_src(sample(seed), &canary);
            assert!(prompt.contains(&canary));
        }
    }
}

#[cfg(test)]
mod eval_pair_gate {
    use super::*;

    #[test]
    fn eval_pair_routes_through_the_instance_methods() {
        let samples = [0u64, 1, 127, 128, 300, 16_384, u64::MAX];
        for v in samples {
            assert_eq!(eval_pair(Op::EncodedLen, v).0, eval_len(v));
            let (_, after) = eval_pair(Op::EncodeVarint, v);
            assert_eq!(after, encode_bytes(v));
            // Decode consumes exactly its own encoding.
            let (consumed, rest) = eval_pair(Op::DecodeVarint, v);
            assert_eq!(consumed, eval_len(v));
            assert!(rest.is_empty());
            let z = w_zigzag_encode(v as i64);
            assert_eq!(eval_pair(Op::ZigzagEncode, v).0, z);
            // Decoding takes the FOLDED value, not the raw operand.
            assert_eq!(eval_pair(Op::ZigzagDecode, z).0 as i64, v as i64);
        }
    }
}

#[cfg(test)]
mod truncation_probe_gate {
    use super::*;

    #[test]
    fn differential_probes_truncated_input_when_decode_selected() {
        let mut saw = false;
        for seed in 0..300u64 {
            let spec = sample(seed);
            let src = differential_test_src(spec);
            assert_eq!(
                src.contains("Truncated prefixes must answer None"),
                spec.ops.contains(&Op::DecodeVarint),
                "seed {seed}: truncation probe misaligned"
            );
            assert_eq!(
                src.contains("Overlong runs of continuation bytes"),
                spec.ops.contains(&Op::DecodeVarint),
                "seed {seed}: overlong probe misaligned"
            );
            // The boundary sweep ships for EVERY selection: whichever ops
            // are chosen, their seven-bit edges and fold extremes ride.
            assert!(src.contains("boundary_sweep_matches_reference"));
            saw |= spec.ops.contains(&Op::DecodeVarint);
        }
        assert!(saw);
    }
}
