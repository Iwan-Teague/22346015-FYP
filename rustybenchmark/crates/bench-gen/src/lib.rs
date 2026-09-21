//! `bench-gen` — turns a seed into a fresh problem instance.
//!
//! Tasks are *generators*, not files. A family is a function from a seed to a
//! concrete instance, its reference implementation, its oracle, and the skeleton
//! the model completes — all built from the same seed, **solution-first**, so
//! the oracle is correct by construction (docs/02-task-format.md, ADR-0003).
//!
//! This crate provides seed derivation, canary minting, the `Generator` trait, the
//! distance-aware [`epoch`] sampler, and the family registry ([`FAMILY_IDS`] /
//! [`family`]). Each family draws its *structural* choices from the seed — the
//! operation, not just identifiers — so seeds resist memorisation rather than
//! merely renaming; [`spec_diversity`] counts those distinct skills (Q31).
//! `validate-family` in the CLI runs the compile-dependent construction gates
//! (reference-passes-its-own-oracle, skeleton-fails, baselines-caught); the pure
//! invariants (determinism, canary, category, spec-signature, the diversity floor)
//! are guarded generically over the whole registry in this crate's tests.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod angles;
pub mod atomics_order;
pub mod base64_codec;
pub mod base_convert;
pub mod binary_heap;
pub mod bisect;
pub mod bit_manipulation;
pub mod bitset;
pub mod bloom_filter;
pub mod brackets;
pub mod caesar;
pub mod checked_eval;
pub mod chess;
pub mod clock;
pub mod closure_pipe;
pub mod coins;
pub mod collatz;
pub mod columns;
pub mod complex_plane;

pub mod convert_trait;
pub mod count_min;
pub mod cow_str;
pub mod datecalc;
pub mod deref_wrap;
pub mod dice;
pub mod distance;
pub mod digitroot;
pub mod epoch;
pub mod value_tree;

/// Derive an instance seed from the epoch, task id and index (docs/02):
/// `blake3(epoch || task_id || index)[..8]`. Local/offline runs pass the seed
/// directly instead.
pub fn derive_seed(epoch: &str, task_id: &str, index: u32) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(epoch.as_bytes());
    h.update(&[0u8]);
    h.update(task_id.as_bytes());
    h.update(&[0u8]);
    h.update(&index.to_le_bytes());
    let bytes = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// A unique low-frequency string embedded in the prompt. Its later appearance in
/// a public corpus is direct evidence the instance leaked (docs/02, ADR-0001).
pub fn mint_canary(family: &str, seed: u64) -> String {
    let mut h = blake3::Hasher::new();
    h.update(family.as_bytes());
    h.update(&seed.to_le_bytes());
    let hex = h.finalize().to_hex();
    format!("rb-{}", &hex[..12])
}

/// A small deterministic PRNG (SplitMix64). Generation must be pure in the seed
/// — same seed → byte-identical instance — so we never touch the OS RNG.
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed.wrapping_add(0x9E3779B97F4A7C15),
        }
    }
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// A fully materialised generated task: the model's view, the hidden oracle, the
/// prompt, and the grading configuration derived from the same seed.
pub struct GeneratedTask {
    pub id: String,
    pub category: String,
    pub prompt: String,
    pub canary: String,
    /// Where the model's answer is written, e.g. `src/lib.rs`.
    pub answer_path: String,
    /// Files given to the model (Cargo.toml + skeleton).
    pub files: BTreeMap<PathBuf, String>,
    /// Hidden oracle files (behaviour, differential, alloc tests).
    pub hidden: BTreeMap<PathBuf, String>,
    /// `cargo test --test` target names.
    pub behavior_test: String,
    pub differential_test: String,
    pub alloc_test: String,
    /// L3 AST constraint: max `unsafe` usages. `None` opts the check out entirely
    /// (the constraint layer then reflects only the other checks) — used where
    /// `unsafe` is irrelevant (`idiom-refactor`) or mandatory (`unsafe-core`).
    pub max_unsafe: Option<u32>,
    /// L3 AST constraint: forbidden type/function/method names.
    pub forbidden_paths: Vec<String>,
    /// L3 constraint: run `cargo clippy` on the answer and score its cleanliness
    /// (docs/03 — the idiomaticity signal, dominant for `idiom-refactor`).
    pub check_clippy: bool,
    /// Clippy lints to allow (not counted against cleanliness), e.g.
    /// `clippy::needless_range_loop` where an index loop is legitimate.
    pub clippy_allow: Vec<String>,
    /// Per-category weights (behavior, constraint, quality).
    pub weights: (f32, f32, f32),
}

impl GeneratedTask {
    pub fn instance(&self) -> bench_core::Instance {
        bench_core::Instance {
            prompt: self.prompt.clone(),
            files: self.files.clone(),
            hidden: self.hidden.clone(),
            canary: self.canary.clone(),
        }
    }

    /// The same task with the model's answer replaced by a given source — used
    /// by the validation gates to grade the reference and the skeleton.
    pub fn files_with_answer(&self, answer: &str) -> BTreeMap<PathBuf, String> {
        let mut f = self.files.clone();
        f.insert(PathBuf::from(&self.answer_path), answer.to_string());
        f
    }
}

/// A task family: a deterministic function from seed to instance, plus the two
/// artefacts the validation gates need.
pub trait Generator {
    fn id(&self) -> &str;
    fn category(&self) -> &str;
    /// Generate the instance for `seed`. Must be pure in `seed`.
    fn generate(&self, seed: u64) -> GeneratedTask;
    /// The correct reference implementation for `seed`. Grading it must score
    /// 1.0 (ADR-0003: correct by construction).
    fn reference_code(&self, seed: u64) -> String;
    /// The ablated skeleton (`todo!()`). Grading it must fail.
    fn skeleton_code(&self, seed: u64) -> String;
    /// Degenerate answers (label, code) that have the right shape but the wrong
    /// content. Each must fail grading, or the oracle is too weak. Default: none.
    fn trivial_baselines(&self, _seed: u64) -> Vec<(String, String)> {
        Vec::new()
    }

    /// The structural identity of the task `seed` produces: the generative choices
    /// that define the *skill*, excluding cosmetic variation (identifiers, numeric
    /// constants, worked-example data). Two seeds with the same signature test the
    /// same skill; the count of distinct signatures is the family's genuine task
    /// diversity — the measure that is neither inflatable by example noise nor
    /// deflatable by shared boilerplate (docs/OPEN-QUESTIONS.md Q31). Returned as a
    /// set of feature tokens; order is not significant.
    fn spec_signature(&self, seed: u64) -> Vec<String>;
}

/// The number of distinct [`Generator::spec_signature`]s over `seed = 0..upto` —
/// a family's genuine, ungameable task diversity (Q31). This is a family-quality
/// measure checked at authoring time, distinct from the per-epoch view-distance
/// the sampler enforces to keep served prompts fresh.
pub fn spec_diversity(gen: &dyn Generator, upto: u64) -> usize {
    let mut seen = std::collections::HashSet::new();
    for s in 0..upto {
        let mut sig = gen.spec_signature(s);
        sig.sort();
        seen.insert(sig.join("|"));
    }
    seen.len()
}

/// The minimum [`spec_diversity`] a family must clear to ship — docs/17's
/// "comfortably above [a per-epoch seed count of] 8". Provisional, like
/// `bench_stats::CLUSTER_FLOOR`: the real value is fixed once Phase 4 sets the
/// per-epoch seed count (docs/OPEN-QUESTIONS.md Q30/Q31). Enforced generically over
/// [`FAMILY_IDS`] in this crate's tests; every current family clears it with
/// headroom (the smallest ships at 12).
pub const MIN_SPEC_DIVERSITY: usize = 8;

/// Every registered family id. The run protocol serves these; keep it in sync with
/// [`family`] (a test asserts every id here resolves).
pub const FAMILY_IDS: &[&str] = &[
    "bit-ops",
    "bitset",
    "checked-eval",
    "value-tree",
    "collatz",
    "base-convert",
    "digitroot",
    "datecalc",
    "bisect",
    "clock",
    "coins",
    "complex-plane",
    "angles",
    "caesar",
    "brackets",
    "columns",
    "dice",
    "chess",
    "convert-trait",
    "deref-wrap",
    "closure-pipe",
    "cow-str",
    "count-min-sketch",
    "atomics-order",
    "binary-heap",
    "bloom-filter",
    "base64-codec",
];

/// Look up a family by id.
pub fn family(id: &str) -> Option<Box<dyn Generator>> {
    match id {
        "bit-ops" => Some(Box::new(bit_manipulation::BitManipulationFamily)),
        "bitset" => Some(Box::new(bitset::BitsetFamily)),
        "checked-eval" => Some(Box::new(checked_eval::CheckedEvalFamily)),
        "value-tree" => Some(Box::new(value_tree::ValueTreeFamily)),
        "collatz" => Some(Box::new(collatz::CollatzFamily)),
        "base-convert" => Some(Box::new(base_convert::BaseConvertFamily)),
        "digitroot" => Some(Box::new(digitroot::DigitRootFamily)),
        "datecalc" => Some(Box::new(datecalc::DateCalcFamily)),
        "bisect" => Some(Box::new(bisect::BisectFamily)),
        "clock" => Some(Box::new(clock::ClockFamily)),
        "coins" => Some(Box::new(coins::CoinsFamily)),
        "complex-plane" => Some(Box::new(complex_plane::ComplexPlaneFamily)),
        "angles" => Some(Box::new(angles::AngleFamily)),
        "caesar" => Some(Box::new(caesar::CaesarFamily)),
        "brackets" => Some(Box::new(brackets::BracketsFamily)),
        "columns" => Some(Box::new(columns::ColumnsFamily)),
        "dice" => Some(Box::new(dice::DiceFamily)),
        "chess" => Some(Box::new(chess::ChessFamily)),
        "convert-trait" => Some(Box::new(convert_trait::ConvertTraitFamily)),
        "deref-wrap" => Some(Box::new(deref_wrap::DerefWrapFamily)),
        "closure-pipe" => Some(Box::new(closure_pipe::ClosurePipeFamily)),
        "cow-str" => Some(Box::new(cow_str::CowStrFamily)),
        "count-min-sketch" => Some(Box::new(count_min::CountMinSketchFamily)),
        "atomics-order" => Some(Box::new(atomics_order::AtomicsOrderFamily)),
        "binary-heap" => Some(Box::new(binary_heap::BinaryHeapFamily)),
        "bloom-filter" => Some(Box::new(bloom_filter::BloomFilterFamily)),
        "base64-codec" => Some(Box::new(base64_codec::Base64CodecFamily)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_derivation_is_deterministic() {
        assert_eq!(
            derive_seed("2026-08", "window-op", 3),
            derive_seed("2026-08", "window-op", 3)
        );
        assert_ne!(
            derive_seed("2026-08", "window-op", 3),
            derive_seed("2026-08", "window-op", 4)
        );
    }

    #[test]
    fn canary_is_stable_and_seed_specific() {
        assert_eq!(mint_canary("window-op", 7), mint_canary("window-op", 7));
        assert_ne!(mint_canary("window-op", 7), mint_canary("window-op", 8));
        assert!(mint_canary("window-op", 7).starts_with("rb-"));
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..10 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn seed_derivation_separates_every_axis() {
        // The epoch rotates the whole pool; task id and index partition within it.
        let base = derive_seed("2026-08", "window-op", 3);
        assert_ne!(base, derive_seed("2026-09", "window-op", 3), "epoch");
        assert_ne!(base, derive_seed("2026-08", "error-handling", 3), "task");
        assert_ne!(base, derive_seed("2026-08", "window-op", 4), "index");
        // Index is little-endian bytes: a huge index still yields a u64.
        let _ = derive_seed("e", "t", u32::MAX);
    }

    #[test]
    fn canary_separates_family_and_seed_and_has_fixed_shape() {
        assert_ne!(
            mint_canary("window-op", 7),
            mint_canary("error-handling", 7),
            "families must not share canaries"
        );
        let c = mint_canary("window-op", 7);
        assert!(c.starts_with("rb-"));
        assert_eq!(c.len(), 3 + 12, "12 hex chars after the prefix");
        assert!(c[3..].chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn rng_below_stays_in_range_and_covers() {
        let mut rng = Rng::new(7);
        for _ in 0..500 {
            let v = rng.below(5);
            assert!(v < 5);
        }
        // Degenerate domain: below(1) is constant 0.
        let mut rng = Rng::new(9);
        for _ in 0..20 {
            assert_eq!(rng.below(1), 0);
        }
        // A fair coin must come up both ways within 200 flips.
        let mut rng = Rng::new(11);
        let (mut zeros, mut ones) = (0u32, 0u32);
        for _ in 0..200 {
            match rng.below(2) {
                0 => zeros += 1,
                _ => ones += 1,
            }
        }
        assert!(zeros > 0 && ones > 0, "below(2) collapsed: {zeros}/{ones}");
    }

    #[test]
    fn instance_round_trips_the_model_visible_fields() {
        let g = crate::dice::DiceFamily;
        let t = g.generate(5);
        let i = t.instance();
        assert_eq!(i.prompt, t.prompt);
        assert_eq!(i.files, t.files);
        assert_eq!(i.hidden, t.hidden);
        assert_eq!(i.canary, t.canary);
    }

    #[test]
    fn files_with_answer_swaps_only_the_answer_file() {
        let g = crate::dice::DiceFamily;
        let t = g.generate(5);
        let f = t.files_with_answer("fn answer() {}");
        assert_eq!(f.len(), t.files.len(), "no files added or dropped");
        assert_eq!(
            f.get(std::path::Path::new(&t.answer_path)).unwrap(),
            "fn answer() {}"
        );
        for (p, c) in &t.files {
            if p.to_string_lossy() != t.answer_path {
                assert_eq!(f.get(p), Some(c), "{p:?} must be untouched");
            }
        }
    }

    #[test]
    fn spec_diversity_counts_distinct_signatures_on_value_tree() {
        // value-tree has C(5,2) = 10 query pairs; diversity must see exactly 10.
        let g = crate::value_tree::ValueTreeFamily;
        assert_eq!(crate::spec_diversity(&g, 300), 10);
    }

    #[test]
    fn every_family_id_resolves() {
        // FAMILY_IDS must not drift from the family() registry.
        for id in FAMILY_IDS {
            assert!(
                family(id).is_some(),
                "FAMILY_IDS entry {id} does not resolve"
            );
        }
    }

    #[test]
    fn every_family_meets_the_pure_construction_invariants() {
        // A generic drift-guard over the whole registry: the invariants that need no
        // toolchain (the compile/differential gates stay in `validate-family`). A new
        // family that forgets determinism, its canary, a category, a spec-signature,
        // or enough diversity fails here in `cargo test`, not only in the manual CLI.
        for id in FAMILY_IDS {
            let g = family(id).unwrap();
            assert!(!g.category().is_empty(), "{id}: empty category");
            assert!(
                spec_diversity(g.as_ref(), 4000) >= MIN_SPEC_DIVERSITY,
                "{id}: spec-diversity below the floor of {MIN_SPEC_DIVERSITY}"
            );
            for seed in [0u64, 1, 7, 42, 1000] {
                let a = g.generate(seed);
                let b = g.generate(seed);
                assert_eq!(
                    a.prompt, b.prompt,
                    "{id} seed {seed}: prompt not deterministic"
                );
                assert_eq!(
                    a.files, b.files,
                    "{id} seed {seed}: files not deterministic"
                );
                assert_eq!(
                    a.hidden, b.hidden,
                    "{id} seed {seed}: hidden not deterministic"
                );
                assert!(
                    a.prompt.contains(&a.canary),
                    "{id} seed {seed}: prompt is missing its canary"
                );
                assert!(
                    !g.spec_signature(seed).is_empty(),
                    "{id} seed {seed}: empty spec_signature"
                );
                assert_eq!(
                    a.answer_path, "src/lib.rs",
                    "{id} seed {seed}: answer_path must name the graded file (an \n                     empty one makes the oracle open the workspace root)"
                );
                assert_eq!(
                    a.category,
                    g.category(),
                    "{id} seed {seed}: instance category disagrees with the family"
                );
                assert!(
                    a.id.starts_with(&format!("{id}/")),
                    "{id} seed {seed}: task id does not carry the registry family id"
                );
                assert_eq!(
                    a.canary,
                    mint_canary(id, seed),
                    "{id} seed {seed}: canary is not derived from the registry family id"
                );
                for key in ["tests/behavior.rs", "tests/differential.rs"] {
                    assert!(
                        a.hidden.contains_key(&std::path::PathBuf::from(key)),
                        "{id} seed {seed}: hidden tests missing {key}"
                    );
                }
            }
        }
    }

    #[test]
    fn spec_diversity_is_the_structural_count() {
        // The honest, ungameable task-diversity ceiling (Q31): distinct structural
        // specs, constants excluded. Pinned so narrowing a surface fails loudly.
        // Families built on the shared combinator scaffolding sit at 10; bit-ops
        // crosses 5 masks with 4 transforms.
        for id in ["angles", "atomics-order", "base64-codec", "base-convert",
                   "binary-heap", "bisect", "bitset", "bloom-filter", "brackets",
                   "caesar", "chess", "clock", "closure-pipe",
                   "coins", "collatz", "columns", "complex-plane", "convert-trait",
                   "count-min-sketch", "cow-str", "datecalc", "deref-wrap",
                   "digitroot", "dice", "value-tree"] {
            assert_eq!(
                spec_diversity(family(id).unwrap().as_ref(), 4000),
                10,
                "{id} narrowed"
            );
        }
        // checked-eval = 12 structural specs; bit-ops = 5 masks x 4 transforms.
        assert_eq!(
            spec_diversity(family("checked-eval").unwrap().as_ref(), 4000),
            12
        );
        assert_eq!(
            spec_diversity(family("bit-ops").unwrap().as_ref(), 4000),
            20
        );
    }

    /// Pull the hex literal from a differential LCG binding.
    fn scan_state_constants(src: &str) -> Vec<String> {
        let marker = "let mut state: u64 = ";
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(pos) = src[from..].find(marker) {
            let mut start = from + pos + marker.len();
            if start >= src.len() {
                break;
            }
            // Skip an explicit `0x` prefix before collecting digits.
            for c in src[start..].chars() {
                if c.is_whitespace() {
                    start += 1;
                } else {
                    if c == '0' {
                        start += 1;
                    }
                    break;
                }
            }
            if start < src.len() && src[start..].starts_with('x') {
                start += 1;
            }
            let tail: String = src[start..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
                .collect();
            let norm = tail.replace('_', "").to_ascii_lowercase();
            if !norm.is_empty() {
                out.push(norm);
            }
            from = start;
        }
        out
    }

    /// Pull the hex literal from every `const NAME: u64 = 0x…;` binding.
    fn scan_named_hex_consts(src: &str, name: &str) -> Vec<String> {
        let marker = format!("const {name}: u64 = ");
        let mut out = Vec::new();
        let mut from = 0;
        while let Some(pos) = src[from..].find(&marker) {
            let mut start = from + pos + marker.len();
            if start >= src.len() {
                break;
            }
            // Skip an explicit `0x` prefix before collecting digits.
            for c in src[start..].chars() {
                if c.is_whitespace() {
                    start += 1;
                } else {
                    if c == '0' {
                        start += 1;
                    }
                    break;
                }
            }
            if start < src.len() && src[start..].starts_with('x') {
                start += 1;
            }
            let tail: String = src[start..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == '_')
                .collect();
            let norm = tail.replace('_', "").to_ascii_lowercase();
            if !norm.is_empty() {
                out.push(norm);
            }
            from = start;
        }
        out
    }

    #[test]
    fn every_lookup_arm_is_listed_in_family_ids() {
        // The reverse of `every_family_id_resolves`: a Generator wired
        // into `family()` but missing from FAMILY_IDS compiles fine and
        // is silently invisible to suite runs. Parse the arms straight
        // out of this file so neither side can drift alone.
        let src = include_str!("lib.rs");
        let mut arms = Vec::new();
        for line in src.lines() {
            let t = line.trim_start();
            if !t.starts_with('"') {
                continue;
            }
            if let Some((id, _)) = t.split_once("\" => Some(Box::new(") {
                arms.push(id.trim_matches('"').to_string());
            }
        }
        assert!(
            arms.len() >= 20,
            "arm parsing drifted — found {} arms",
            arms.len()
        );
        for id in &arms {
            assert!(
                FAMILY_IDS.contains(&id.as_str()),
                "family() arm {id} is missing from FAMILY_IDS"
            );
        }
        assert_eq!(arms.len(), FAMILY_IDS.len(), "registry sizes diverged");
    }

    #[test]
    fn differential_state_constants_are_unique_across_families() {
        // The bitset/matrix collision class (fixed in 2da6ca7): two
        // families sharing a differential LCG initial state fuzz
        // identical streams, quietly correlating their differentials.
        // Every family's emitted differential binds `let mut state:
        // u64 = 0x…;`, so demand global uniqueness of those literals.
        let mut owner: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for entry in std::fs::read_dir("src").expect("bench-gen src/ must be readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).unwrap();
            for hex in scan_state_constants(&text) {
                if let Some(prev) = owner.insert(hex.clone(), file.clone()) {
                    assert!(
                        prev == file,
                        "differential state {hex} declared in both {prev} \
                         and {file} — fuzz streams would collide"
                    );
                }
            }
        }
        assert!(
            owner.len() >= FAMILY_IDS.len(),
            "found only {} distinct differential states across {} families \
             — scanning likely drifted",
            owner.len(),
            FAMILY_IDS.len()
        );
    }

    #[test]
    fn canonical_seed_constants_are_unique_across_families() {
        // CANONICAL_SEED picks the canonical worked example inside each
        // family; two families sharing one would emit identical canonical
        // tasks whenever their op pairs line up. Demand global uniqueness
        // of every `const CANONICAL_SEED: u64 = 0x…;` literal.
        let mut owner: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut declared = 0usize;
        for entry in std::fs::read_dir("src").expect("bench-gen src/ must be readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).unwrap();
            for hex in scan_named_hex_consts(&text, "CANONICAL_SEED") {
                declared += 1;
                if let Some(prev) = owner.insert(hex.clone(), file.clone()) {
                    assert!(
                        prev == file,
                        "CANONICAL_SEED {hex} declared in both {prev} and {file} \
                         — canonical examples would collide"
                    );
                }
            }
        }
        assert!(
            declared >= 25,
            "only {declared} CANONICAL_SEED consts found — scanning likely drifted"
        );
    }

    #[test]
    fn examples_seed_constants_are_unique_across_families() {
        // EXAMPLES_SEED derives the non-canonical worked examples; a shared
        // value would correlate the corner-case batteries of two families.
        // Same class as the differential-state collision fixed in 2da6ca7.
        let mut owner: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut declared = 0usize;
        for entry in std::fs::read_dir("src").expect("bench-gen src/ must be readable") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).unwrap();
            for hex in scan_named_hex_consts(&text, "EXAMPLES_SEED") {
                declared += 1;
                if let Some(prev) = owner.insert(hex.clone(), file.clone()) {
                    assert!(
                        prev == file,
                        "EXAMPLES_SEED {hex} declared in both {prev} and {file} \
                         — worked-example batteries would collide"
                    );
                }
            }
        }
        assert!(
            declared >= 25,
            "only {declared} EXAMPLES_SEED consts found — scanning likely drifted"
        );
    }
}

