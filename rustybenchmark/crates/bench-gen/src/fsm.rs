//! The `fsm` family (category `automata`) — query algorithms over a
//! deterministic finite state machine given as a transition table.
//!
//! The machine is a total function: six states, each with exactly two listed
//! transitions. Where `interval-map` folds ranges and `value-tree` recurses
//! through a tree, this family walks a **graph**: breadth-first search,
//! shortest paths, closure sizes, and cycle detection. The seed prunes which
//! two of five query ops are required: `reachable`, `dist`, `basin`,
//! `cycle_len`, `terminals`. C(5,2) = **10 distinct skills**, above the
//! diversity floor; op names are semantic.
//!
//! Solution-first and correct-by-construction (ADR-0003): the native ops and
//! the emitted reference share one `bfs_levels` frontier fold; the differential
//! fuzzes 3000 random machines against the model.
//!
//! Trivial baselines: `const-zero` (fails every op outright on the canonical
//! machine) and `adjacent-only` (answers from the two immediate transitions,
//! never traversing — exact for `terminals`, which is inherently local, but
//! wrong on the canonical machine for every other op, so every pair catches
//! it through its partner).

use crate::{mint_canary, GeneratedTask, Generator, Rng};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Query menu — two of these five are chosen per seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Op {
    Reachable,
    Dist,
    Basin,
    CycleLen,
    Terminals,
}

const OP_ALL: [Op; 5] = [
    Op::Reachable,
    Op::Dist,
    Op::Basin,
    Op::CycleLen,
    Op::Terminals,
];

/// Machine size, fixed for the whole family.
const N: usize = 6;

impl Op {
    /// The required function name — semantic, not cosmetic.
    fn name(self) -> &'static str {
        match self {
            Op::Reachable => "reachable",
            Op::Dist => "dist",
            Op::Basin => "basin",
            Op::CycleLen => "cycle_len",
            Op::Terminals => "terminals",
        }
    }

    fn ret(self) -> &'static str {
        match self {
            Op::Reachable => "bool",
            Op::Dist | Op::CycleLen => "i64",
            Op::Basin | Op::Terminals => "usize",
        }
    }

    /// True when the op takes a source (and target) state argument.
    fn takes_source(self) -> bool {
        !matches!(self, Op::Terminals)
    }

    fn prose(self) -> &'static str {
        match self {
            Op::Reachable => {
                "whether state `b` can be reached from state `a` by \
                            following any sequence of transitions \
                            (a state reaches itself)"
            }
            Op::Dist => {
                "the length of the shortest path from `a` to `b` in \
                          transitions (0 if `a == b`, -1 if unreachable)"
            }
            Op::Basin => {
                "how many distinct states can be reached from `a`, \
                          including `a` itself"
            }
            Op::CycleLen => {
                "follow the **first** transition of each state starting \
                              from `a`; return how many states form the cycle \
                              eventually entered (always >= 1 because every \
                              state has a transition)"
            }
            Op::Terminals => {
                "how many states list themselves as **both** of their \
                               transitions"
            }
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

type Graph = [[usize; 2]; N];

/// BFS level map: `levels[s]` = shortest distance from `a`, -1 if unseen.
fn bfs_levels(g: &Graph, a: usize) -> Vec<i64> {
    let mut levels = vec![-1i64; N];
    levels[a] = 0;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(a);
    while let Some(s) = queue.pop_front() {
        for &t in &g[s] {
            if levels[t] < 0 {
                levels[t] = levels[s] + 1;
                queue.push_back(t);
            }
        }
    }
    levels
}

fn cycle_length(g: &Graph, a: usize) -> i64 {
    // Walk the first transition until a state repeats; the entered cycle's
    // length is the tail cut off the walked order.
    let mut order: Vec<usize> = Vec::new();
    let mut pos = [usize::MAX; N];
    let mut cur = a;
    while pos[cur] == usize::MAX {
        pos[cur] = order.len();
        order.push(cur);
        cur = g[cur][0];
    }
    (order.len() - pos[cur]) as i64
}

fn terminal_count(g: &Graph) -> usize {
    g.iter()
        .enumerate()
        .filter(|(s, tr)| tr[0] == *s && tr[1] == *s)
        .count()
}

fn op_eval(op: Op, g: &Graph, a: usize, b: usize) -> Out {
    match op {
        Op::Reachable => Out::Bool(bfs_levels(g, a)[b] >= 0),
        Op::Dist => Out::Int(bfs_levels(g, a)[b]),
        Op::Basin => Out::Count(bfs_levels(g, a).iter().filter(|&&l| l >= 0).count()),
        Op::CycleLen => Out::Int(cycle_length(g, a)),
        Op::Terminals => Out::Count(terminal_count(g)),
    }
}

/// A query result, typed because the ops return three different shapes.
#[derive(Clone, Debug, PartialEq)]
enum Out {
    Int(i64),
    Bool(bool),
    Count(usize),
}

impl Out {
    /// The result as emitted-source syntax for behavior-test assertions.
    fn lit(&self) -> String {
        match self {
            Out::Int(x) => x.to_string(),
            Out::Bool(b) => b.to_string(),
            Out::Count(n) => n.to_string(),
        }
    }
}

// ---- canonical machine ------------------------------------------------------

/// Structural facts the canonical machine is required to exhibit, used both to
/// validate the sampled second transitions and to pin non-degenerate answers.
struct Facts {
    cycle_start: usize,
    cycle_next: usize,
    tail_start: usize,
    term: usize,
}

/// The canonical machine: a 3-cycle fed by a 2-state tail plus one terminal
/// state, rotated by the seed. First transitions are pinned; second
/// transitions are sampled and retried until the anchor facts hold.
///
/// Guaranteed for every seed: `cycle_len(anything) == 3`, `terminals() == 1`,
/// `dist(tail_start, cycle_next) == 3`, `reachable(term, cycle_start) ==
/// false`, `basin(term) == 1`, `basin(tail_start) >= 5`.
fn canonical(seed: u64) -> (Graph, Facts) {
    let mut rng = Rng::new(seed ^ 0x3F_5A_A1_70);
    let r = rng.below(N as u64) as usize;
    let c0 = r % N;
    let c1 = (r + 1) % N;
    let c2 = (r + 2) % N;
    let t1 = (r + 3) % N;
    let t0 = (r + 4) % N;
    let term = (r + 5) % N;
    let facts = Facts {
        cycle_start: c0,
        cycle_next: c1,
        tail_start: t0,
        term,
    };
    let mut g = [[0usize; 2]; N];
    g[c0][0] = c1;
    g[c1][0] = c2;
    g[c2][0] = c0;
    g[t1][0] = c0;
    g[t0][0] = t1;
    g[term][0] = term;
    g[term][1] = term;
    // Sampled second transitions, retried until the anchors hold.
    for _ in 0..100_000 {
        let mut cand = g;
        for (s, tr) in cand.iter_mut().enumerate() {
            if s != term {
                let e1 = rng.below(N as u64) as usize;
                tr[1] = e1;
            }
        }
        if anchors_hold(&cand, &facts) {
            return (cand, facts);
        }
    }
    unreachable!("canonical machine sampling failed to satisfy anchors");
}

fn anchors_hold(g: &Graph, f: &Facts) -> bool {
    terminal_count(g) == 1
        && cycle_length(g, f.cycle_start) == 3
        && cycle_length(g, f.tail_start) == 3
        && bfs_levels(g, f.tail_start)[f.cycle_next] == 3
        && bfs_levels(g, f.term)[f.cycle_start] < 0
        && bfs_levels(g, f.term).iter().filter(|&&l| l >= 0).count() == 1
        && bfs_levels(g, f.tail_start)
            .iter()
            .filter(|&&l| l >= 0)
            .count()
            >= 5
}

/// Uniformly random machine from the allowed envelope: every state lists two
/// arbitrary transitions, self-loops and duplicates included.
fn rand_graph(rng: &mut Rng) -> Graph {
    let mut g = [[0usize; 2]; N];
    for tr in g.iter_mut() {
        let e0 = rng.below(N as u64) as usize;
        let e1 = rng.below(N as u64) as usize;
        *tr = [e0, e1];
    }
    g
}

// ---- worked examples --------------------------------------------------------

type ExampleCase = (Graph, Vec<(Op, Out)>, usize, usize);

fn worked_examples(spec: &Spec, seed: u64) -> Vec<ExampleCase> {
    let mut rng = Rng::new(seed ^ 0xE7EE_0000_0000_0046);
    let mut cases: Vec<ExampleCase> = Vec::new();
    // Canonical machine first.
    let (can_g, can_f) = canonical(seed);
    cases.push((
        can_g,
        spec.ops
            .map(|op| (op, op_eval(op, &can_g, can_f.tail_start, can_f.cycle_next)))
            .to_vec(),
        can_f.tail_start,
        can_f.cycle_next,
    ));
    // All-terminal machine: every query collapses to its local answer.
    let sink: Graph = [[0, 0], [1, 1], [2, 2], [3, 3], [4, 4], [5, 5]];
    cases.push((
        sink,
        spec.ops.map(|op| (op, op_eval(op, &sink, 2, 3))).to_vec(),
        2,
        3,
    ));
    for _ in 0..3 {
        let g = rand_graph(&mut rng);
        let a = rng.below(N as u64) as usize;
        let b = rng.below(N as u64) as usize;
        let outs = spec.ops.map(|op| (op, op_eval(op, &g, a, b))).to_vec();
        cases.push((g, outs, a, b));
    }
    cases
}

// ---- emitted-source fragments -----------------------------------------------

/// Render a native graph as emitted-source syntax: `&[[1, 3], [2, 0], ...]`.
fn render_graph(g: &Graph) -> String {
    format!(
        "&[{}]",
        g.iter()
            .map(|tr| format!("[{}, {}]", tr[0], tr[1]))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// One-line indented prose form for prompt readability.
fn prose_graph(g: &Graph) -> String {
    let rows: Vec<String> = g
        .iter()
        .enumerate()
        .map(|(s, tr)| format!("{s}->[{}, {}]", tr[0], tr[1]))
        .collect();
    format!("[{}]", rows.join(", "))
}

/// The shared BFS helper, emitted whenever any graph-walk op runs;
/// `cycle_len` and `terminals` do not need it.
fn bfs_levels_src() -> String {
    "fn bfs_levels(g: &[[usize; 2]; 6], a: usize) -> Vec<i64> {\n\
     \x20   let mut levels = vec![-1i64; 6];\n\
     \x20   levels[a] = 0;\n\
     \x20   let mut queue = std::collections::VecDeque::new();\n\
     \x20   queue.push_back(a);\n\
     \x20   while let Some(s) = queue.pop_front() {\n\
     \x20       for &t in &g[s] {\n\
     \x20           if levels[t] < 0 {\n\
     \x20               levels[t] = levels[s] + 1;\n\
     \x20               queue.push_back(t);\n\
     \x20           }\n\
     \x20       }\n\
     \x20   }\n\
     \x20   levels\n\
     }\n"
    .to_string()
}

fn op_fn_src(op: Op) -> String {
    let name = op.name();
    let ret = op.ret();
    match op {
        Op::Reachable => format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize, b: usize) -> {ret} {{\n\
             \x20   bfs_levels(g, a)[b] >= 0\n\
             }}\n",
            name = name,
            ret = ret,
        ),
        Op::Dist => format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize, b: usize) -> {ret} {{\n\
             \x20   bfs_levels(g, a)[b]\n\
             }}\n",
            name = name,
            ret = ret,
        ),
        Op::Basin => format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize) -> {ret} {{\n\
             \x20   bfs_levels(g, a).iter().filter(|&&level| level >= 0).count()\n\
             }}\n",
            name = name,
            ret = ret,
        ),
        Op::CycleLen => format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize) -> {ret} {{\n\
             \x20   let mut order: Vec<usize> = Vec::new();\n\
             \x20   let mut pos = vec![usize::MAX; 6];\n\
             \x20   let mut cur = a;\n\
             \x20   while pos[cur] == usize::MAX {{\n\
             \x20       pos[cur] = order.len();\n\
             \x20       order.push(cur);\n\
             \x20       cur = g[cur][0];\n\
             \x20   }}\n\
             \x20   (order.len() - pos[cur]) as i64\n\
             }}\n",
            name = name,
            ret = ret,
        ),
        Op::Terminals => format!(
            "pub fn {name}(g: &[[usize; 2]; 6]) -> {ret} {{\n\
             \x20   g.iter().enumerate().filter(|(s, tr)| tr[0] == *s && tr[1] == *s).count()\n\
             }}\n",
            name = name,
            ret = ret,
        ),
    }
}

/// The stub the model must fill in — signature only, `todo!()` body.
fn op_stub_src(op: Op) -> String {
    if op == Op::Terminals {
        "pub fn terminals(g: &[[usize; 2]; 6]) -> usize {\n\
         \x20   todo!()\n\
         }\n"
        .to_string()
    } else if matches!(op, Op::Reachable | Op::Dist) {
        format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize, b: usize) -> {ret} {{\n\
             \x20   todo!()\n\
             }}\n",
            name = op.name(),
            ret = op.ret(),
        )
    } else {
        format!(
            "pub fn {name}(g: &[[usize; 2]; 6], a: usize) -> {ret} {{\n\
             \x20   todo!()\n\
             }}\n",
            name = op.name(),
            ret = op.ret(),
        )
    }
}

/// Bare signature for the prompt's fence (no body, no answer leak).
fn op_sig_src(op: Op) -> String {
    if op == Op::Terminals {
        "pub fn terminals(g: &[[usize; 2]; 6]) -> usize".to_string()
    } else if matches!(op, Op::Reachable | Op::Dist) {
        format!(
            "pub fn {}(g: &[[usize; 2]; 6], a: usize, b: usize) -> {}",
            op.name(),
            op.ret()
        )
    } else {
        format!(
            "pub fn {}(g: &[[usize; 2]; 6], a: usize) -> {}",
            op.name(),
            op.ret()
        )
    }
}

fn reference_src(spec: &Spec) -> String {
    let needs_bfs = spec
        .ops
        .iter()
        .any(|op| matches!(op, Op::Reachable | Op::Dist | Op::Basin));
    let mut s = String::new();
    if needs_bfs {
        s.push_str(&bfs_levels_src());
    }
    for op in spec.ops {
        s.push_str(&op_fn_src(op));
    }
    s
}

/// The call expression for one op in an emitted assertion.
fn call_src(op: Op, graph: &str, a: usize, b: usize) -> String {
    match op {
        Op::Reachable | Op::Dist => format!("{}({}, {}, {})", op.name(), graph, a, b),
        Op::Basin | Op::CycleLen => format!("{}({}, {})", op.name(), graph, a),
        Op::Terminals => format!("{}({})", op.name(), graph),
    }
}

fn worked_examples_prose(spec: &Spec, seed: u64) -> String {
    let mut s = String::new();
    for (g, outs, a, b) in worked_examples(spec, seed) {
        let results = outs
            .iter()
            .map(|(op, out)| format!("{} = {}", op.name(), out.lit()))
            .collect::<Vec<_>>()
            .join(", ");
        let args = if outs.iter().any(|(op, _)| op.takes_source()) {
            format!("  a={}, b={}", a, b)
        } else {
            String::new()
        };
        s.push_str(&format!(
            "  transitions {}{}  ->  {}\n",
            prose_graph(&g),
            args,
            results
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
        "Implement the two query functions in `src/lib.rs`. The machine is \
         given as `transitions`, a `[[usize; 2]; 6]`: `transitions[s]` lists \
         the two destination states available from state `s`. Every state has \
         a transition, so every walk eventually cycles.\n\
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
    for (i, (g, outs, a, b)) in worked_examples(spec, seed).iter().enumerate() {
        body.push_str(&format!(
            "#[test]\nfn ex{i}() {{\n\
             \x20   let transitions = {g};\n",
            g = render_graph(g),
        ));
        for (op, out) in outs {
            body.push_str(&format!(
                "    assert_eq!({call}, {expected});\n",
                call = call_src(*op, "transitions", *a, *b),
                expected = out.lit(),
            ));
        }
        body.push_str("}\n\n");
    }
    body
}

/// The differential's reference — the BFS helper plus the two selected ops,
/// pasted into the test file under `ref_*` names.
fn differential_test_src(spec: &Spec) -> String {
    let reference = reference_src(spec)
        .replacen("pub fn reachable", "fn ref_reachable", 1)
        .replacen("pub fn dist", "fn ref_dist", 1)
        .replacen("pub fn basin", "fn ref_basin", 1)
        .replacen("pub fn cycle_len", "fn ref_cycle_len", 1)
        .replacen("pub fn terminals", "fn ref_terminals", 1);
    format!(
        "use task::{{{imports}}};\n\
         \n\
         {reference}\
         fn nx(state: &mut u64) -> u64 {{\n\
         \x20   *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);\n\
         \x20   *state >> 33\n\
         }}\n\
         \n\
         fn gen_machine(state: &mut u64) -> [[usize; 2]; 6] {{\n\
         \x20   let mut g = [[0usize; 2]; 6];\n\
         \x20   for s in 0..6 {{\n\
         \x20       let e0 = (nx(state) % 6) as usize;\n\
         \x20       let e1 = (nx(state) % 6) as usize;\n\
         \x20       g[s] = [e0, e1];\n\
         \x20   }}\n\
         \x20   g\n\
         }}\n\
         \n\
         #[test]\n\
         fn differential_vs_reference() {{\n\
         \x20   let mut state: u64 = 0xE7EE_ED00_0000_0056;\n\
         \x20   for _ in 0..3000 {{\n\
         \x20       let g = gen_machine(&mut state);\n\
         \x20       let a = (nx(&mut state) % 6) as usize;\n\
         \x20       let b = (nx(&mut state) % 6) as usize;\n\
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
        asserts = spec
            .ops
            .iter()
            .map(|op| {
                let name = op.name();
                let (call, ref_call) = match op {
                    Op::Reachable | Op::Dist => (
                        format!("{name}(&g, a, b)"),
                        format!("ref_{name}(&g, a, b)"),
                    ),
                    Op::Basin | Op::CycleLen => {
                        (format!("{name}(&g, a)"), format!("ref_{name}(&g, a)"))
                    }
                    Op::Terminals => (format!("{name}(&g)"), format!("ref_{name}(&g)")),
                };
                format!(
                    "        assert_eq!({call}, {ref_call});\n",
                    call = call,
                    ref_call = ref_call,
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    )
}

/// Degenerate: everything zero/false.
fn const_zero(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let (sig_args, body) = match op {
                Op::Reachable => (
                    "g: &[[usize; 2]; 6], a: usize, b: usize",
                    "let _ = (g, a, b);\n    false",
                ),
                Op::Dist => (
                    "g: &[[usize; 2]; 6], a: usize, b: usize",
                    "let _ = (g, a, b);\n    0",
                ),
                Op::Basin | Op::CycleLen => {
                    ("g: &[[usize; 2]; 6], a: usize", "let _ = (g, a);\n    0")
                }
                Op::Terminals => ("g: &[[usize; 2]; 6]", "let _ = g;\n    0usize"),
            };
            format!(
                "pub fn {name}({args}) -> {ret} {{\n\
                 \x20   {body}\n\
                 }}\n",
                name = op.name(),
                args = sig_args,
                ret = op.ret(),
                body = body,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

/// The structural cheat: answer from the two immediate transitions only,
/// never traversing further. Exact for `terminals` (inherently local); wrong
/// on the canonical machine for every other op.
fn adjacent_only(spec: &Spec) -> String {
    let fns = spec
        .ops
        .iter()
        .map(|op| {
            let body = match op {
                Op::Reachable => "a == b || g[a].contains(&b)",
                Op::Dist => {
                    "{\n\
                     \x20   if a == b {\n\
                     \x20       0\n\
                     \x20   } else if g[a].contains(&b) {\n\
                     \x20       1\n\
                     \x20   } else {\n\
                     \x20       -1\n\
                     \x20   }\n\
                     \x20 }"
                }
                Op::Basin => {
                    "{\n\
                     \x20   let mut seen = vec![a, g[a][0], g[a][1]];\n\
                     \x20   seen.sort();\n\
                     \x20   seen.dedup();\n\
                     \x20   seen.len()\n\
                     \x20 }"
                }
                Op::CycleLen => {
                    "{\n\
                     \x20   if g[a][0] == a {\n\
                     \x20       1\n\
                     \x20   } else {\n\
                     \x20       2\n\
                     \x20   }\n\
                     \x20 }"
                }
                Op::Terminals => {
                    "g.iter().enumerate().filter(|(s, tr)| tr[0] == *s && tr[1] == *s).count()"
                }
            };
            if *op == Op::Terminals {
                format!(
                    "pub fn terminals(g: &[[usize; 2]; 6]) -> usize {{\n\
                     \x20   {body}\n\
                     }}\n",
                    body = body,
                )
            } else if matches!(op, Op::Reachable | Op::Dist) {
                format!(
                    "pub fn {name}(g: &[[usize; 2]; 6], a: usize, b: usize) -> {ret} {{\n\
                     \x20   {body}\n\
                     }}\n",
                    name = op.name(),
                    ret = op.ret(),
                    body = body,
                )
            } else {
                format!(
                    "pub fn {name}(g: &[[usize; 2]; 6], a: usize) -> {ret} {{\n\
                     \x20   {body}\n\
                     }}\n",
                    name = op.name(),
                    ret = op.ret(),
                    body = body,
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fns
}

pub struct FsmFamily;

impl Generator for FsmFamily {
    fn id(&self) -> &str {
        "fsm"
    }
    fn category(&self) -> &str {
        "automata"
    }

    fn generate(&self, seed: u64) -> GeneratedTask {
        let spec = sample(seed);
        let canary = mint_canary("fsm", seed);

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
            id: format!("fsm/{seed:016x}"),
            category: self.category().to_string(),
            prompt: prompt(&spec, seed, &canary),
            canary,
            answer_path: "src/lib.rs".to_string(),
            files,
            hidden,
            behavior_test: "behavior".to_string(),
            differential_test: "differential".to_string(),
            alloc_test: String::new(),
            // Pure integer bookkeeping — no unsafe anywhere near it.
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
            ("adjacent-only".to_string(), adjacent_only(&spec)),
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
        let g = FsmFamily;
        assert_eq!(g.generate(33).prompt, g.generate(33).prompt);
        assert_eq!(g.generate(33).hidden, g.generate(33).hidden);
    }

    #[test]
    fn native_ops_match_intent() {
        // Two-cycle 0 <-> 1 with a tail 2 -> 0, plus a terminal state 5.
        let g: Graph = [[1, 2], [0, 3], [0, 0], [3, 3], [2, 0], [5, 5]];
        // Reachability spans the whole component {0,1,2,3}; 4 reaches it too.
        assert!(bfs_levels(&g, 0)[1] >= 0);
        assert!(bfs_levels(&g, 4)[3] >= 0);
        assert!(bfs_levels(&g, 0)[5] < 0);
        // Shortest paths: 0 -> 1 direct; 0 -> 3 via 1; 4 -> 3 via 2,0,1.
        assert_eq!(bfs_levels(&g, 0)[1], 1);
        assert_eq!(bfs_levels(&g, 0)[3], 2);
        assert_eq!(bfs_levels(&g, 4)[3], 3);
        assert_eq!(bfs_levels(&g, 3)[3], 0);
        // Basin counts the closure including the source.
        assert_eq!(bfs_levels(&g, 0).iter().filter(|&&l| l >= 0).count(), 4);
        assert_eq!(bfs_levels(&g, 5).iter().filter(|&&l| l >= 0).count(), 1);
        assert_eq!(bfs_levels(&g, 4).iter().filter(|&&l| l >= 0).count(), 5);
        // Cycle lengths along the first transition.
        assert_eq!(cycle_length(&g, 0), 2);
        assert_eq!(cycle_length(&g, 4), 2);
        assert_eq!(cycle_length(&g, 3), 1);
        // Terminal counts states whose BOTH transitions are self loops:
        // here only 3 and 5 qualify ([0,0] leaves state 2).
        assert_eq!(terminal_count(&g), 2);
        let all_sink: Graph = [[0, 0], [1, 1], [2, 2], [3, 3], [4, 4], [5, 5]];
        assert_eq!(terminal_count(&all_sink), 6);
        assert_eq!(cycle_length(&all_sink, 2), 1);
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
        // Both baselines must fail under EVERY pair: const-zero fails all five
        // outright; adjacent-only fails every op except terminals, and every
        // pair containing terminals also carries a separator.
        for seed in 0..200u64 {
            let (g, f) = canonical(seed);
            // Anchor facts the sampler enforces.
            assert_eq!(terminal_count(&g), 1, "seed {seed}");
            assert_eq!(cycle_length(&g, f.cycle_start), 3);
            assert_eq!(cycle_length(&g, f.tail_start), 3);
            assert_eq!(bfs_levels(&g, f.tail_start)[f.cycle_next], 3);
            assert!(bfs_levels(&g, f.term)[f.cycle_start] < 0);
            assert_eq!(
                bfs_levels(&g, f.term).iter().filter(|&&l| l >= 0).count(),
                1
            );
            // const-zero separates everywhere.
            for op in OP_ALL {
                let truth = op_eval(op, &g, f.tail_start, f.cycle_next);
                let zero = match op {
                    Op::Reachable => Out::Bool(false),
                    Op::Dist | Op::CycleLen => Out::Int(0),
                    _ => Out::Count(0),
                };
                assert_ne!(truth, zero, "const-zero survives {op:?} seed {seed}");
            }
            // adjacent-only separates on the canonical probe pair.
            let adj = |op: Op| -> Out {
                match op {
                    Op::Reachable => Out::Bool(
                        f.tail_start == f.cycle_next || g[f.tail_start].contains(&f.cycle_next),
                    ),
                    Op::Dist => Out::Int({
                        if f.tail_start == f.cycle_next {
                            0
                        } else if g[f.tail_start].contains(&f.cycle_next) {
                            1
                        } else {
                            -1
                        }
                    }),
                    Op::Basin => Out::Count({
                        let mut seen = vec![f.tail_start, g[f.tail_start][0], g[f.tail_start][1]];
                        seen.sort();
                        seen.dedup();
                        seen.len()
                    }),
                    Op::CycleLen => Out::Int(if g[f.tail_start][0] == f.tail_start {
                        1
                    } else {
                        2
                    }),
                    Op::Terminals => Out::Count(terminal_count(&g)),
                }
            };
            for op in OP_ALL {
                if op == Op::Terminals {
                    continue; // inherently local; partner op carries the pair
                }
                let truth = op_eval(op, &g, f.tail_start, f.cycle_next);
                assert_ne!(truth, adj(op), "adjacent-only survives {op:?} seed {seed}");
            }
        }
    }

    #[test]
    fn worked_examples_agree_with_eval() {
        for seed in [1u64, 2, 3, 7, 42, 99, 2024] {
            let spec = sample(seed);
            for (g, outs, a, b) in worked_examples(&spec, seed) {
                for (op, out) in outs {
                    assert_eq!(op_eval(op, &g, a, b), out, "seed {seed}");
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
                // Match the `pub fn` line: bare names substring-collide.
                let fn_line = format!("pub fn {}", op.name());
                if spec.ops.contains(&op) {
                    assert!(src.contains(&fn_line));
                } else {
                    assert!(!src.contains(&fn_line), "{:?} leaked", op);
                }
            }
            // The helper appears iff some op walks the graph.
            let needs_bfs = spec
                .ops
                .iter()
                .any(|op| matches!(op, Op::Reachable | Op::Dist | Op::Basin));
            assert_eq!(src.contains("fn bfs_levels("), needs_bfs);
        }
    }

    #[test]
    fn skeleton_and_prompt_stub_out_the_answer() {
        for seed in [0u64, 1, 2] {
            let spec = sample(seed);
            let sk = skeleton_src(&spec, seed);
            assert!(sk.contains("todo!()"), "skeleton must be stubbed");
            assert!(!sk.contains("bfs_levels"), "skeleton leaks the walk");
            assert!(!sk.contains("queue"), "skeleton leaks the walk");
            let p = prompt(&spec, seed, "rb-canary");
            assert!(!p.contains("todo!()"));
            assert!(!p.contains("bfs_levels"));
            assert!(!p.contains("queue"));
            for op in spec.ops {
                assert!(p.contains(&op_sig_src(op)));
            }
        }
    }

    #[test]
    fn call_sites_match_signature_arity() {
        // Regression pin: a catch-all arm once rendered basin(g) without its
        // source argument, breaking every pair that selected it.
        for op in OP_ALL {
            let call = call_src(op, "g", 4, 5);
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
        let g = FsmFamily;
        let t = g.generate(15);
        assert!(t.prompt.contains(&t.canary));
    }
}
