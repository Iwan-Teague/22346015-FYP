use std::collections::HashSet;
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20000);
    let only: Option<String> = std::env::args().nth(2);
    println!("family\tcategory\tdistinct_seen\tdistinct_code\tdistinct_structure\tpanics\tfirst_bad_seed");
    for id in bench_gen::FAMILY_IDS {
        if let Some(o) = &only { if o != id { continue; } }
        let g = bench_gen::family(id).unwrap();
        let (mut seen, mut code, mut sig) = (HashSet::new(), HashSet::new(), HashSet::new());
        let mut panics = 0u64; let mut first_bad: Option<u64> = None;
        for s in 0..n {
            let seed = s.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let t = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.generate(seed))) { Ok(t) => t, Err(_) => { panics += 1; first_bad.get_or_insert(seed); continue; } };
            // what the model sees, minus the per-seed canary marker
            let mut view = t.prompt.replace(&t.canary, "");
            for (p, f) in &t.files { view.push_str(&p.display().to_string()); view.push_str(&f.replace(&t.canary, "")); }
            seen.insert(view);
            code.insert(g.reference_code(seed));
            sig.insert(g.spec_signature(seed).join("|"));
        }
        println!("{}\t{}\t{}\t{}\t{}\t{}\t{:?}", id, g.category(), seen.len(), code.len(), sig.len(), panics, first_bad);
    }
}
