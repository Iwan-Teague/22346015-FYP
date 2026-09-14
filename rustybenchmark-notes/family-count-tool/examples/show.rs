fn main(){ let a: Vec<String>=std::env::args().collect(); let g=bench_gen::family(&a[1]).unwrap();
 for s in [a[2].parse::<u64>().unwrap(), a[3].parse::<u64>().unwrap()] { let t=g.generate(s); println!("=== seed {s} sig={:?}\n{}", g.spec_signature(s), t.prompt.replace(&t.canary,"<CANARY>")); } }
