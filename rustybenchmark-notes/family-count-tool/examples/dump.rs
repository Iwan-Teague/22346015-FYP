use std::hash::{Hash,Hasher};
fn main(){ std::panic::set_hook(Box::new(|_|{})); let g=bench_gen::family("collatz").unwrap();
 for s in 0..200_000u64 { let seed=s.wrapping_mul(0x9E37_79B9_7F4A_7C15);
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.generate(seed))) {
   Ok(t)=>{ let mut h=std::collections::hash_map::DefaultHasher::new(); t.prompt.hash(&mut h); t.hidden.hash(&mut h); t.files.hash(&mut h); println!("{seed} {:x}",h.finish()); }
   Err(_)=>println!("{seed} PANIC") } } }
