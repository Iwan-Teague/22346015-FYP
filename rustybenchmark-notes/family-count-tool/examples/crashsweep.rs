fn main(){ std::panic::set_hook(Box::new(|_|{})); let n: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
 let ids: Vec<&str> = bench_gen::FAMILY_IDS.to_vec();
 std::thread::scope(|sc| { for chunk in ids.chunks(ids.len().div_ceil(10)) { sc.spawn(move || { for id in chunk { let g=bench_gen::family(id).unwrap(); let mut bad=vec![];
  for s in 0..n { let seed=s.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5bd1e995;
   if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { g.generate(seed); g.reference_code(seed); })).is_err() { bad.push(seed); if bad.len()>=3 {break;} } }
  if !bad.is_empty() { println!("{id}: {:?}", bad); } } }); } }); println!("done"); }
