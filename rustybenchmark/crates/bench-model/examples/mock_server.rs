//! Run the in-repo mock endpoint by hand, e.g. to try `rustybench calibrate` without a model:
//!
//! ```text
//! cargo run -p bench-model --features mock --example mock_server -- 8099 [decode_tok_per_s] [seconds]
//! rustybench calibrate --model http://127.0.0.1:8099 --warmup-secs 1 --reps 3 --sustained-secs 3
//! ```

use bench_model::mock::{Behavior, MockServer, ModelSpec};

fn main() {
    let mut a = std::env::args().skip(1);
    let _port: u16 = a.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let decode: f64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(2000.0);
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(120);
    let srv = MockServer::start(vec![Behavior::Model(ModelSpec {
        decode_tok_per_s: decode,
        ..Default::default()
    })]);
    println!("{}", srv.url());
    std::thread::sleep(std::time::Duration::from_secs(secs));
}
