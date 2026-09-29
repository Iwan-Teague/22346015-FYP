//! L3 constraint: the hot path must not allocate. A counting global allocator
//! brackets a call to `reverse_windows`; a clone-everything solution (to_vec,
//! Vec::from, iter().collect(), …) allocates and fails, no matter which API it
//! reached for. This is the measured mechanism the design settled on instead of
//! name-blacklisting `clone` (docs/03-oracle.md).

use split_mut_window::reverse_windows;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;
// SAFETY: `Counting` is a zero-sized allocator with no state; `alloc`/
// `dealloc` forward the caller's Layout straight to `System`, which upholds
// the `GlobalAlloc` contract for any valid layout and returns null/panics
// per its documented behavior on invalid ones.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn hot_path_does_not_allocate() {
    // The input Vec is allocated *before* the snapshot, so only allocations
    // performed by reverse_windows itself are counted.
    let mut v: Vec<i64> = (0..256).collect();
    let before = ALLOCS.load(Ordering::SeqCst);
    let n = reverse_windows(&mut v, 7);
    let after = ALLOCS.load(Ordering::SeqCst);
    assert!(n > 0, "expected some full windows");
    assert_eq!(
        after - before,
        0,
        "reverse_windows allocated {} time(s) in the hot path",
        after - before
    );
}
