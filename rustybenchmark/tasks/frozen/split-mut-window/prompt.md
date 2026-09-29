Implement the function `reverse_windows` in `src/lib.rs`.

```rust
/// Reverse each consecutive, non-overlapping window of width `w` in `v`, in
/// place. Any trailing elements that do not fill a full window are left
/// untouched. Returns the number of full windows reversed.
///
/// Constraints:
/// - `w == 0` must return 0 and leave `v` unchanged (do not panic).
/// - Must not allocate a second copy of the data (no `Vec`, `clone`, `to_vec`).
///
/// Examples:
///   [1,2,3,4], w=2  -> [2,1,4,3], returns 2
///   [1,2,3,4,5], w=2 -> [2,1,4,3,5], returns 2   (5 is a trailing remainder)
///   [1,2,3], w=0    -> [1,2,3], returns 0
pub fn reverse_windows(v: &mut [i64], w: usize) -> usize {
    todo!()
}
```

Return the complete file.
