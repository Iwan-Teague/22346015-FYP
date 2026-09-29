use split_mut_window::reverse_windows;

#[test]
fn even_split() {
    let mut v = [1, 2, 3, 4];
    assert_eq!(reverse_windows(&mut v, 2), 2);
    assert_eq!(v, [2, 1, 4, 3]);
}

#[test]
fn trailing_remainder_untouched() {
    let mut v = [1, 2, 3, 4, 5];
    assert_eq!(reverse_windows(&mut v, 2), 2);
    assert_eq!(v, [2, 1, 4, 3, 5]);
}

#[test]
fn zero_width_is_noop() {
    let mut v = [1, 2, 3];
    assert_eq!(reverse_windows(&mut v, 0), 0);
    assert_eq!(v, [1, 2, 3]);
}

#[test]
fn width_one_is_identity() {
    let mut v = [9, 8, 7];
    assert_eq!(reverse_windows(&mut v, 1), 3);
    assert_eq!(v, [9, 8, 7]);
}

#[test]
fn empty_slice() {
    let mut v: [i64; 0] = [];
    assert_eq!(reverse_windows(&mut v, 3), 0);
}
