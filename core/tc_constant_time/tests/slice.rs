use tc_constant_time::{Choice, ConstantTimeEq, fixed_time_eq};

#[test]
fn slices_scan_all_elements_but_can_reveal_public_length_mismatches() {
    use core::cell::Cell;
    struct Counted<'a>(u8, &'a Cell<usize>);
    impl ConstantTimeEq for Counted<'_> {
        fn ct_eq(&self, rhs: &Self) -> Choice {
            self.1.set(self.1.get() + 1);
            self.0.ct_eq(&rhs.0)
        }
    }
    let visits = Cell::new(0);
    let left = [
        Counted(1, &visits),
        Counted(2, &visits),
        Counted(3, &visits),
    ];
    let right = [
        Counted(9, &visits),
        Counted(2, &visits),
        Counted(3, &visits),
    ];
    assert_eq!(left[..].ct_eq(&right[..]).unwrap_u8(), 0);
    assert_eq!(visits.replace(0), 3);
    assert_eq!(left[..].ct_eq(&right[..2]).unwrap_u8(), 0);
    assert_eq!(visits.get(), 0);
    assert_eq!(left[..0].ct_eq(&right[..0]).unwrap_u8(), 1);
    assert_eq!(visits.get(), 0);
    assert!(!fixed_time_eq(b"prefix", b"prefix-extra"));
    assert!(!fixed_time_eq(b"prefix-extra", b"prefix"));
    assert!(fixed_time_eq(b"", b""));
}
