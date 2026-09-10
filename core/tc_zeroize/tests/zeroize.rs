//! Functional checks through the public API; these do not prove code generation.

use core::cell::Cell;
use core::mem::MaybeUninit;
use tc_zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

macro_rules! integer_tests {
    ($($name:ident: $ty:ty),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                for mut value in [<$ty>::MIN, 0, 1, <$ty>::MAX] {
                    value.zeroize();
                    assert_eq!(value, 0);
                    value.zeroize();
                    assert_eq!(value, 0);
                }
            }
        )+
    };
}

integer_tests! {
    u8_values: u8, u16_values: u16, u32_values: u32,
    u64_values: u64, u128_values: u128, usize_values: usize,
    i8_values: i8, i16_values: i16, i32_values: i32,
    i64_values: i64, i128_values: i128, isize_values: isize,
}

#[test]
fn bool_values() {
    for mut value in [true, false] {
        value.zeroize();
        assert!(!value);
    }
}

#[test]
fn char_values() {
    for mut value in ['\0', 'a', '\u{d7ff}', '\u{e000}', char::MAX] {
        value.zeroize();
        assert_eq!(value, '\0');
    }
}

#[test]
fn arrays_clear_every_element_and_keep_their_length() {
    let mut value = [[1_u32, 0, u32::MAX], [7, 8, 9]];
    value.zeroize();
    assert_eq!(value, [[0; 3]; 2]);
}

#[test]
fn empty_arrays() {
    let mut value: [u8; 0] = [];
    value.zeroize();
    assert_eq!(value, []);
}

#[test]
fn slices_clear_only_the_borrowed_range() {
    let mut value = [1_u64, 2, 0, u64::MAX, 5];
    value[1..4].zeroize();
    assert_eq!(value, [1, 0, 0, 0, 5]);
}

#[test]
fn empty_slices() {
    let mut value = [9_u8];
    value[..0].zeroize();
    assert_eq!(value, [9]);
}

#[test]
fn maybe_uninit_initialized_and_uninitialized_integers() {
    for mut value in [MaybeUninit::new(u64::MAX), MaybeUninit::<u64>::uninit()] {
        value.zeroize();
        // SAFETY: The zero store initialized every byte of padding-free `u64`,
        // and zero is a valid `u64` value.
        assert_eq!(unsafe { value.assume_init() }, 0);
    }
}

#[test]
fn maybe_uninit_arrays_and_slices() {
    let mut values = [MaybeUninit::new(u8::MAX); 4];
    values.zeroize();
    for value in values {
        // SAFETY: The zero store initialized this padding-free byte.
        assert_eq!(unsafe { value.assume_init() }, 0);
    }
    let mut values = [MaybeUninit::<u8>::uninit(); 4];
    values.as_mut_slice().zeroize();
    for value in values {
        // SAFETY: The zero store initialized this padding-free byte.
        assert_eq!(unsafe { value.assume_init() }, 0);
    }
    let mut empty: [MaybeUninit<u8>; 0] = [];
    empty.zeroize();
}

// Observe the still-live payload inside its destructor, never freed storage.
struct DropProbe<'a> {
    secret: [u8; 4],
    wipes: &'a Cell<usize>,
    drops: &'a Cell<usize>,
}

impl Zeroize for DropProbe<'_> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.wipes.set(self.wipes.get() + 1);
    }
}

impl Drop for DropProbe<'_> {
    fn drop(&mut self) {
        assert_eq!(self.secret, [0; 4]);
        self.drops.set(self.drops.get() + 1);
    }
}

#[test]
fn option_clears_before_dropping_its_payload_and_becoming_none() {
    let wipes = Cell::new(0);
    let drops = Cell::new(0);
    let mut value = Some(DropProbe {
        secret: [7; 4],
        wipes: &wipes,
        drops: &drops,
    });
    value.zeroize();
    assert!(value.is_none());
    assert_eq!(wipes.get(), 1);
    assert_eq!(drops.get(), 1);
    value.zeroize();
    assert_eq!(wipes.get(), 1);
    assert_eq!(drops.get(), 1);
}

#[test]
fn option_none_stays_none() {
    let mut value: Option<[u32; 4]> = None;
    value.zeroize();
    assert_eq!(value, None);
}

#[test]
fn arrays_and_slices_accept_non_copy_elements_without_dropping_them() {
    let wipes = Cell::new(0);
    let drops = Cell::new(0);
    {
        let mut values = core::array::from_fn::<_, 3, _>(|_| DropProbe {
            secret: [8; 4],
            wipes: &wipes,
            drops: &drops,
        });
        values.zeroize();
        assert_eq!(wipes.get(), 3);
        assert_eq!(drops.get(), 0);
        for value in &mut values {
            value.secret = [9; 4];
        }
        values.as_mut_slice().zeroize();
        assert_eq!(wipes.get(), 6);
        assert_eq!(drops.get(), 0);
    }
    assert_eq!(drops.get(), 3);
}

#[test]
fn nested_options_and_arrays() {
    let mut values = Some([Some([1_u8, 2]), None, Some([3, 4])]);
    values.zeroize();
    assert_eq!(values, None);
}

#[test]
fn guard_borrows_mutates_and_clears_before_inner_drop() {
    fn marked<T: ZeroizeOnDrop>(_: &T) {}

    let wipes = Cell::new(0);
    let drops = Cell::new(0);
    {
        let mut guard = Zeroizing::new(DropProbe {
            secret: [7; 4],
            wipes: &wipes,
            drops: &drops,
        });
        marked(&guard);
        assert_eq!(guard.secret, [7; 4]);
        guard.secret[0] = 42;
        assert_eq!(guard.secret[0], 42);
        assert_eq!(wipes.get(), 0);
        assert_eq!(drops.get(), 0);
        let moved = guard;
        assert_eq!(moved.secret[0], 42);
    }
    assert_eq!(wipes.get(), 1);
    assert_eq!(drops.get(), 1);
}

#[test]
fn guard_clears_during_unwinding() {
    let wipes = Cell::new(0);
    let drops = Cell::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = Zeroizing::new(DropProbe {
            secret: [7; 4],
            wipes: &wipes,
            drops: &drops,
        });
        panic!("exercise unwinding");
    }));
    assert!(result.is_err());
    assert_eq!(wipes.get(), 1);
    assert_eq!(drops.get(), 1);
}
