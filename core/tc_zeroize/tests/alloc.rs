//! Checks of still-live allocations and erasure before element destruction.

#![cfg(feature = "alloc")]

use core::cell::Cell;
use tc_zeroize::Zeroize;

#[test]
fn vec_clears_live_and_spare_capacity_and_retains_allocation() {
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&[1_u8, 2, 3, 4]);
    let capacity = value.capacity();
    for slot in value.spare_capacity_mut() {
        slot.write(u8::MAX);
    }
    value.zeroize();
    assert!(value.is_empty());
    assert_eq!(value.capacity(), capacity);
    let spare = value.spare_capacity_mut();
    assert_eq!(spare.len(), capacity);
    for slot in spare {
        // SAFETY: Erasure initialized each padding-free byte with zero. The
        // allocation is still owned by `value` and borrowed through `spare`.
        assert_eq!(unsafe { slot.assume_init() }, 0);
    }
}

// Inspect a live value from its destructor, never freed storage.
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
fn vec_clears_each_element_before_dropping_it_once() {
    let wipes = Cell::new(0);
    let drops = Cell::new(0);
    let mut value: Vec<_> = (0..3)
        .map(|_| DropProbe {
            secret: [7; 4],
            wipes: &wipes,
            drops: &drops,
        })
        .collect();
    value.zeroize();
    assert!(value.is_empty());
    assert_eq!(wipes.get(), 3);
    assert_eq!(drops.get(), 3);
    value.zeroize();
    drop(value);
    assert_eq!(wipes.get(), 3);
    assert_eq!(drops.get(), 3);
}

#[test]
fn empty_vectors_with_and_without_capacity() {
    for mut value in [Vec::<u8>::new(), Vec::with_capacity(8)] {
        let capacity = value.capacity();
        value.zeroize();
        assert!(value.is_empty());
        assert_eq!(value.capacity(), capacity);
        for slot in value.spare_capacity_mut() {
            // SAFETY: Erasure initialized this byte in the still-live allocation.
            assert_eq!(unsafe { slot.assume_init() }, 0);
        }
    }
}

#[test]
fn boxes_clear_sized_values_and_slices_in_place() {
    let mut value = Box::new(u32::MAX);
    value.zeroize();
    assert_eq!(*value, 0);
    let mut value: Box<[u8]> = vec![1, 2, 3, 4].into_boxed_slice();
    value.zeroize();
    assert_eq!(&*value, &[0; 4]);
}

#[test]
fn nested_vectors_clear_before_dropping_inner_allocations() {
    let mut value = vec![vec![1_u8, 2], vec![], vec![3, 4, 5]];
    let capacity = value.capacity();
    value.zeroize();
    assert!(value.is_empty());
    assert_eq!(value.capacity(), capacity);
}
