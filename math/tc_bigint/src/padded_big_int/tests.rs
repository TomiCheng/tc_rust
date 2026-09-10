//! 二補數表示、符號擴展與定長核心的回歸測試。

use super::*;
use crate::{BitOps, CheckedShl, CheckedShr, One, PaddedBigUint, Zero};

fn small(value: i64, width: usize) -> PaddedBigInt {
    PaddedBigInt::from_big_int(&BigInt::from(value), width).unwrap()
}

#[test]
fn resize_widens_with_the_original_sign() {
    for value in [-129, -1, 0, 1, 127] {
        let narrow = small(value, 1);
        let wide = narrow.resize(4).unwrap();
        assert_eq!(wide.to_big_int(), BigInt::from(value));
        assert_eq!(wide.len(), 4);
        let extension = if value < 0 { Word::MAX } else { 0 };
        assert!(
            wide.limbs[1..]
                .iter()
                .all(|limb| limb.to_word() == extension)
        );
        assert_eq!(wide.resize(1).unwrap(), narrow);
    }
}

#[test]
fn resize_rejects_discarded_non_extension_limbs() {
    for words in [[1, 1], [Word::MAX - 1, Word::MAX - 1]] {
        let value = PaddedBigInt::from_limbs(words.map(Limb::new).into());
        assert_eq!(value.resize(1), Err(ConversionError::InputTooLarge));
    }
}

#[test]
fn resize_rejects_a_changed_retained_sign() {
    for words in [[Word::MAX, 0], [0, Word::MAX]] {
        let value = PaddedBigInt::from_limbs(words.map(Limb::new).into());
        assert_eq!(value.resize(1), Err(ConversionError::InputTooLarge));
    }
    assert!(small(-1, 1).resize(0).is_err());
    assert!(small(1, 1).resize(0).is_err());
    assert!(small(0, 4).resize(0).unwrap().is_empty());
}

#[test]
fn signed_decoding_and_narrow_buffer_writes_preserve_sign() {
    for (bytes, expected) in [
        (&[0xff][..], -1),
        (&[0, 0xff][..], 255),
        (&[0xff, 0][..], -256),
    ] {
        let value = PaddedBigInt::from_be_bytes(bytes, 4).unwrap();
        let reversed: alloc::vec::Vec<_> = bytes.iter().copied().rev().collect();
        assert_eq!(value, PaddedBigInt::from_le_bytes(&reversed, 4).unwrap());
        assert_eq!(value.to_big_int(), BigInt::from(expected));
        let mut out = alloc::vec![0; bytes.len()];
        value.write_be_bytes(&mut out).unwrap();
        assert_eq!(out, bytes);
    }
    for value in [128, 255, -129, -256] {
        let mut out = [0x55];
        assert_eq!(
            small(value, 2).write_be_bytes(&mut out),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(out, [0x55]);
    }
    let mut out = [0; 12];
    small(-1, 1).write_be_bytes(&mut out).unwrap();
    assert_eq!(out, [0xff; 12]);
    assert!(small(0, 0).write_be_bytes(&mut []).is_err());
    assert!(PaddedBigInt::from_be_bytes(&[0xff], 0).is_err());
    assert!(PaddedBigInt::from_be_bytes(&[0], 0).unwrap().is_empty());
    let mut positive_overflow = alloc::vec![0xff; size_of::<Word>() + 1];
    positive_overflow[0] = 0;
    assert!(PaddedBigInt::from_be_bytes(&positive_overflow, 1).is_err());
    assert!(PaddedBigInt::from_be_bytes(&alloc::vec![0xff; 4 * size_of::<Word>()], 1).is_ok());
}

#[test]
fn mixed_sign_operators_align_by_sign_extension() {
    for (a, b) in [(-7, 3), (7, -3), (-7, -3), (7, 3), (0, -3)] {
        let lhs = small(a, 4);
        let rhs = small(b, 1);
        for (result, expected) in [
            (&lhs + &rhs, a + b),
            (&lhs - &rhs, a - b),
            (&lhs * &rhs, a * b),
        ] {
            assert_eq!(result.len(), 4);
            assert_eq!(result.to_big_int(), BigInt::from(expected));
        }
        assert_eq!(
            (&lhs & &rhs).to_big_int(),
            BigInt::from(a) & BigInt::from(b)
        );
    }
    assert_eq!(small(-1, 1), small(-1, 4));
    assert_eq!(small(0, 0), small(0, 4));
    assert!(small(-1, 4) < small(0, 0));
}

#[test]
fn arithmetic_right_shift_copies_sign_bits() {
    for value in [-129, -2, -1, 0, 1, 129] {
        let padded = small(value, 4);
        for shift in [0, 1, 7, Word::BITS as usize, 4 * Word::BITS as usize - 1] {
            let result = &padded >> shift;
            assert_eq!(result.len(), 4);
            assert_eq!(result.to_big_int(), BigInt::from(value) >> shift);
            assert_eq!(result.is_negative(), value < 0);
        }
        let far = padded.shr_core(usize::MAX);
        assert_eq!(far, small(if value < 0 { -1 } else { 0 }, 4));
    }
}

#[test]
fn checked_shifts_respect_both_signed_boundaries() {
    let shift = Word::BITS - 1;
    assert!(small(1, 1).checked_shl(shift).is_none());
    assert!(small(-1, 1).checked_shl(shift).is_some());
    assert!(small(-2, 1).checked_shl(shift).is_none());
    assert!(small(1, 1).checked_shl(shift - 1).is_some());
    assert!(small(-2, 1).checked_shl(shift - 1).is_some());
    let truncated = &small(1, 1) << shift as usize;
    assert!(truncated.is_negative());
    assert_eq!((&truncated << 1).to_big_int(), BigInt::from(0));
    assert!(small(-1, 1).checked_shr(Word::BITS).is_none());
    assert!(std::panic::catch_unwind(|| small(-1, 1) >> Word::BITS as usize).is_err());
}

#[test]
fn zero_width_is_a_first_class_zero() {
    let zero = PaddedBigInt::zero();
    assert!(zero.is_empty());
    assert!(!zero.is_negative());
    assert_eq!(zero.ct_is_negative().unwrap_u8(), 0);
    assert_eq!(PaddedBigInt::default().len(), 0);
    assert_eq!(PaddedBigInt::one().len(), 1);
    for shift in [0, 1, Word::BITS as usize, usize::MAX] {
        assert!((&zero << shift).is_empty());
        assert!((zero.clone() << shift).is_empty());
        assert!((&zero >> shift).is_empty());
        assert!((zero.clone() >> shift).is_empty());
        let mut a = zero.clone();
        a <<= shift;
        a >>= shift;
        assert!(a.is_empty());
    }
    assert!(PaddedBigInt::add(&zero, &zero).0.is_empty());
    assert!(!PaddedBigInt::sub(&zero, &zero).1);
    assert!(!zero.mul_core(&zero).1);
    assert!((-zero.clone()).is_empty());
}

#[test]
fn ct_methods_are_strict_and_preserve_width() {
    fn drop_policy<T: ZeroizeOnDrop>() {}
    drop_policy::<PaddedBigInt>();
    for width in [0, 1, 4] {
        let a = small(if width == 0 { 0 } else { -7 }, width);
        let b = small(if width == 0 { 0 } else { 3 }, width);
        assert_eq!(PaddedBigInt::add(&a, &b).0.len(), width);
        assert_eq!(PaddedBigInt::sub(&a, &b).0.len(), width);
        assert_eq!(a.mul_core(&b).0.len(), width);
        assert_eq!(a.shl_core(usize::MAX).len(), width);
        for choice in [0, 1] {
            let selected = PaddedBigInt::conditional_select(&a, &b, Choice::from_lsb(choice));
            assert_eq!(selected.len(), width);
            assert_eq!(selected, if choice == 0 { a.clone() } else { b.clone() });
        }
        assert_eq!(a.ct_eq(&a.clone()).unwrap_u8(), 1);
        let mut erased = a.clone();
        erased.zeroize();
        assert_eq!(erased.len(), width);
        assert_eq!(erased.ct_is_zero().unwrap_u8(), 1);
        erased.set_zero();
        assert_eq!(erased.len(), width);
    }
    let a = small(1, 4);
    let b = small(1, 1);
    assert!(std::panic::catch_unwind(|| PaddedBigInt::add(&a, &b)).is_err());
    assert!(std::panic::catch_unwind(|| PaddedBigInt::sub(&a, &b)).is_err());
    assert!(std::panic::catch_unwind(|| a.mul_core(&b)).is_err());
    assert!(std::panic::catch_unwind(|| a.ct_eq(&b)).is_err());
    assert!(
        std::panic::catch_unwind(|| PaddedBigInt::conditional_select(&a, &b, Choice::from_lsb(0)))
            .is_err()
    );
    assert_eq!(alloc::format!("{a:?}"), "PaddedBigInt { limbs: 4, .. }");
}

#[test]
fn unsigned_interconversion_preserves_width_or_reports_sign_errors() {
    for width in [0, 1, 4] {
        let value = small(if width == 0 { 0 } else { 7 }, width);
        let unsigned = PaddedBigUint::try_from(&value).unwrap();
        assert_eq!(unsigned.len(), width);
        assert_eq!(PaddedBigInt::try_from(&unsigned).unwrap(), value);
        assert_eq!(
            PaddedBigInt::try_from(unsigned.clone()).unwrap().len(),
            width
        );
        assert_eq!(PaddedBigUint::try_from(value).unwrap(), unsigned);
    }
    assert_eq!(
        PaddedBigUint::try_from(small(-1, 1)),
        Err(ConversionError::NegativeValue)
    );
    let top = PaddedBigUint::zero_with_limbs(1).set_bit(Word::BITS as usize - 1);
    assert_eq!(
        PaddedBigInt::try_from(top),
        Err(ConversionError::InputTooLarge)
    );
}
