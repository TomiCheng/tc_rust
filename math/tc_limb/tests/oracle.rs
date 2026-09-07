use num_bigint::BigUint;
use tc_limb::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, LimbArray, WideWord, Word};

fn next(state: &mut u64) -> Word {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as Word
}

fn oracle<const N: usize>(value: &LimbArray<N>) -> BigUint {
    let bytes: Vec<_> = value
        .as_limbs()
        .iter()
        .flat_map(|limb| limb.to_word().to_le_bytes())
        .collect();
    BigUint::from_bytes_le(&bytes)
}

fn assert_same<const N: usize>(value: LimbArray<N>, expected: BigUint) {
    let bytes = expected.to_bytes_le();
    assert!(expected.bits() <= (N * Word::BITS as usize) as u64);
    let expected_words: [Word; N] = core::array::from_fn(|index| {
        let mut word = 0 as Word;
        for byte in 0..core::mem::size_of::<Word>() {
            word |= (bytes
                .get(index * core::mem::size_of::<Word>() + byte)
                .copied()
                .unwrap_or(0) as Word)
                << (byte * 8);
        }
        word
    });
    assert_eq!(value.into_limbs().map(Limb::to_word), expected_words);
}

// Reconstruct both halves using the independent oracle's shifts and addition, not the arithmetic under test.
fn joined<const N: usize>(low: &LimbArray<N>, high: &LimbArray<N>) -> BigUint {
    oracle(low) + (oracle(high) << (N * Word::BITS as usize))
}

fn random_cases<const N: usize>() {
    let mut state = 0x243f_6a88_85a3_08d3;
    let width = N * Word::BITS as usize;
    let radix = BigUint::from(1_u8) << width;
    let mask = &radix - 1_u8;
    let wide_radix = &radix * &radix;
    let wide_mask = &wide_radix - 1_u8;
    for case in 0..600 {
        let mut a: [Limb; N] = core::array::from_fn(|_| Limb::new(next(&mut state)));
        let mut b: [Limb; N] = core::array::from_fn(|_| Limb::new(next(&mut state)));
        // Cover single-word divisors, leading zeros, normalization boundaries, full carry chains, and equal operands.
        let len = case % N + 1;
        b[len..].fill(Limb::new(0));
        match case % 6 {
            0 => b[len - 1] = Limb::new(1),
            1 => b[len - 1] = Limb::new(Word::MAX),
            2 => a.fill(Limb::new(Word::MAX)),
            3 => a = b,
            4 => a.fill(Limb::new(0)),
            _ => {}
        }
        if b.iter().all(|word| word.to_word() == 0) {
            b[0] = Limb::new(1);
        }
        let a = LimbArray::new(a);
        let b = LimbArray::new(b);
        let oa = oracle(&a);
        let ob = oracle(&b);
        assert_eq!(a.cmp(&b), oa.cmp(&ob));
        let sum = &oa + &ob;
        let product = &oa * &ob;
        for ((value, flag), expected, expected_flag) in [
            (a.add(&b), &sum & &mask, sum >= radix),
            (a.sub(&b), (&oa + &radix - &ob) & &mask, oa < ob),
            (a.mul(&b), &product & &mask, product >= radix),
        ] {
            assert_same(value, expected);
            assert_eq!(flag, expected_flag);
        }
        let (low, high) = a.mul_wide(&b);
        assert_same(low, &product & &mask);
        assert_same(high, &product >> width);
        assert_eq!(joined(&low, &high), product);
        let square = &oa * &oa;
        let (low, high) = a.square_wide();
        assert_same(low, &square & &mask);
        assert_same(high, &square >> width);
        let (q, r) = a.div_rem(&b);
        assert_same(q, &oa / &ob);
        assert_same(r, &oa % &ob);
        let (mut left, mut right) = (oa.clone(), ob.clone());
        while right != BigUint::from(0_u8) {
            let remainder = &left % &right;
            left = right;
            right = remainder;
        }
        assert_same(a.gcd(&b), left);
        let negated = (&radix - &oa) & &mask;
        assert_same(a.wrapping_neg(), negated.clone());
        let negative = oa.bit((width - 1) as u64);
        assert_eq!(a.bit_len(), oa.bits() as usize);
        assert_eq!(a.is_zero(), oa == BigUint::from(0_u8));
        assert_eq!(a.is_one(), oa == BigUint::from(1_u8));
        for bit in 0..width {
            assert_eq!(a.test_bit(bit), oa.bit(bit as u64));
        }
        let mut shifted = a;
        assert_eq!(shifted.shl_one(), negative);
        assert_same(shifted, (&oa << 1_usize) & &mask);
        shifted = a;
        shifted.shr_one();
        assert_same(shifted, &oa >> 1_usize);
        let mut acc_low = LimbArray::new(core::array::from_fn(|_| Limb::new(next(&mut state))));
        let mut acc_high = LimbArray::new(core::array::from_fn(|_| Limb::new(next(&mut state))));
        assert_same(a.wide_rem(&acc_high, &b), joined(&a, &acc_high) % &ob);
        let expected = joined(&acc_low, &acc_high) + &product;
        let overflow = a.mul_add_to(&b, &mut acc_low, &mut acc_high);
        assert_same(acc_low, &expected & &mask);
        assert_same(acc_high, (&expected >> width) & &mask);
        assert_eq!(joined(&acc_low, &acc_high), &expected & &wide_mask);
        assert_eq!(overflow, expected >= wide_radix);
        assert_eq!(a.ct_eq(&b).unwrap_u8(), (oa == ob) as u8);
        assert_eq!(a.ct_eq(&a).unwrap_u8(), 1);
        for bit in [0, 1] {
            assert_eq!(
                LimbArray::conditional_select(&a, &b, Choice::from_lsb(bit)),
                if bit == 0 { a } else { b }
            );
        }
    }
}

#[test]
fn every_array_operation_matches_num_bigint() {
    random_cases::<1>();
    random_cases::<2>();
    random_cases::<4>();
    random_cases::<8>();
}

#[test]
fn limb_operations_match_native_and_double_width_words() {
    let mut state = 0x1319_8a2e_0370_7344;
    for _ in 0..4000 {
        let a = next(&mut state);
        let b = next(&mut state);
        let carry = next(&mut state);
        let x = Limb::new(a);
        let y = Limb::new(b);
        let sum = a as WideWord + b as WideWord + carry as WideWord;
        let (low, high) = x.carrying_add(y, Limb::new(carry));
        assert_eq!(
            (low.to_word(), high.to_word()),
            (sum as Word, (sum >> Word::BITS) as Word)
        );
        for borrow in [0, 1] {
            let (first, b1) = a.overflowing_sub(b);
            let (difference, b2) = first.overflowing_sub(borrow);
            assert_eq!(
                x.borrowing_sub(y, Limb::new(borrow)),
                (Limb::new(difference), Limb::new((b1 | b2) as Word))
            );
        }
        assert_eq!(x.overflowing_add(y), {
            let (v, f) = a.overflowing_add(b);
            (Limb::new(v), f)
        });
        assert_eq!(x.overflowing_sub(y), {
            let (v, f) = a.overflowing_sub(b);
            (Limb::new(v), f)
        });
        assert_eq!(x.wrapping_add(y).to_word(), a.wrapping_add(b));
        assert_eq!(x.wrapping_sub(y).to_word(), a.wrapping_sub(b));
        assert_eq!(x.wrapping_neg().to_word(), a.wrapping_neg());
        let product = a as WideWord * b as WideWord;
        assert_eq!(
            x.widening_mul(y),
            (
                Limb::new(product as Word),
                Limb::new((product >> Word::BITS) as Word)
            )
        );
        assert_eq!((x & y).to_word(), a & b);
        assert_eq!((x | y).to_word(), a | b);
        assert_eq!((x ^ y).to_word(), a ^ b);
        assert_eq!((!x).to_word(), !a);
        let shift = carry as usize % Word::BITS as usize;
        assert_eq!((x << shift).to_word(), a << shift);
        assert_eq!((x >> shift).to_word(), a >> shift);
        let small_a = Limb::new(a & 0xff);
        let small_b = Limb::new(b & 0xff);
        assert_eq!((small_a * small_b).to_word(), (a & 0xff) * (b & 0xff));
        assert_eq!((small_a + small_b).to_word(), (a & 0xff) + (b & 0xff));
        let mut assigned = small_a;
        assigned += small_b;
        assigned -= small_b;
        assert_eq!(assigned, small_a);
        assert_eq!(x.ct_eq(&y).unwrap_u8(), (a == b) as u8);
        assert_eq!(x.ct_eq(&x).unwrap_u8(), 1);
        for bit in [0, 1] {
            assert_eq!(
                Limb::conditional_select(&x, &y, Choice::from_lsb(bit)),
                if bit == 0 { x } else { y }
            );
        }
    }
}

#[test]
fn empty_width_and_full_carry_borrow_chains() {
    let z = LimbArray::<0>::zero();
    assert_eq!(z, LimbArray::default());
    assert_eq!(z.as_limbs(), &[]);
    assert_eq!(z.add(&z), (z, false));
    assert_eq!(z.sub(&z), (z, false));
    assert_eq!(z.mul(&z), (z, false));
    assert_eq!(z.mul_wide(&z), (z, z));
    assert_eq!(z.square_wide(), (z, z));
    let (mut low, mut high) = (z, z);
    assert!(!z.mul_add_to(&z, &mut low, &mut high));
    assert!(!low.shl_one());
    low.shr_one();
    assert_eq!((low, high), (z, z));
    assert_eq!(z.gcd(&z), z);
    assert_eq!(z.wrapping_neg(), z);
    assert!(z.is_zero());
    assert!(!z.is_one());
    assert_eq!(z.bit_len(), 0);
    assert_eq!(z.cmp(&z), core::cmp::Ordering::Equal);
    assert_eq!(z.ct_eq(&z).unwrap_u8(), 1);
    assert_eq!(
        LimbArray::conditional_select(&z, &z, Choice::from_lsb(1)),
        z
    );
    let max = LimbArray::new([Limb::new(Word::MAX); 4]);
    let one = LimbArray::new([Limb::new(1), Limb::new(0), Limb::new(0), Limb::new(0)]);
    assert_eq!(max.add(&one), (LimbArray::zero(), true));
    assert_eq!(LimbArray::zero().sub(&one), (max, true));
    let mut low = max;
    let mut high = max;
    assert!(one.mul_add_to(&one, &mut low, &mut high));
    assert_eq!((low, high), (LimbArray::zero(), LimbArray::zero()));
    let min = LimbArray::new([Limb::new(0), Limb::new(1 << (Word::BITS - 1))]);
    assert_eq!(min.wrapping_neg(), min);
    for index in 0..4 {
        let mut limbs = max.into_limbs();
        limbs[index] = Limb::new(Word::MAX - 1);
        assert_eq!(max.ct_eq(&LimbArray::new(limbs)).unwrap_u8(), 0);
    }
}

#[test]
fn bit_changes_cover_every_limb_boundary() {
    const N: usize = 3;
    let zero = LimbArray::<N>::zero();
    for index in [
        0,
        Word::BITS as usize - 1,
        Word::BITS as usize,
        N * Word::BITS as usize - 1,
    ] {
        let set = zero.set_bit(index);
        assert!(set.test_bit(index));
        assert!(!set.clear_bit(index).test_bit(index));
        assert_eq!(zero.flip_bit(index).flip_bit(index), zero);
    }
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn test_bit_rejects_out_of_range_index() {
    let _ = LimbArray::<2>::zero().test_bit(2 * Word::BITS as usize);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn set_bit_rejects_out_of_range_index() {
    let _ = LimbArray::<2>::zero().set_bit(2 * Word::BITS as usize);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn clear_bit_rejects_out_of_range_index() {
    let _ = LimbArray::<2>::zero().clear_bit(2 * Word::BITS as usize);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn flip_bit_rejects_out_of_range_index() {
    let _ = LimbArray::<2>::zero().flip_bit(2 * Word::BITS as usize);
}

#[test]
fn invalid_inputs_panic_instead_of_silently_truncating() {
    let max = Limb::new(Word::MAX);
    let one = Limb::new(1);
    let zero = Limb::new(0);
    assert!(std::panic::catch_unwind(|| max + one).is_err());
    assert!(std::panic::catch_unwind(|| zero - one).is_err());
    assert!(std::panic::catch_unwind(|| max * max).is_err());
    assert!(std::panic::catch_unwind(|| zero.borrowing_sub(zero, Limb::new(2))).is_err());
    for shift in [Word::BITS as usize, usize::MAX] {
        assert!(std::panic::catch_unwind(|| one << shift).is_err());
        assert!(std::panic::catch_unwind(|| one >> shift).is_err());
    }
    let z = LimbArray::<1>::zero();
    assert!(std::panic::catch_unwind(|| z.div_rem(&z)).is_err());
    assert!(std::panic::catch_unwind(|| z.wide_rem(&z, &z)).is_err());
    assert!(std::panic::catch_unwind(|| z.test_bit(Word::BITS as usize)).is_err());
    let z = LimbArray::<0>::zero();
    assert!(std::panic::catch_unwind(|| z.div_rem(&z)).is_err());
    assert!(std::panic::catch_unwind(|| z.wide_rem(&z, &z)).is_err());
    assert!(std::panic::catch_unwind(|| z.test_bit(0)).is_err());
}
