//! 工單七的變動時間介面與既有 CT 介面的分界驗證。
use crate::{BigUint, Limb, PaddedBigUint as PU, Word, *};
use alloc::{format, string::String, vec, vec::Vec};

struct Sequence(u64);
impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn value(&mut self, width: usize) -> PU {
        PU::from_limbs((0..width).map(|_| Limb::new(self.next() as Word)).collect())
    }
}
fn small(v: u8, width: usize) -> PU {
    PU::from_be_bytes(&[v], width).unwrap()
}
fn check(value: PU, expected: &BigUint, width: usize) {
    assert_eq!(value.len(), width);
    assert_eq!(&value.to_big_uint(), expected);
}
fn panic_contains(f: impl FnOnce() + std::panic::UnwindSafe, expected: &str) {
    let error = std::panic::catch_unwind(f).expect_err("預期 panic");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(message.contains(expected), "{message}");
}
macro_rules! operator_forms {
    ($a:ident, $b:ident, $expected:expr, $op:tt, $assign:tt) => {{
        let expected = $expected;
        let width = $a.len().max($b.len());
        check(&$a $op &$b, &expected, width);
        check($a.clone() $op &$b, &expected, width);
        check(&$a $op $b.clone(), &expected, width);
        check($a.clone() $op $b.clone(), &expected, width);
        let mut assigned = $a.clone();
        assigned $assign &$b;
        check(assigned, &expected, width);
        let mut assigned = $a.clone();
        assigned $assign $b.clone();
        check(assigned, &expected, width);
    }};
}

#[test]
fn two_hundred_cross_width_operator_cases_match_big_uint() {
    let mut rng = Sequence(0x9172_9374_1229_abcf);
    for case in 0..200 {
        let aw = case % 4 + 1;
        let bw = if case % 2 == 0 { 1 } else { 4 };
        let a = if case % 3 == 0 {
            small((rng.next() % 128) as u8, aw)
        } else {
            rng.value(aw)
        };
        let b = if case % 3 == 0 {
            small((rng.next() % 127 + 1) as u8, bw)
        } else {
            rng.value(bw)
        };
        let aa = a.to_big_uint();
        let bb = b.to_big_uint();
        let width = aw.max(bw);
        let radix = BigUint::from(1_u8) << (width * Word::BITS as usize);
        let max = &radix - BigUint::from(1_u8);

        let sum = &aa + &bb;
        let overflow = sum >= radix;
        let (wrapped, flag) = a.overflowing_add(&b);
        assert_eq!(flag, overflow);
        check(wrapped, &(&sum % &radix), width);
        check(a.wrapping_add(&b), &(&sum % &radix), width);
        check(
            a.saturating_add(&b),
            if overflow { &max } else { &sum },
            width,
        );
        assert_eq!(
            a.checked_add(&b).map(|v| v.to_big_uint()),
            (!overflow).then_some(sum.clone())
        );
        if !overflow {
            operator_forms!(a, b, sum, +, +=);
        } else {
            panic_contains(
                || {
                    let _ = &a + &b;
                },
                "attempted to add with overflow",
            );
        }

        let borrowed = aa < bb;
        let wrapped = (&aa + &radix - &bb) % &radix;
        let (result, flag) = a.overflowing_sub(&b);
        assert_eq!(flag, borrowed);
        check(result, &wrapped, width);
        check(a.wrapping_sub(&b), &wrapped, width);
        let saturated = if borrowed {
            BigUint::zero()
        } else {
            wrapped.clone()
        };
        check(a.saturating_sub(&b), &saturated, width);
        assert_eq!(
            a.checked_sub(&b).map(|v| v.to_big_uint()),
            (!borrowed).then_some(wrapped.clone())
        );
        if !borrowed {
            operator_forms!(a, b, &aa - &bb, -, -=);
        } else {
            panic_contains(
                || {
                    let _ = &a - &b;
                },
                "attempted to subtract with underflow",
            );
        }

        let product = &aa * &bb;
        let overflow = product >= radix;
        let (wrapped, flag) = a.overflowing_mul(&b);
        assert_eq!(flag, overflow);
        check(wrapped, &(&product % &radix), width);
        check(a.wrapping_mul(&b), &(&product % &radix), width);
        check(
            a.saturating_mul(&b),
            if overflow { &max } else { &product },
            width,
        );
        assert_eq!(
            a.checked_mul(&b).map(|v| v.to_big_uint()),
            (!overflow).then_some(product.clone())
        );
        if !overflow {
            operator_forms!(a, b, product, *, *=);
        } else {
            panic_contains(
                || {
                    let _ = &a * &b;
                },
                "attempted to multiply with overflow",
            );
        }

        operator_forms!(a, b, &aa / &bb, /, /=);
        operator_forms!(a, b, &aa % &bb, %, %=);
        operator_forms!(a, b, &aa & &bb, &, &=);
        operator_forms!(a, b, &aa | &bb, |, |=);
        operator_forms!(a, b, &aa ^ &bb, ^, ^=);
        check(a.checked_div(&b).unwrap(), &(&aa / &bb), width);
        check(a.checked_rem(&b).unwrap(), &(&aa % &bb), width);
        let (q, r) = a.div_rem(&b);
        check(q, &(&aa / &bb), width);
        check(r, &(&aa % &bb), width);
        check(a.rem_euclid(&b), &aa.rem_euclid(&bb), width);
        check(a.gcd(&b), &aa.gcd(&bb), width);
        check(a.and_not(&b), &aa.and_not(&bb), width);
        let amax = (BigUint::from(1_u8) << (aw * Word::BITS as usize)) - BigUint::from(1_u8);
        check(!&a, &(&amax ^ &aa), aw);
        check(!a.clone(), &(&amax ^ &aa), aw);
        let shift = case % (aw * Word::BITS as usize);
        check(&a >> shift, &(&aa >> shift), aw);
        check(a.clone() >> shift, &(&aa >> shift), aw);
        let mut shifted = a.clone();
        shifted >>= shift;
        check(shifted, &(&aa >> shift), aw);
        check(a.checked_shr(shift as u32).unwrap(), &(&aa >> shift), aw);
        let left = &aa << shift;
        let truncated = &left & &amax;
        check(&a << shift, &truncated, aw);
        check(a.clone() << shift, &truncated, aw);
        let mut shifted = a.clone();
        shifted <<= shift;
        check(shifted, &truncated, aw);
        if left <= amax {
            check(a.checked_shl(shift as u32).unwrap(), &left, aw);
        } else {
            assert!(a.checked_shl(shift as u32).is_none());
        }
    }
}

#[test]
fn identity_assignment_and_ct_width_contracts_remain_distinct() {
    let zero = PU::zero();
    assert_eq!(zero.len(), 0);
    assert_eq!(PU::default().len(), 0);
    assert_eq!(PU::one().len(), 1);
    let q = small(7, 4);
    operator_forms!(q, zero, q.to_big_uint(), +, +=);
    check(&q + PU::one(), &BigUint::from(8_u8), 4);
    let mut identity = q.clone();
    identity.set_zero();
    assert_eq!(identity.len(), 4);
    assert!(identity.is_zero());
    identity.set_one();
    assert_eq!(identity.len(), 4);
    assert!(identity.is_one());
    assert_eq!(NonZero::new(q.clone()).unwrap().into_inner(), q);
    let one = PU::one();
    for f in [PU::add, PU::sub] {
        assert!(std::panic::catch_unwind(|| f(&q, &one)).is_err());
    }
    assert!(std::panic::catch_unwind(|| q.ct_eq(&one)).is_err());
    assert!(
        std::panic::catch_unwind(|| PU::conditional_select(&q, &one, Choice::from_lsb(0))).is_err()
    );
    assert!(std::panic::catch_unwind(|| q.clone().add_assign(&one)).is_err());
    assert!(std::panic::catch_unwind(|| q.clone().sub_assign(&one)).is_err());
    for n in [0, 1, 4] {
        let z = PU::zero_with_limbs(n);
        assert!(q.checked_div(&z).is_none());
        assert!(q.checked_rem(&z).is_none());
        assert!(std::panic::catch_unwind(|| &q / &z).is_err());
        assert!(std::panic::catch_unwind(|| &q % &z).is_err());
    }
    check(&zero + &zero, &BigUint::zero(), 0);
    check(&zero - &zero, &BigUint::zero(), 0);
    check(&zero * &zero, &BigUint::zero(), 0);
    let max = !PU::zero_with_limbs(1);
    for f in [
        |a: &PU, b: &PU| {
            let mut a = a.clone();
            a += b;
        },
        |a: &PU, b: &PU| {
            let mut a = a.clone();
            a *= b;
        },
    ] {
        assert!(std::panic::catch_unwind(|| f(&max, &small(2, 1))).is_err());
    }
    let mut unchanged = max.clone();
    let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unchanged += &one));
    assert!(error.is_err());
    assert_eq!(unchanged, max);
    assert_eq!(unchanged.len(), 1);
    panic_contains(
        || {
            let _ = &q << usize::MAX;
        },
        "attempted to shift left with overflow",
    );
    panic_contains(
        || {
            let _ = &q >> usize::MAX;
        },
        "attempted to shift right with overflow",
    );
    assert!(q.checked_shl(4 * Word::BITS).is_none());
    assert!(q.checked_shr(4 * Word::BITS).is_none());
}

#[test]
fn powers_modular_traits_and_parsing_match_the_public_backend() {
    let mut rng = Sequence(0x1283_5678_3333_af10);
    for case in 0..200 {
        let a = rng.value(case % 4 + 1);
        let b = rng.value(1);
        let modulus = small((case % 250 + 1) as u8, 3);
        let exponent = small((case % 9) as u8, 2);
        let aa = a.to_big_uint();
        let bb = b.to_big_uint();
        let mm = modulus.to_big_uint();
        check(
            a.mod_pow(&exponent, &modulus),
            &aa.mod_pow(&exponent.to_big_uint(), &mm),
            3,
        );
        check(a.mod_add(&b, &modulus), &aa.mod_add(&bb, &mm), 3);
        check(a.mod_sub(&b, &modulus), &aa.mod_sub(&bb, &mm), 3);
        check(a.mod_mul(&b, &modulus), &aa.mod_mul(&bb, &mm), 3);
        let inverse = a.mod_inverse(&modulus);
        if let Some(value) = &inverse {
            assert_eq!(value.len(), 3);
        }
        assert_eq!(inverse.map(|v| v.to_big_uint()), aa.mod_inverse(&mm));
        for radix in [2, 8, 10, 16, 36] {
            let s = aa.to_str_radix(radix);
            let parsed = PU::from_str_radix(&s, radix).unwrap();
            assert_eq!(parsed.len(), limbs_for_bits(aa.bit_length()));
            assert_eq!(parsed.to_str_radix(radix), s);
            assert_eq!(parsed.to_big_uint(), aa);
        }
        let small_base = small((case % 6) as u8, 4);
        let exp = (case % 5) as u32;
        let expected = Pow::pow(small_base.to_big_uint(), exp);
        check(Pow::pow(&small_base, exp), &expected, 4);
        check(Pow::pow(&small_base, &exp), &expected, 4);
        check(Pow::pow(small_base.clone(), exp), &expected, 4);
        check(Pow::pow(small_base.clone(), &exp), &expected, 4);
        check(
            small_base.square(),
            &(&small_base.to_big_uint() * &small_base.to_big_uint()),
            4,
        );
    }
    assert_eq!("0".parse::<PU>().unwrap().len(), 0);
    assert_eq!(PU::from_str_radix("ff", 16).unwrap(), small(255, 1));
    for (s, radix) in [("-1", 10), ("", 10), ("x", 10), ("1", 1), ("1", 37)] {
        assert_eq!(
            PU::from_str_radix(s, radix).err(),
            BigUint::from_str_radix(s, radix).err()
        );
    }
    let v = small(255, 4);
    let b = v.to_big_uint();
    assert_eq!(
        format!("{v:08} {v:#010x} {v:X} {v:o} {v:b}"),
        format!("{b:08} {b:#010x} {b:X} {b:o} {b:b}")
    );
    assert!(std::panic::catch_unwind(|| Pow::pow(!PU::zero_with_limbs(1), 2_u32)).is_err());
}

#[test]
fn primitive_conversions_use_the_source_type_width() {
    macro_rules! unsigned { ($($method:ident, $ty:ty),*) => {$({
        for value in [0, 1, <$ty>::MAX] {
            let p = PU::$method(value).unwrap();
            assert_eq!(p.len(), limbs_for_bits(<$ty>::BITS as usize));
            assert_eq!(p.to_u128(), Some(value as u128));
            assert_eq!(PU::from(value).len(), p.len());
            assert_eq!(PU::from(value), p);
        }
    })*}; }
    unsigned!(
        from_u8, u8, from_u16, u16, from_u32, u32, from_u64, u64, from_u128, u128, from_usize,
        usize
    );
    macro_rules! signed { ($($method:ident, $ty:ty),*) => {$({
        assert!(PU::$method(-1).is_none());
        for value in [0, 1, <$ty>::MAX] {
            let p = PU::$method(value).unwrap();
            assert_eq!(p.len(), limbs_for_bits(<$ty>::BITS as usize));
            assert_eq!(p.to_i128(), Some(value as i128));
        }
    })*}; }
    signed!(
        from_i8, i8, from_i16, i16, from_i32, i32, from_i64, i64, from_i128, i128, from_isize,
        isize
    );
    let huge = PU::from(u128::MAX).resize(limbs_for_bits(256)).unwrap();
    assert_eq!(huge.to_u128(), Some(u128::MAX));
    assert_eq!(huge.to_i128(), None);
    assert_eq!(huge.to_u64(), None);
    assert_eq!(huge.to_i64(), None);
    let too_big = PU::from_big_uint(&(BigUint::from(1_u8) << 128), limbs_for_bits(256)).unwrap();
    assert_eq!(too_big.to_u128(), None);
    let value = small(42, 4);
    assert_eq!(value.to_u8(), Some(42));
    assert_eq!(value.to_u16(), Some(42));
    assert_eq!(value.to_u32(), Some(42));
    assert_eq!(value.to_usize(), Some(42));
    assert_eq!(value.to_i8(), Some(42));
    assert_eq!(value.to_i16(), Some(42));
    assert_eq!(value.to_i32(), Some(42));
    assert_eq!(value.to_isize(), Some(42));
    assert_eq!(PU::from_f32(42.5).unwrap(), value);
    assert_eq!(PU::from_f64(42.5).unwrap(), value);
    assert!(PU::from_f64(f64::NAN).is_none());
    assert!(PU::from_f64(f64::INFINITY).is_none());
    assert_eq!(value.to_f32(), Some(42.0));
    assert_eq!(value.to_f64(), Some(42.0));
}

#[test]
fn array_conversions_preserve_width_and_unsigned_encodings_are_shortest() {
    macro_rules! encoding {
        ($ty:ty, $decode:ident, $unsigned_decode:ident, $write:ident, $unsigned_write:ident, $full:ident, $short:ident, $length:ident, $unsigned_length:ident) => {{
            for data in [vec![], vec![0], vec![0, 7, 0], vec![<$ty>::MAX; 3]] {
                let value = <PU as ArrayEncoding>::$decode(&data).unwrap();
                let big = BigUint::$decode(&data);
                let width = limbs_for_bits(data.len() * <$ty>::BITS as usize);
                assert_eq!(value.len(), width);
                assert_eq!(value.to_big_uint(), big);
                let unsigned = <PU as ArrayEncoding>::$unsigned_decode(&data).unwrap();
                assert_eq!(unsigned.len(), width);
                assert_eq!(unsigned, value);
                let full = value.$full();
                assert_eq!(
                    full.len(),
                    (width * Word::BITS as usize).div_ceil(<$ty>::BITS as usize)
                );
                assert_eq!(BigUint::$decode(&full), big);
                assert_eq!(value.$short(), big.$full());
                assert_eq!(value.$length(), full.len());
                assert_eq!(value.$unsigned_length(), big.$unsigned_length());
                for size in 0..=full.len() + 1 {
                    let mut out = vec![0x55 as $ty; size];
                    let mut expected = out.clone();
                    let result = <PU as ArrayEncoding>::$write(&value, &mut out);
                    let reference = if size < full.len() {
                        Err(ConversionError::BufferTooSmall)
                    } else {
                        expected[..full.len()].copy_from_slice(&full);
                        Ok(full.len())
                    };
                    assert_eq!(result, reference);
                    assert_eq!(out, expected);
                    let mut out = vec![0x55 as $ty; size];
                    let mut expected = out.clone();
                    let reference = big.$write(&mut expected);
                    assert_eq!(
                        <PU as ArrayEncoding>::$unsigned_write(&value, &mut out),
                        reference
                    );
                    assert_eq!(out, expected);
                }
            }
        }};
    }
    encoding!(
        u8,
        from_le_bytes,
        from_unsigned_le_bytes,
        write_le_bytes,
        write_unsigned_le_bytes,
        to_le_bytes,
        to_unsigned_le_bytes,
        byte_length,
        byte_length_unsigned
    );
    encoding!(
        u8,
        from_be_bytes,
        from_unsigned_be_bytes,
        write_be_bytes,
        write_unsigned_be_bytes,
        to_be_bytes,
        to_unsigned_be_bytes,
        byte_length,
        byte_length_unsigned
    );
    encoding!(
        u32,
        from_le_u32,
        from_unsigned_le_u32,
        write_le_u32,
        write_unsigned_le_u32,
        to_le_u32,
        to_unsigned_le_u32,
        u32_length,
        u32_length_unsigned
    );
    encoding!(
        u32,
        from_be_u32,
        from_unsigned_be_u32,
        write_be_u32,
        write_unsigned_be_u32,
        to_be_u32,
        to_unsigned_be_u32,
        u32_length,
        u32_length_unsigned
    );
    encoding!(
        u64,
        from_le_u64,
        from_unsigned_le_u64,
        write_le_u64,
        write_unsigned_le_u64,
        to_le_u64,
        to_unsigned_le_u64,
        u64_length,
        u64_length_unsigned
    );
    encoding!(
        u64,
        from_be_u64,
        from_unsigned_be_u64,
        write_be_u64,
        write_unsigned_be_u64,
        to_be_u64,
        to_unsigned_be_u64,
        u64_length,
        u64_length_unsigned
    );
}

#[test]
fn ct_sources_never_delegate_to_variable_width_integers() {
    for source in [
        include_str!("add.rs"),
        include_str!("sub.rs"),
        include_str!("mul.rs"),
        include_str!("shift.rs"),
    ] {
        let code = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "significant_len(",
            "bit_len(",
            "is_zero(",
            "to_big_uint(",
            "from_big_uint(",
        ] {
            assert!(!code.contains(forbidden), "CT 路徑包含 {forbidden}");
        }
        // 比對獨立識別字，避免把 PaddedBigUint 誤認成 BigUint。
        assert!(
            !code
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|token| token == "BigUint")
        );
    }
    // 這只是回歸防護，不證明時間性質，也無法攔住手寫的變動時間除法迴圈。
}

#[test]
fn every_operator_impl_has_a_variable_time_doc() {
    for source in [
        include_str!("ops.rs"),
        include_str!("div.rs"),
        include_str!("str.rs"),
    ] {
        let lines: Vec<_> = source.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("impl ") {
                let docs = lines[..i]
                    .iter()
                    .rev()
                    .take_while(|l| {
                        let l = l.trim();
                        l.starts_with("///") || l.starts_with("#[doc")
                    })
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(docs.contains("變動時間"), "缺少變動時間文件：{line}");
            }
        }
    }
}

#[test]
fn numeric_aggregate_bounds_are_satisfied() {
    fn numeric<T: Num + NumOps + NumRef + NumAssign + NumAssignOps + NumAssignRef + Unsigned>() {}
    fn references<T>()
    where
        for<'a> &'a T: RefNum<T>,
    {
    }
    numeric::<PU>();
    references::<PU>();
}

#[test]
fn qualified_ct_calls_remain_strict_when_operator_traits_are_in_scope() {
    use core::ops::Add;
    let a = small(7, 4);
    let b = small(3, 1);
    let public_sum = a.clone().add(&b);
    check(public_sum, &BigUint::from(10_u8), 4);
    assert!(std::panic::catch_unwind(|| PU::add(&a, &b)).is_err());
    assert_eq!(PU::add(&a, &b.resize(4).unwrap()).0, small(10, 4));
}

#[test]
fn zero_width_shift_operators_accept_every_shift_count() {
    for shift in [0, 1, Word::BITS as usize, usize::MAX] {
        let zero = PU::zero();
        check(&zero << shift, &BigUint::zero(), 0);
        check(zero.clone() << shift, &BigUint::zero(), 0);
        check(&zero >> shift, &BigUint::zero(), 0);
        check(zero.clone() >> shift, &BigUint::zero(), 0);
        let mut left = zero.clone();
        left <<= shift;
        let mut right = zero.clone();
        right >>= shift;
        check(left, &BigUint::zero(), 0);
        check(right, &BigUint::zero(), 0);
        let (ct_left, lost) = PU::shl(&zero, shift);
        check(ct_left, &BigUint::zero(), 0);
        assert!(!lost);
        check(PU::shr(&zero, shift), &BigUint::zero(), 0);
    }
    let top = PU::from_be_bytes(&[1], 1)
        .unwrap()
        .set_bit(Word::BITS as usize - 1);
    assert!(top.checked_shl(1).is_none());
    assert_eq!((&top << 1).to_big_uint(), BigUint::from(2_u8));
    assert!(PU::shl(&top, 1).1);
    let (zero, lost) = PU::shl(&top, usize::MAX);
    assert!(zero.is_zero());
    assert!(lost);
}

#[cfg(feature = "rand_core")]
impl rand_core::TryRng for Sequence {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
#[test]
fn random_and_prime_traits_keep_the_declared_precision() {
    let mut rng = Sequence(0x9123_4376_8291_aaff);
    for bits in [0, 1, 7, 32, 33, 63, 64, 65, 129] {
        let value = PU::try_random_bits(&mut rng, bits).unwrap();
        assert_eq!(value.len(), limbs_for_bits(bits as usize));
        assert!(value.bit_len() <= bits as usize);
        let value = PU::random_bits_with_precision(&mut rng, bits, bits + 129);
        assert_eq!(value.len(), limbs_for_bits(bits as usize + 129));
        assert!(value.bit_len() <= bits as usize);
        assert!(PU::try_random_bits_with_precision(&mut rng, bits + 1, bits).is_err());
    }
    let upper = NonZero::new(small(17, 4)).unwrap();
    for _ in 0..200 {
        let value = <PU as RandomMod>::random_mod_vartime(&mut rng, &upper);
        assert_eq!(value.len(), 4);
        assert!(value < *upper);
    }
    for bits in [2, 3, 8, 9] {
        let value = PU::probable_prime(&mut rng, bits);
        assert_eq!(value.len(), limbs_for_bits(bits as usize));
        assert_eq!(value.bit_len(), bits as usize);
        assert!(value.is_probable_prime(30, &mut rng));
    }
    let prime = small(17, 4).next_probable_prime(&mut rng).unwrap();
    assert_eq!(prime, small(19, 4));
    assert_eq!(prime.len(), 4);
    assert!(!small(21, 4).is_probable_prime(30, &mut rng));
    assert!(PU::zero().next_probable_prime(&mut rng).is_none());
    assert!(
        (!PU::zero_with_limbs(1))
            .next_probable_prime(&mut rng)
            .is_none()
    );
}

#[cfg(feature = "rand_core")]
#[test]
fn random_trait_errors_are_preserved() {
    #[derive(Debug, PartialEq, Eq)]
    struct Failure;
    impl core::fmt::Display for Failure {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("測試 RNG 錯誤")
        }
    }
    impl core::error::Error for Failure {}
    struct Failing;
    impl rand_core::TryRng for Failing {
        type Error = Failure;
        fn try_next_u32(&mut self) -> Result<u32, Failure> {
            Err(Failure)
        }
        fn try_next_u64(&mut self) -> Result<u64, Failure> {
            Err(Failure)
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Failure> {
            Err(Failure)
        }
    }
    assert_eq!(
        PU::try_random_bits(&mut Failing, 1),
        Err(RandomBitsError::RandCore(Failure))
    );
    assert_eq!(
        <PU as RandomMod>::try_random_mod_vartime(
            &mut Failing,
            &NonZero::new(small(3, 4)).unwrap()
        ),
        Err(Failure)
    );
    assert_eq!(
        PU::try_random_bits_with_precision(&mut Failing, 2, 1),
        Err(RandomBitsError::BitLengthTooLarge {
            bit_length: 2,
            bits_precision: 1
        })
    );
}

#[test]
fn readme_pu_column_matches_the_implemented_contracts() {
    fn checked<
        T: CheckedAdd
            + CheckedSub
            + CheckedMul
            + CheckedDiv
            + CheckedRem
            + CheckedShl
            + CheckedShr
            + OverflowingAdd
            + OverflowingSub
            + OverflowingMul
            + WrappingAdd
            + WrappingSub
            + WrappingMul
            + SaturatingAdd
            + SaturatingSub
            + SaturatingMul,
    >() {
    }
    fn arithmetic<
        T: Pow<u32, Output = T>
            + Square<Output = T>
            + DivRem<Quotient = T, Remainder = T>
            + RemEuclid<Output = T>
            + Gcd<Output = T>
            + ModInverse<Output = T>
            + ModPow<Output = T>
            + ModAdd<Output = T>
            + ModSub<Output = T>
            + ModMul<Output = T>
            + BitOps<Output = T>
            + AndNot<Output = T>,
    >() {
    }
    fn conversions<T: FromPrimitive + ToPrimitive + ArrayEncoding + ToStrRadix>() {}
    checked::<PU>();
    arithmetic::<PU>();
    conversions::<PU>();
    #[cfg(feature = "rand_core")]
    {
        fn random<
            T: RandomBits
                + RandomMod
                + ProbablePrime
                + IsProbablePrime
                + NextProbablePrime<Output = Option<T>>,
        >() {
        }
        random::<PU>();
    }
    let readme = include_str!("../../README.md");
    let mut headings = 0;
    let mut rows = 0;
    // 欄位位置由標題列決定，日後新增欄位不會讓這個測試壞掉。
    let mut column = None;
    for line in readme.lines().filter(|line| line.starts_with('|')) {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        if cells.get(1) == Some(&"Trait") {
            column = cells.iter().position(|cell| *cell == "PU");
            assert!(column.is_some(), "README 的標題列少了 PU 欄：{line}");
            headings += 1;
            continue;
        }
        let Some(index) = column else { continue };
        if cells.len() > index && cells[1].starts_with('`') {
            let blank = matches!(
                cells[1],
                "`Bounded`" | "`Random`" | "`Signed`" | "`CheckedNeg` `WrappingNeg`"
            );
            assert_eq!(cells[index], if blank { "" } else { "✓" }, "{line}");
            rows += 1;
        }
    }
    assert_eq!(headings, 6);
    assert_eq!(rows, 25);
}
