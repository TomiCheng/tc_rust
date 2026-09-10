//! 公開值 trait 與文件契約的回歸測試。

use crate::*;
use PaddedBigInt as PI;
use alloc::{vec, vec::Vec};

struct Sequence(u64);
impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn value(&mut self, width: usize) -> PI {
        PI::from_limbs((0..width).map(|_| Limb::new(self.next() as Word)).collect())
    }
}
fn small(value: i64, width: usize) -> PI {
    PI::from_big_int(&BigInt::from(value), width).unwrap()
}
fn check(value: PI, expected: &BigInt, width: usize) {
    assert_eq!(value.len(), width);
    assert_eq!(&value.to_big_int(), expected);
}
fn limits(width: usize) -> (BigInt, BigInt) {
    if width == 0 {
        return (BigInt::zero(), BigInt::zero());
    }
    let half = BigInt::one() << (width * Word::BITS as usize - 1);
    (-&half, half - BigInt::one())
}
fn wrapped(exact: &BigInt, width: usize) -> BigInt {
    if width == 0 {
        return BigInt::zero();
    }
    let modulus = BigInt::one() << (width * Word::BITS as usize);
    let half = &modulus >> 1;
    let value = exact.rem_euclid(&modulus);
    if value >= half {
        value - modulus
    } else {
        value
    }
}
fn fits(exact: &BigInt, width: usize) -> bool {
    let (min, max) = limits(width);
    exact >= &min && exact <= &max
}

#[test]
fn two_hundred_mixed_width_cases_match_bigint_for_each_arithmetic_policy() {
    let mut rng = Sequence(0x9123_4376_8291_aaff);
    for i in 0..200 {
        let (left_width, right_width) = [(4, 1), (1, 4), (1, 1), (4, 4)][i % 4];
        let a = rng.value(left_width);
        let b = rng.value(right_width);
        let x = a.to_big_int();
        let y = b.to_big_int();
        let width = left_width.max(right_width);
        let (minimum, maximum) = limits(width);
        macro_rules! arithmetic {
            ($op:tt, $assign:tt, $checked:ident, $overflowing:ident, $wrapping:ident, $saturating:ident, $core:ident) => {{
                let exact = &x $op &y;
                let expected_overflow = !fits(&exact, width);
                let (result, overflow) = a.$overflowing(&b);
                assert_eq!(overflow, expected_overflow);
                check(result, &wrapped(&exact, width), width);
                check(a.$wrapping(&b), &wrapped(&exact, width), width);
                assert_eq!(a.$checked(&b).map(|v| v.to_big_int()), (!expected_overflow).then(|| exact.clone()));
                let saturating = if exact < minimum { minimum.clone() }
                    else if exact > maximum { maximum.clone() } else { exact.clone() };
                check(a.$saturating(&b), &saturating, width);
                let (aa, bb) = super::ops::aligned(&a, &b);
                let (ct_result, ct_overflow) = PI::$core(&aa, &bb);
                assert_eq!(ct_overflow, expected_overflow);
                check(ct_result, &wrapped(&exact, width), width);
                if expected_overflow {
                    assert!(std::panic::catch_unwind(|| &a $op &b).is_err());
                    let mut unchanged = a.clone();
                    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { unchanged $assign &b; })).is_err());
                    assert_eq!(unchanged, a);
                    assert_eq!(unchanged.len(), a.len());
                } else {
                    check(&a $op &b, &exact, width);
                    check(a.clone() $op &b, &exact, width);
                    check(&a $op b.clone(), &exact, width);
                    check(a.clone() $op b.clone(), &exact, width);
                    let mut assigned = a.clone(); assigned $assign &b; check(assigned, &exact, width);
                    let mut assigned = a.clone(); assigned $assign b.clone(); check(assigned, &exact, width);
                }
            }};
        }
        arithmetic!(+, +=, checked_add, overflowing_add, wrapping_add, saturating_add, add);
        arithmetic!(-, -=, checked_sub, overflowing_sub, wrapping_sub, saturating_sub, sub);
        arithmetic!(*, *=, checked_mul, overflowing_mul, wrapping_mul, saturating_mul, mul_core);
    }
}

#[test]
fn two_hundred_cases_match_bigint_for_division_bits_signs_and_shifts() {
    let mut rng = Sequence(0x8877_6655_4433_2211);
    for i in 0..200 {
        let a = rng.value(if i % 2 == 0 { 4 } else { 1 });
        let b = rng.value(if i % 3 == 0 { 4 } else { 1 });
        let x = a.to_big_int();
        let y = b.to_big_int();
        let width = a.len().max(b.len());
        macro_rules! binary {
            ($op:tt, $assign:tt) => {{
                let exact = &x $op &y;
                check(&a $op &b, &exact, width);
                check(a.clone() $op &b, &exact, width);
                check(&a $op b.clone(), &exact, width);
                check(a.clone() $op b.clone(), &exact, width);
                let mut out = a.clone(); out $assign &b; check(out, &exact, width);
                let mut out = a.clone(); out $assign b.clone(); check(out, &exact, width);
            }};
        }
        binary!(/, /=);
        binary!(%, %=);
        binary!(&, &=);
        binary!(|, |=);
        binary!(^, ^=);
        let (q, r) = a.div_rem(&b);
        check(q, &(&x / &y), width);
        check(r, &(&x % &y), width);
        check(a.checked_div(&b).unwrap(), &(&x / &y), width);
        check(a.checked_rem(&b).unwrap(), &(&x % &y), width);
        check(a.rem_euclid(&b), &x.rem_euclid(&y), width);
        check(a.gcd(&b), &x.gcd(&y), width);
        check(a.and_not(&b), &x.and_not(&y), width);
        check(!&a, &!&x, a.len());
        check(!a.clone(), &!&x, a.len());
        assert_eq!(a.cmp(&b), x.cmp(&y));
        assert_eq!(a.bit_length(), x.bit_length());
        assert_eq!(a.bit_count(), x.bit_count());
        assert_eq!(a.lowest_set_bit(), x.lowest_set_bit());
        let index = (rng.next() as usize) % (a.len() * Word::BITS as usize);
        for bit in [index, a.len() * Word::BITS as usize + 7] {
            assert_eq!(a.test_bit(bit), x.test_bit(bit));
        }
        check(
            a.set_bit(index),
            &wrapped(&x.set_bit(index), a.len()),
            a.len(),
        );
        check(
            a.clear_bit(index),
            &wrapped(&x.clear_bit(index), a.len()),
            a.len(),
        );
        check(
            a.flip_bit(index),
            &wrapped(&x.flip_bit(index), a.len()),
            a.len(),
        );
        let shift = index;
        check(&a << shift, &wrapped(&(&x << shift), a.len()), a.len());
        check(
            a.clone() << shift,
            &wrapped(&(&x << shift), a.len()),
            a.len(),
        );
        check(&a >> shift, &(&x >> shift), a.len());
        check(a.clone() >> shift, &(&x >> shift), a.len());
        let mut out = a.clone();
        out <<= shift;
        check(out, &wrapped(&(&x << shift), a.len()), a.len());
        let mut out = a.clone();
        out >>= shift;
        check(out, &(&x >> shift), a.len());
        assert_eq!(
            a.checked_shl(shift as u32).map(|v| v.to_big_int()),
            fits(&(&x << shift), a.len()).then(|| &x << shift)
        );
        check(
            a.checked_shr(shift as u32).unwrap(),
            &(&x >> shift),
            a.len(),
        );
        check(-&a, &-&x, a.len());
        check(-a.clone(), &-&x, a.len());
        check(a.wrapping_neg(), &wrapped(&-&x, a.len()), a.len());
        check(a.checked_neg().unwrap(), &-&x, a.len());
        check(a.abs(), &x.abs(), a.len());
        check(a.signum(), &x.signum(), a.len());
        assert_eq!(a.is_positive(), x.is_positive());
        assert_eq!(a.is_negative(), x.is_negative());
        let exact = x.abs_sub(&y);
        if fits(&exact, width) {
            check(a.abs_sub(&b), &exact, width);
        } else {
            assert!(std::panic::catch_unwind(|| a.abs_sub(&b)).is_err());
        }
    }
}

#[test]
fn two_hundred_modular_and_power_cases_match_bigint() {
    let mut rng = Sequence(0x1357_9abc_def0_2468);
    for i in 0..200 {
        let x = BigInt::from((rng.next() % 31) as i64 - 15);
        let y = BigInt::from((rng.next() % 43) as i64 - 21);
        let exponent = (rng.next() % 6) as u32;
        let m = BigInt::from((rng.next() % 43 + 1) as i64);
        let a = PI::from_big_int(&x, if i % 2 == 0 { 4 } else { 1 }).unwrap();
        let b = PI::from_big_int(&y, 1).unwrap();
        let modulus = PI::from_big_int(&m, if i % 3 == 0 { 4 } else { 1 }).unwrap();
        let e = small(exponent as i64, 1);
        check(a.mod_add(&b, &modulus), &x.mod_add(&y, &m), modulus.len());
        check(a.mod_sub(&b, &modulus), &x.mod_sub(&y, &m), modulus.len());
        check(a.mod_mul(&b, &modulus), &x.mod_mul(&y, &m), modulus.len());
        check(
            a.mod_pow(&e, &modulus),
            &x.mod_pow(&BigInt::from(exponent), &m),
            modulus.len(),
        );
        let actual = a.mod_inverse(&modulus);
        if let Some(ref value) = actual {
            assert_eq!(value.len(), modulus.len());
        }
        assert_eq!(actual.map(|v| v.to_big_int()), x.mod_inverse(&m));
        let power = Pow::pow(&x, exponent);
        check(Pow::pow(&a, exponent), &power, a.len());
        check(Pow::pow(a.clone(), exponent), &power, a.len());
        check(Pow::pow(&a, &exponent), &power, a.len());
        check(Pow::pow(a.clone(), &exponent), &power, a.len());
        check(a.square(), &x.square(), a.len());
    }
}

#[test]
fn explicit_signed_overflow_and_zero_divisors() {
    let (min, max) = limits(1);
    let minimum = PI::from_big_int(&min, 1).unwrap();
    let maximum = PI::from_big_int(&max, 1).unwrap();
    let one = small(1, 1);
    let minus_one = small(-1, 1);
    assert!(PI::add(&maximum, &one).1);
    assert!(PI::sub(&minimum, &one).1);
    assert!(!PI::add(&minus_one, &one).1);
    assert!(!PI::sub(&small(0, 1), &one).1);
    assert!(minimum.checked_neg().is_none());
    assert_eq!(minimum.wrapping_neg(), minimum);
    assert!(std::panic::catch_unwind(|| -&minimum).is_err());
    assert!(std::panic::catch_unwind(|| minimum.abs()).is_err());
    assert!(minimum.checked_div(&minus_one).is_none());
    assert!(std::panic::catch_unwind(|| &minimum / &minus_one).is_err());
    // 取餘直接委派 BigInt：MIN % -1 是可表示的零，沒有商轉換溢位。
    assert!(minimum.checked_rem(&minus_one).unwrap().is_zero());
    assert!((&minimum % &minus_one).is_zero());
    assert_eq!(minimum.saturating_mul(&minus_one), maximum);
    assert_eq!(minimum.saturating_mul(&small(2, 1)), minimum);
    assert!(std::panic::catch_unwind(|| Pow::pow(&maximum, 2)).is_err());
    assert!(std::panic::catch_unwind(|| Pow::pow(&PI::zero(), 0)).is_err());
    assert!(Pow::pow(&PI::zero(), 3).is_empty());
    let zero = PI::zero();
    assert!(one.checked_div(&zero).is_none());
    assert!(one.checked_rem(&zero).is_none());
    assert!(std::panic::catch_unwind(|| &one / &zero).is_err());
    assert!(std::panic::catch_unwind(|| &one % &zero).is_err());
    assert!(std::panic::catch_unwind(|| one.mod_mul(&one, &zero)).is_err());
    assert!(std::panic::catch_unwind(|| one.mod_mul(&one, &minus_one)).is_err());
}

#[test]
fn primitive_string_and_array_conversions_keep_their_width_contracts() {
    for value in [i64::MIN, -129, -1, 0, 127, i64::MAX] {
        let a = PI::from_i64(value).unwrap();
        assert_eq!(a.len(), limbs_for_bits(64));
        assert_eq!(a.to_i64(), Some(value));
        assert_eq!(a.to_u64(), u64::try_from(value).ok());
        assert_eq!(PI::from(value), a);
        assert_eq!(a.to_i128(), Some(value as i128));
        assert_eq!(a.to_u128(), u128::try_from(value).ok());
        let big = BigInt::from(value);
        for radix in [2, 8, 10, 16, 36] {
            let encoded = big.to_str_radix(radix);
            let parsed = PI::from_str_radix(&encoded, radix).unwrap();
            assert_eq!(parsed.len(), big.as_limbs().len());
            assert_eq!(parsed, a);
            assert_eq!(a.to_str_radix(radix), encoded);
        }
        assert_eq!(big.to_str_radix(10).parse::<PI>().unwrap(), a);
        assert_eq!(
            alloc::format!("{a:+} {a:#x} {a:#X} {a:#o} {a:#b}"),
            alloc::format!("{big:+} {big:#x} {big:#X} {big:#o} {big:#b}")
        );
    }
    assert!(PI::from_u128(u128::MAX).is_none());
    assert_eq!(PI::from_u8(255).unwrap().to_i64(), Some(255));
    assert_eq!(
        <PI as ArrayEncoding>::from_be_bytes(&[0xff, 0xfe]).unwrap(),
        small(-2, 1)
    );
    assert_eq!(
        <PI as ArrayEncoding>::from_unsigned_be_bytes(&[0xff, 0xfe]).unwrap(),
        small(65534, 1)
    );
    for width in [0, 1, 4] {
        for value in if width == 0 {
            vec![0]
        } else {
            vec![-129, -1, 0, 127, 255]
        } {
            let a = small(value, width);
            let big = a.to_big_int();
            macro_rules! encoding {
                ($ty:ty, $decode:ident, $unsigned_decode:ident, $write:ident, $uwrite:ident, $encode:ident, $uencode:ident, $length:ident, $ulength:ident) => {{
                    let full = a.$encode();
                    assert_eq!(full.len(), a.$length());
                    let roundtrip = <PI as ArrayEncoding>::$decode(&full).unwrap();
                    assert_eq!(roundtrip, a);
                    assert_eq!(
                        roundtrip.len(),
                        limbs_for_bits(full.len() * <$ty>::BITS as usize)
                    );
                    assert_eq!(a.$uencode(), big.$uencode());
                    assert_eq!(a.$ulength(), big.$ulength());
                    let unsigned = <PI as ArrayEncoding>::$unsigned_decode(&a.$uencode());
                    if let Ok(value) = unsigned {
                        assert_eq!(value.to_big_int(), big.abs());
                    }
                    for size in [0, full.len().saturating_sub(1), full.len(), full.len() + 2] {
                        let mut output = vec![0x55 as $ty; size];
                        let result = <PI as ArrayEncoding>::$write(&a, &mut output);
                        if size < full.len() {
                            assert_eq!(result, Err(ConversionError::BufferTooSmall));
                            assert!(output.iter().all(|&v| v == 0x55));
                        } else {
                            assert_eq!(result, Ok(full.len()));
                            assert_eq!(&output[..full.len()], &full);
                            assert!(output[full.len()..].iter().all(|&v| v == 0x55));
                        }
                        let mut expected = vec![0x55 as $ty; size];
                        let mut output = expected.clone();
                        assert_eq!(
                            <PI as ArrayEncoding>::$uwrite(&a, &mut output),
                            big.$uwrite(&mut expected)
                        );
                        assert_eq!(output, expected);
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
    }
}

#[test]
fn ct_sources_never_delegate_or_normalize() {
    for source in [
        include_str!("add.rs"),
        include_str!("sub.rs"),
        include_str!("mul.rs"),
        include_str!("shift.rs"),
    ] {
        let code = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "significant_len(",
            "bit_len(",
            "is_zero(",
            "to_big_int(",
            "from_big_int(",
            "normalize",
        ] {
            assert!(!code.contains(forbidden), "CT 路徑包含 {forbidden}");
        }
        assert!(
            !code
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|token| token == "BigInt" || token == "BigUint")
        );
    }
    // 這是回歸防護，不是常數時間證明，也無法攔住手寫的變動時間除法。
}

#[test]
fn every_operator_impl_has_a_variable_time_doc() {
    for source in [
        include_str!("ops.rs"),
        include_str!("bits.rs"),
        include_str!("div.rs"),
        include_str!("neg.rs"),
        include_str!("str.rs"),
    ] {
        let lines: Vec<_> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let line = line.trim_start();
            if line.starts_with("impl core::ops::")
                || line.starts_with("impl Pow")
                || line.starts_with("impl fmt::")
            {
                let docs = lines[..index]
                    .iter()
                    .rev()
                    .take_while(|line| {
                        line.trim().starts_with("///") || line.trim().starts_with("#[doc")
                    })
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(
                    docs.contains("變動時間：只能用於公開值"),
                    "缺少變動時間文件：{line}"
                );
            }
        }
    }
}

#[test]
fn readme_pi_column_matches_the_implemented_contracts() {
    fn numeric<T: Num + NumOps + NumRef + NumAssign + NumAssignOps + NumAssignRef + Signed>() {}
    fn references<T>()
    where
        for<'a> &'a T: RefNum<T>,
    {
    }
    fn checked<
        T: CheckedAdd
            + CheckedSub
            + CheckedMul
            + CheckedDiv
            + CheckedRem
            + CheckedNeg
            + CheckedShl
            + CheckedShr
            + OverflowingAdd
            + OverflowingSub
            + OverflowingMul
            + WrappingAdd
            + WrappingSub
            + WrappingMul
            + WrappingNeg
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
    numeric::<PI>();
    references::<PI>();
    checked::<PI>();
    arithmetic::<PI>();
    conversions::<PI>();
    #[cfg(feature = "rand_core")]
    {
        fn random<
            T: RandomBits + ProbablePrime + IsProbablePrime + NextProbablePrime<Output = Option<T>>,
        >() {
        }
        random::<PI>();
    }
    let mut headings = 0;
    let mut rows = 0;
    // 欄位位置由標題列決定，日後新增欄位不會讓這個測試壞掉。
    let mut column = None;
    for line in include_str!("../../README.md")
        .lines()
        .filter(|line| line.starts_with('|'))
    {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        if cells.get(1) == Some(&"Trait") {
            column = cells.iter().position(|cell| *cell == "PI");
            assert!(column.is_some(), "README 的標題列少了 PI 欄：{line}");
            headings += 1;
            continue;
        }
        let Some(index) = column else { continue };
        if cells.len() > index && cells[1].starts_with('`') {
            let blank = matches!(
                cells[1],
                "`Bounded`" | "`Random`" | "`Unsigned`" | "`RandomMod`"
            );
            assert_eq!(cells[index], if blank { "" } else { "✓" }, "{line}");
            rows += 1;
        }
    }
    assert_eq!(headings, 6);
    assert_eq!(rows, 25);
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
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(feature = "rand_core")]
#[test]
fn random_bits_preserve_full_nonnegative_range_and_explicit_sign_precision() {
    let mut rng = Sequence(0x7465_8291_aafb_1379);
    for bits in [0, 1, 7, 31, 32, 33, 63, 64, 65, 100, 128] {
        let limit = BigInt::one() << bits as usize;
        for _ in 0..200 {
            let value = PI::random_bits(&mut rng, bits);
            assert_eq!(value.len(), limbs_for_bits(bits as usize + 1));
            assert!(!value.is_negative());
            assert!(value.to_big_int() < limit);
            let value = PI::random_bits_with_precision(&mut rng, bits, bits + 129);
            assert_eq!(value.len(), limbs_for_bits(bits as usize + 129));
            assert!(!value.is_negative());
            assert!(value.to_big_int() < limit);
        }
        assert!(PI::try_random_bits_with_precision(&mut rng, bits, bits).is_err());
    }
    struct Ones;
    impl rand_core::TryRng for Ones {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::MAX)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::MAX)
        }
        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            output.fill(0xff);
            Ok(())
        }
    }
    for bits in [31, 32, 63, 64, 128] {
        let maximum = (BigInt::one() << bits as usize) - BigInt::one();
        check(
            PI::random_bits(&mut Ones, bits),
            &maximum,
            limbs_for_bits(bits as usize + 1),
        );
        check(
            PI::random_bits_with_precision(&mut Ones, bits, bits + 1),
            &maximum,
            limbs_for_bits(bits as usize + 1),
        );
    }
    for bits in [2, 3, 8, 9] {
        let value = PI::probable_prime(&mut rng, bits);
        assert_eq!(value.len(), limbs_for_bits(bits as usize + 1));
        assert_eq!(value.bit_length(), bits as usize);
        assert!(value.is_probable_prime(30, &mut rng));
    }
    check(
        small(17, 4).next_probable_prime(&mut rng).unwrap(),
        &BigInt::from(19),
        4,
    );
    assert!(PI::zero().next_probable_prime(&mut rng).is_none());
    let max = PI::from_big_int(&limits(1).1, 1).unwrap();
    assert!(max.next_probable_prime(&mut rng).is_none());
}

#[cfg(feature = "rand_core")]
#[test]
fn random_errors_propagate_and_bad_precision_does_not_consume_rng() {
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
        PI::try_random_bits(&mut Failing, 1),
        Err(RandomBitsError::RandCore(Failure))
    );
    assert_eq!(
        PI::try_random_bits_with_precision(&mut Failing, 1, 2),
        Err(RandomBitsError::RandCore(Failure))
    );
    for (bits, precision) in [(0, 0), (1, 1), (2, 1)] {
        assert_eq!(
            PI::try_random_bits_with_precision(&mut Failing, bits, precision),
            Err(RandomBitsError::BitLengthTooLarge {
                bit_length: bits,
                bits_precision: precision
            })
        );
    }
}
