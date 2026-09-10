use alloc::vec::Vec;

use super::{MontyForm, MontyParams, PaddedMontyForm, PaddedMontyParams};
use crate::{BigUint, Limb, Odd, PaddedBigUint, Word};

/// 固定種子的 xorshift，讓隨機測試可以重現。
struct XorShift(u64);

impl XorShift {
    fn next_word(&mut self) -> Word {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as Word
    }

    /// 取一個寬度為 `limbs` 的奇數，且最高位 limb 非零。
    fn next_odd_modulus(&mut self, limbs: usize) -> PaddedBigUint {
        let mut words = (0..limbs).map(|_| self.next_word()).collect::<Vec<_>>();
        words[0] |= 1;
        words[limbs - 1] |= 1 << (Word::BITS - 1);
        from_words(&words)
    }

    fn next_value(&mut self, limbs: usize) -> PaddedBigUint {
        let words = (0..limbs).map(|_| self.next_word()).collect::<Vec<_>>();
        from_words(&words)
    }
}

fn from_words(words: &[Word]) -> PaddedBigUint {
    PaddedBigUint::from_limbs(words.iter().copied().map(Limb::new).collect())
}

fn small(value: u8, limbs: usize) -> PaddedBigUint {
    PaddedBigUint::from_be_bytes(&[value], limbs).unwrap()
}

fn params_for(modulus: &PaddedBigUint) -> PaddedMontyParams {
    PaddedMontyParams::new(Odd::new(modulus.clone()).unwrap())
}

/// 同一組模數的既有 heap 版參數，用來當作參考答案。
fn reference_params(modulus: &PaddedBigUint) -> MontyParams<BigUint> {
    MontyParams::new(Odd::new(modulus.to_big_uint()).unwrap())
}

#[test]
fn entering_the_domain_and_leaving_it_matches_the_variable_length_type() {
    let mut rng = XorShift(0x1f3b_9d02_74ac_5e61);

    for case in 0..200 {
        let width = case % 4 + 1;
        let modulus = rng.next_odd_modulus(width);
        let value = rng.next_value(width);

        let padded = PaddedMontyForm::new_ct(&value, params_for(&modulus));
        let reference = MontyForm::new(&value.to_big_uint(), reference_params(&modulus));

        assert_eq!(
            padded.retrieve().to_big_uint(),
            reference.retrieve(),
            "case {case}"
        );
        // 離開域之後仍然保持模數寬度。
        assert_eq!(padded.retrieve().len(), width, "case {case}");
    }
}

#[test]
fn the_variable_time_constructor_agrees_with_the_constant_time_one() {
    let mut rng = XorShift(0x4c07_31be_28fa_650d);

    for case in 0..200 {
        let width = case % 4 + 1;
        let modulus = rng.next_odd_modulus(width);
        let value = rng.next_value(width);
        let params = params_for(&modulus);

        assert_eq!(
            PaddedMontyForm::new(&value, params.clone()),
            PaddedMontyForm::new_ct(&value, params),
            "case {case}"
        );
    }
}

#[test]
fn constant_time_power_matches_the_variable_length_type() {
    let mut rng = XorShift(0x63c8_1a55_e097_2d4f);

    for case in 0..60 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);
        let base = rng.next_value(width);
        let exponent = rng.next_value(width);

        let padded = PaddedMontyForm::new_ct(&base, params_for(&modulus)).pow_ct(&exponent);
        let reference = MontyForm::new(&base.to_big_uint(), reference_params(&modulus))
            .pow(&exponent.to_big_uint());

        assert_eq!(
            padded.retrieve().to_big_uint(),
            reference.retrieve(),
            "case {case}"
        );
    }
}

#[test]
fn the_public_and_secret_power_paths_agree() {
    let mut rng = XorShift(0x0d47_e6b1_3a92_c85d);

    for case in 0..60 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);
        let base = rng.next_value(width);
        let exponent = rng.next_value(width);
        let params = params_for(&modulus);

        let form = PaddedMontyForm::new_ct(&base, params);
        assert_eq!(form.pow_ct(&exponent), form.pow(&exponent), "case {case}");
    }
}

#[test]
fn leading_zeros_in_the_exponent_do_not_change_the_result() {
    let modulus = from_words(&[101, 0, 0]);
    let params = params_for(&modulus);
    let form = PaddedMontyForm::new_ct(&small(7, 3), params);

    let narrow = small(3, 1).resize(3).unwrap();
    let wide = small(3, 3);
    assert_eq!(narrow, wide);

    // 7^3 = 343 = 3 * 101 + 40
    assert_eq!(form.pow_ct(&wide).retrieve(), small(40, 3));
    assert_eq!(form.pow_ct(&narrow).retrieve(), small(40, 3));
    assert_eq!(form.pow(&wide).retrieve(), small(40, 3));
}

#[test]
fn a_value_wider_than_the_modulus_reduces_correctly() {
    let mut rng = XorShift(0x4b21_09fe_57d3_6a8c);

    for case in 0..60 {
        let half = case % 3 + 1;
        let modulus = rng.next_odd_modulus(half);
        let wide = rng.next_value(2 * half);

        let padded = PaddedMontyForm::new_ct(&wide, params_for(&modulus));
        let reference = MontyForm::new(&wide.to_big_uint(), reference_params(&modulus));

        assert_eq!(
            padded.retrieve().to_big_uint(),
            reference.retrieve(),
            "case {case}"
        );
        assert_eq!(padded.retrieve().len(), half, "case {case}");
    }
}

#[test]
fn an_input_wider_than_twice_the_modulus_takes_the_horner_fallback() {
    let mut rng = XorShift(0x18f5_60b3_c479_2ade);

    for case in 0..40 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);

        // 三倍與五倍寬都超過拆半路徑的上界，只能走逐位元約簡。
        for multiple in [3, 5] {
            let wide = rng.next_value(multiple * width);
            let padded = PaddedMontyForm::new_ct(&wide, params_for(&modulus));
            let reference = MontyForm::new(&wide.to_big_uint(), reference_params(&modulus));

            assert_eq!(
                padded.retrieve().to_big_uint(),
                reference.retrieve(),
                "case {case}, {multiple} 倍寬"
            );
            assert_eq!(padded.retrieve().len(), width);
        }
    }
}

#[test]
fn both_domain_entry_paths_agree_at_the_width_boundary() {
    let mut rng = XorShift(0x2ea9_71c4_0d38_b5f7);

    for case in 0..60 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);
        let params = params_for(&modulus);

        // 恰好兩倍寬走拆半，多一個 limb 就退回 Horner；同一個數值兩邊要一致。
        let exact = rng.next_value(2 * width);
        let padded = exact
            .resize(2 * width + 1)
            .expect("widening never overflows");

        assert_eq!(
            PaddedMontyForm::new_ct(&exact, params.clone()).retrieve(),
            PaddedMontyForm::new_ct(&padded, params).retrieve(),
            "case {case}"
        );
    }
}

#[test]
fn domain_arithmetic_matches_plain_modular_arithmetic() {
    let mut rng = XorShift(0x39ad_5c74_1e60_b2f9);

    for case in 0..100 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);
        let lhs = rng.next_value(width);
        let rhs = rng.next_value(width);
        let params = params_for(&modulus);

        let left = PaddedMontyForm::new_ct(&lhs, params.clone());
        let right = PaddedMontyForm::new_ct(&rhs, params.clone());
        let modulus_big = modulus.to_big_uint();

        assert_eq!(
            (&left + &right).retrieve().to_big_uint(),
            (lhs.to_big_uint() + rhs.to_big_uint()) % &modulus_big,
            "add case {case}"
        );
        assert_eq!(
            (&left * &right).retrieve().to_big_uint(),
            (lhs.to_big_uint() * rhs.to_big_uint()) % &modulus_big,
            "mul case {case}"
        );
        assert_eq!(
            left.square().retrieve(),
            (&left * &left).retrieve(),
            "square case {case}"
        );
        assert_eq!(
            left.double().retrieve(),
            (&left + &left).retrieve(),
            "double case {case}"
        );
        // 減法在模意義下與加回模數一致。
        assert_eq!(
            ((&left - &right) + &right).retrieve(),
            left.retrieve(),
            "sub case {case}"
        );
    }
}

#[test]
fn the_domain_identities_hold() {
    let modulus = from_words(&[101, 0]);
    let params = params_for(&modulus);
    let value = PaddedMontyForm::new_ct(&small(7, 2), params.clone());

    assert_eq!(
        PaddedMontyForm::zero(params.clone()).retrieve(),
        small(0, 2)
    );
    assert_eq!(PaddedMontyForm::one(params.clone()).retrieve(), small(1, 2));
    assert_eq!(
        (&value * &PaddedMontyForm::one(params.clone())).retrieve(),
        small(7, 2)
    );
    assert_eq!(
        (&value + &PaddedMontyForm::zero(params.clone())).retrieve(),
        small(7, 2)
    );
    // 任何底數的零次方都是一。
    assert_eq!(value.pow_ct(&small(0, 2)).retrieve(), small(1, 2));
    assert_eq!(value.pow(&small(0, 2)).retrieve(), small(1, 2));
}

#[test]
fn parameters_built_twice_from_the_same_modulus_stay_compatible() {
    let modulus = from_words(&[101, 0]);
    // 兩組獨立建立的參數，Arc 位址不同，走逐 limb 的慢路徑。
    let first = params_for(&modulus);
    let second = params_for(&modulus);

    let left = PaddedMontyForm::new_ct(&small(7, 2), first);
    let right = PaddedMontyForm::new_ct(&small(9, 2), second);
    assert_eq!((&left + &right).retrieve(), small(16, 2));
}

#[test]
fn cloned_parameters_share_one_allocation() {
    let modulus = from_words(&[101, 0]);
    let params = params_for(&modulus);
    // clone 之後是同一份 Arc，走位址比較的快路徑。
    let left = PaddedMontyForm::new_ct(&small(7, 2), params.clone());
    let right = PaddedMontyForm::new_ct(&small(9, 2), params);
    assert_eq!((&left + &right).retrieve(), small(16, 2));
}

#[test]
#[should_panic(expected = "Montgomery forms use different moduli")]
fn forms_from_different_moduli_cannot_be_added() {
    let left = PaddedMontyForm::new_ct(&small(7, 2), params_for(&from_words(&[101, 0])));
    let right = PaddedMontyForm::new_ct(&small(7, 2), params_for(&from_words(&[103, 0])));
    let _ = &left + &right;
}

#[test]
fn the_odd_modular_inverse_matches_the_variable_length_type() {
    let mut rng = XorShift(0x7e14_c2a9_5b30_86df);

    for case in 0..60 {
        let width = case % 3 + 1;
        let modulus = rng.next_odd_modulus(width);
        let value = rng.next_value(width);
        // 反元素要求輸入小於模數，先化到域內再取回。
        let value = PaddedMontyForm::new_ct(&value, params_for(&modulus)).retrieve();

        let odd = Odd::new(modulus.clone()).unwrap();
        let Some(inverse) = value.mod_odd_inverse_ct(&odd) else {
            continue;
        };

        assert_eq!(inverse.len(), width, "case {case}");
        // value * inverse 應該在模意義下等於一。
        let params = params_for(&modulus);
        let product = &PaddedMontyForm::new_ct(&value, params.clone())
            * &PaddedMontyForm::new_ct(&inverse, params);
        assert_eq!(product.retrieve(), small(1, width), "case {case}");
    }
}

#[test]
fn a_non_invertible_value_reports_no_inverse() {
    // 模數是 3 的倍數，取一個共同因數的值。
    let modulus = from_words(&[9, 0]);
    let odd = Odd::new(modulus).unwrap();
    assert!(small(3, 2).mod_odd_inverse_ct(&odd).is_none());
    assert!(small(2, 2).mod_odd_inverse_ct(&odd).is_some());
}

#[test]
fn debug_output_reveals_the_width_but_not_the_value() {
    use alloc::format;

    let modulus = from_words(&[0xFFFF_FFF1, 0]);
    let form = PaddedMontyForm::new_ct(&from_words(&[0xDEAD_BEEF, 0]), params_for(&modulus));
    let rendered = format!("{form:?}");
    assert!(rendered.contains("2"), "{rendered}");
    assert!(!rendered.to_lowercase().contains("dead"), "{rendered}");
}

/// 秘密路徑的實作不得呼叫變動時間的輔助方法。
#[test]
fn secret_paths_do_not_call_variable_time_helpers() {
    let source = include_str!("padded_mul.rs");
    for forbidden in ["significant_len(", "bit_len(", "is_zero(", "test_bit("] {
        assert!(
            !source.contains(forbidden),
            "padded_mul.rs 的常數時間路徑呼叫了變動時間的 {forbidden}"
        );
    }

    // new_ct 必須跑滿輸入的儲存寬度，而變動時間的 new 才可以用除法。
    let form = include_str!("padded_form.rs");
    let secret = &form[form.find("pub fn new_ct").unwrap()..form.find("pub fn new(").unwrap()];
    assert!(
        secret.contains("value.len() * Word::BITS"),
        "new_ct 必須由儲存寬度決定圈數"
    );
    for forbidden in ["significant_len(", "bit_len(", "to_big_uint("] {
        assert!(
            !secret.contains(forbidden),
            "new_ct 呼叫了變動時間的 {forbidden}"
        );
    }

    // pow_ct 必須跑滿指數的儲存寬度，不得用 bit_len 決定起點。
    let pow = include_str!("padded_pow.rs");
    let secret = &pow[pow.find("pub fn pow_ct").unwrap()..pow.find("pub fn pow(").unwrap()];
    assert!(
        secret.contains("exponent.len() * Word::BITS"),
        "pow_ct 必須由儲存寬度決定圈數"
    );
    for forbidden in ["bit_len(", "test_bit("] {
        assert!(
            !secret.contains(forbidden),
            "pow_ct 呼叫了變動時間的 {forbidden}"
        );
    }
}
