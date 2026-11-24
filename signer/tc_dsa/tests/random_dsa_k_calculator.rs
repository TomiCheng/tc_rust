use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{DsaKCalculator, RandomDsaKCalculator};

#[test]
fn every_k_falls_in_one_to_n_minus_one_and_each_of_them_turns_up() {
    let n = PaddedBigUint::from(7u8);
    let mut calculator = RandomDsaKCalculator::new(StdRng::seed_from_u64(1));
    calculator.init(&n, &PaddedBigUint::from(3u8), b"message");

    let mut seen = [false; 7];
    for _ in 0..200 {
        let k = calculator.next_k();
        assert!(k >= PaddedBigUint::from(1u8) && k < n);
        seen[usize::from(ArrayEncoding::<u8>::to_le(&k)[0])] = true;
    }
    assert_eq!(seen, [false, true, true, true, true, true, true]);
}

#[test]
fn init_rejects_empty_nonce_ranges() {
    for order in [0u8, 1] {
        assert!(
            std::panic::catch_unwind(|| {
                let mut calculator = RandomDsaKCalculator::new(StdRng::seed_from_u64(1));
                calculator.init(&PaddedBigUint::from(order), &PaddedBigUint::from(1u8), &[]);
            })
            .is_err()
        );
    }
}

#[test]
#[should_panic(expected = "the calculator is initialized")]
fn a_calculator_refuses_to_draw_before_init() {
    let mut calculator = RandomDsaKCalculator::new(StdRng::seed_from_u64(1));
    let _: PaddedBigUint = calculator.next_k();
}
