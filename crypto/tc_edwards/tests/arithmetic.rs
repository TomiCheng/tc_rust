use tc_edwards::{EdwardsPoint, Fe, Scalar};

#[test]
fn ed25519_fixed_base_consumes_every_bit() {
    let mut encoded = [0x66; 32];
    encoded[0] = 0x58;
    let base = EdwardsPoint::<Fe>::decode(&encoded).unwrap();
    for scalar in [
        [0_u8; 32],
        [255; 32],
        {
            let mut b = [0; 32];
            b[31] = 128;
            b
        },
        {
            let mut b = [0; 32];
            b[0] = 1;
            b
        },
    ] {
        let (x, y, z, t) = tc_rfc7748::ed25519_base::scalar_mult_base(&scalar);
        let actual = EdwardsPoint::<Fe>::from_extended(x, y, z, t);
        assert!(actual.equals(&base.multiply(&scalar)));
    }
}
#[test]
fn scalar_reduction_and_mul_add_match_integer_oracle() {
    let modulus = [101_u32];
    for a in 0..300_u32 {
        for b in [0, 1, 100, 101, 255, 65535_u32] {
            let x = Scalar::<1>::reduce(&a.to_le_bytes(), &modulus);
            let y = Scalar::<1>::reduce(&b.to_le_bytes(), &modulus);
            let mut out = [0; 4];
            x.mul_add(&y, &x, &modulus).encode(&mut out);
            assert_eq!(u32::from_le_bytes(out), (a * b + a) % 101);
        }
    }
    // Carry through a full-width modulus, rather than only small moduli.
    let modulus = [u32::MAX - 4];
    let a = Scalar::<1>::reduce(&u64::MAX.to_le_bytes(), &modulus);
    let mut out = [0; 4];
    a.encode(&mut out);
    assert_eq!(
        u32::from_le_bytes(out) as u64,
        u64::MAX % (modulus[0] as u64)
    );
}
