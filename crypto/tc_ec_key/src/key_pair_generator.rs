use crate::{EcError, EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint, RandomBits};
use tc_ec_core_v2::multiplier::{BaseMultiplier, PerCall};
use tc_ec_core_v2::{Curve, Point};
use tc_zeroize::Zeroize;

/// BC's `ECKeyPairGenerator`. Pass the generator of a Ct curve to have d·G computed in
/// constant time.
///
/// `init` builds an `M` for G, so the key pairs it generates reuse its table. `M` defaults to
/// [`PerCall`], which multiplies as the curve does.
pub struct EcKeyPairGenerator<'a, C: Curve, M = PerCall<C>> {
    state: Option<(EcKeyGenerationParams<'a, C>, M)>,
}

impl<C: Curve> EcKeyPairGenerator<'_, C> {
    /// A generator multiplying as the curve does, to be initialized. Constant time.
    pub fn new() -> Self {
        Self::with_multiplier()
    }
}

impl<C: Curve, M: BaseMultiplier<C>> EcKeyPairGenerator<'_, C, M> {
    /// A generator multiplying by `M`, to be initialized. Constant time.
    pub fn with_multiplier() -> Self {
        Self { state: None }
    }
}

impl<C: Curve, M: BaseMultiplier<C>> Default for EcKeyPairGenerator<'_, C, M> {
    fn default() -> Self {
        Self::with_multiplier()
    }
}

/// X9.62 5.2.1, as BC's `GenerateKeyPair`: d from `private_scalar`, then Q = d·G by `M`.
impl<C: Curve<Scalar = PaddedBigUint>, M: BaseMultiplier<C>> KeyPairGenerator
    for EcKeyPairGenerator<'_, C, M>
{
    type PublicKey = EcPublicKey<C>;
    type PrivateKey = EcPrivateKey<C>;
    type Error = EcError;

    fn generate_key_pair(&mut self) -> Result<(EcPublicKey<C>, EcPrivateKey<C>), EcError> {
        let (params, multiplier) = self.state.as_mut().ok_or(EcError::NotInitialized)?;
        let curve = params.g.curve();
        let n = curve.order().ok_or(EcError::MissingOrder)?;
        let d = private_scalar(n, params.rng);
        let q = multiplier.multiply(&d);
        let private_key = EcPrivateKey::new(params.g.clone(), d)?;
        let public_key = EcPublicKey::new(params.g.clone(), &q)?;
        Ok((public_key, private_key))
    }
}

/// Checks G as BC's `ECDomainParameters` does: its curve must know n, and G must not be
/// infinity and must pass `is_valid`; then builds an `M` for G. Variable time; G is public.
impl<'a, C: Curve<Scalar = PaddedBigUint>, M: BaseMultiplier<C>>
    KeyPairGeneratorInit<EcKeyGenerationParams<'a, C>> for EcKeyPairGenerator<'a, C, M>
{
    type Error = EcError;

    fn init(&mut self, params: EcKeyGenerationParams<'a, C>) -> Result<(), EcError> {
        if params.g.curve().order().is_none() {
            return Err(EcError::MissingOrder);
        }
        if params.g.is_infinity() || !params.g.is_valid() {
            return Err(EcError::InvalidGenerator);
        }
        let multiplier = M::new(params.g.clone());
        self.state = Some((params, multiplier));
        Ok(())
    }
}

// BC's `GeneratePrivateScalar`: draws of n's bit length until one lies in [1, n - 1] and its
// NAF has at least a quarter as many nonzero digits as n has bits, against a sparse d. Only
// the draws thrown away decide how many are taken, and each is wiped.
fn private_scalar(n: &PaddedBigUint, rng: &mut dyn CryptoRng) -> PaddedBigUint {
    let bits = n.bits();
    let one = PaddedBigUint::from(1u8);
    loop {
        let mut d = PaddedBigUint::random_bits(rng, bits);
        if d >= one && d < *n && naf_weight(&d) >= bits / 4 {
            return d;
        }
        d.zeroize();
    }
}

// BC's `WNafUtilities.GetNafWeight` in constant time: the nonzero digits of the NAF of k are
// the set bits of 3k XOR k, summed here byte by byte with the carry, over k's public width.
fn naf_weight(k: &PaddedBigUint) -> u32 {
    let mut bytes = ArrayEncoding::<u8>::to_le(k);
    let (mut weight, mut carry, mut previous) = (0, 0u16, 0u8);
    for i in 0..=bytes.len() {
        let byte = bytes.get(i).copied().unwrap_or(0);
        let doubled = (byte << 1) | (previous >> 7);
        let sum = u16::from(byte) + u16::from(doubled) + carry;
        weight += ((sum as u8) ^ byte).count_ones();
        carry = sum >> 8;
        previous = byte;
    }
    bytes[..].zeroize();
    weight
}

#[cfg(test)]
mod tests {
    use super::{EcKeyPairGenerator, naf_weight};
    use crate::{EcError, EcKeyGenerationParams, EcPrivateKey, EcPublicKey};
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::{PaddedBigUint, RandomBits};
    use tc_ec_core_v2::wnaf::get_naf_weight;
    use tc_ec_core_v2::{Curve, Point};
    use tc_f2m_curve_v2::F2mCtCurve;
    use tc_f2m_curve_v2::named_curves::SECT283K1;
    use tc_fp_curve_v2::FpCtCurve;
    use tc_fp_curve_v2::named_curves::SECP256R1;

    #[test]
    fn the_constant_time_naf_weight_is_the_one_core_counts() {
        let mut rng = rand::rng();
        for bits in [1, 7, 8, 63, 64, 65, 255, 256] {
            for _ in 0..32 {
                let k = PaddedBigUint::random_bits(&mut rng, bits);
                let expected = get_naf_weight::<&FpCtCurve<'_>>(&k);
                assert_eq!(naf_weight(&k) as usize, expected, "bits = {bits}");
            }
        }
    }

    fn check<C: Curve<Scalar = PaddedBigUint>>(g: C::Point) {
        let mut rng = rand::rng();
        let mut generator = EcKeyPairGenerator::<C>::new();
        generator
            .init(EcKeyGenerationParams::new(g.clone(), &mut rng))
            .unwrap();
        let n = g.curve().order().unwrap().clone();
        for _ in 0..4 {
            let (public, private) = generator.generate_key_pair().unwrap();
            assert!(*private.d() >= PaddedBigUint::from(1u8) && *private.d() < n);
            assert!(*public.q() == C::multiply(&g, private.d()));
            assert!(public.q().is_valid());
        }
    }

    #[test]
    fn generated_keys_have_d_below_n_and_q_equal_to_d_times_g() {
        let field = SECP256R1.field();
        let curve = SECP256R1.ct_curve(&field);
        check::<&FpCtCurve<'_>>(SECP256R1.ct_generator(&curve));

        let curve = SECT283K1.ct_curve();
        check::<&F2mCtCurve>(SECT283K1.ct_generator(&curve));
    }

    #[test]
    fn the_generator_refuses_to_run_uninitialized_or_on_infinity() {
        let field = SECP256R1.field();
        let curve = SECP256R1.ct_curve(&field);
        let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
        assert_eq!(
            generator.generate_key_pair().err(),
            Some(EcError::NotInitialized)
        );

        let mut rng = rand::rng();
        let params = EcKeyGenerationParams::new(curve.infinity(), &mut rng);
        assert_eq!(generator.init(params), Err(EcError::InvalidGenerator));
    }

    #[test]
    fn keys_refuse_a_scalar_outside_one_to_n_minus_one_and_infinity() {
        let field = SECP256R1.field();
        let curve = SECP256R1.ct_curve(&field);
        let g = SECP256R1.ct_generator(&curve);
        let n = curve.order().unwrap().clone();
        type Ct<'a> = &'a FpCtCurve<'a>;

        for d in [PaddedBigUint::from(0u8), n.clone()] {
            assert_eq!(
                EcPrivateKey::<Ct<'_>>::new(g.clone(), d).err(),
                Some(EcError::InvalidPrivateScalar)
            );
        }
        assert!(EcPrivateKey::<Ct<'_>>::new(g.clone(), PaddedBigUint::from(1u8)).is_ok());
        assert_eq!(
            EcPublicKey::<Ct<'_>>::new(g.clone(), &curve.infinity()).err(),
            Some(EcError::InvalidPublicPoint)
        );
        assert!(EcPublicKey::<Ct<'_>>::new(g.clone(), &g).is_ok());
    }
}
