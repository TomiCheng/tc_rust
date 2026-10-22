use crate::EcdsaError;
use alloc::vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_ec_core::multiplier::{BaseMultiplier, PerCall};
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC's `ECDsaSigner`, drawing each signature's k from the calculator `K`. Initialize it with
/// a key on a Ct curve to keep d and k secret.
///
/// Each `init` builds an `M` for G, and for Q when verifying, so signing or verifying many
/// times under one key reuses their tables. `M` defaults to [`PerCall`], which multiplies as
/// the curve does.
pub struct EcdsaSigner<C: Curve<Scalar = PaddedBigUint>, K, M = PerCall<C>> {
    k_calculator: K,
    state: Option<State<C, M>>,
}

struct State<C: Curve<Scalar = PaddedBigUint>, M> {
    key: Key<C, M>,
    params: PaddedMontyParams,
}

enum Key<C: Curve<Scalar = PaddedBigUint>, M> {
    Signing { key: EcPrivateKey<C>, g: M },
    Verifying { g: M, q: M },
}

impl<C: Curve<Scalar = PaddedBigUint>, K> EcdsaSigner<C, K> {
    /// A signer drawing k from `k_calculator` and multiplying as the curve does, to be
    /// initialized. Constant time.
    pub const fn new(k_calculator: K) -> Self {
        Self::with_multiplier(k_calculator)
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> EcdsaSigner<C, K, M> {
    /// A signer drawing k from `k_calculator` and multiplying by `M`, to be initialized.
    /// Constant time.
    pub const fn with_multiplier(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    fn init_key(
        &mut self,
        g: &C::Point,
        key: impl FnOnce() -> Key<C, M>,
    ) -> Result<(), EcdsaError> {
        self.state = None;
        let n = g.curve().order().cloned().ok_or(EcdsaError::MissingOrder)?;
        let n = Odd::new(n).ok_or(EcdsaError::MissingOrder)?;
        self.state = Some(State {
            key: key(),
            params: PaddedMontyParams::new(n),
        });
        Ok(())
    }
}

/// Keeps a copy of the key to sign with, whose d is wiped when the signer is dropped, and builds
/// an `M` for G. Fails for a curve without an odd order. Variable time: only for public values,
/// as n and G are.
impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPrivateKey<C>>
    for EcdsaSigner<C, K, M>
{
    type Error = EcdsaError;

    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcdsaError> {
        self.init_key(key.g(), || Key::Signing {
            key: key.clone(),
            g: M::new(key.g().clone()),
        })
    }
}

/// Builds an `M` for G and one for Q. Fails for a curve without an odd order. Variable time:
/// only for public values, as the key is.
impl<C: Curve<Scalar = PaddedBigUint>, K, M: BaseMultiplier<C>> DsaInit<EcPublicKey<C>>
    for EcdsaSigner<C, K, M>
{
    type Error = EcdsaError;

    fn init(&mut self, key: &EcPublicKey<C>) -> Result<(), EcdsaError> {
        self.init_key(key.g(), || Key::Verifying {
            g: M::new(key.g().clone()),
            q: M::new(key.q().clone()),
        })
    }
}

impl<C, K, M> Dsa for EcdsaSigner<C, K, M>
where
    C: Curve<Scalar = PaddedBigUint>,
    K: DsaKCalculator<PaddedBigUint>,
    M: BaseMultiplier<C>,
{
    type Integer = PaddedBigUint;
    type Error = EcdsaError;

    /// n. Panics before `init`. Constant time.
    fn order(&self) -> &PaddedBigUint {
        let state = self.state.as_ref().expect("the signer is initialized");
        state.params.modulus()
    }

    /// X9.62 5.3: r = (k·G).x mod n and s = k⁻¹(e + d·r) mod n, drawing k again while either
    /// is zero. As constant time in d and k as `M`'s multiplication; the modular steps are
    /// constant time.
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), EcdsaError> {
        let state = self.state.as_ref().ok_or(EcdsaError::NotInitialized)?;
        let Key::Signing { key, g } = &state.key else {
            return Err(EcdsaError::NotForSigning);
        };
        let params = &state.params;
        let n = params.modulus();
        let e = PaddedMontyForm::new(&calculate_e(n, message), params);
        let d = Zeroizing::new(PaddedMontyForm::new(key.d(), params));
        let zero = PaddedBigUint::from(0u8);

        self.k_calculator.init(n, key.d(), message);
        loop {
            let k = Zeroizing::new(self.k_calculator.next_k());
            let x = g
                .multiply(&k)
                .x()
                .expect("k·G is finite for k in [1, n − 1]");
            let r = field_to_integer(&x) % n;
            if r == zero {
                continue;
            }

            let k_inverse = Zeroizing::new(
                PaddedMontyForm::new(&k, params)
                    .invert()
                    .expect("k in [1, n − 1] is invertible modulo the prime n"),
            );
            let mut sum = Zeroizing::new(PaddedMontyForm::new(&r, params));
            *sum *= &*d;
            *sum += &e;
            *sum *= &*k_inverse;
            let s = sum.retrieve();
            if s != zero {
                return Ok((r, s));
            }
        }
    }

    /// X9.62 5.4: whether (u₁·G + u₂·Q).x mod n is r, for u₁ = e/s and u₂ = r/s. Ok(false) for
    /// r or s out of [1, n − 1]. Variable time: only for public values, as the key, the message
    /// and the signature are.
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, EcdsaError> {
        let state = self.state.as_ref().ok_or(EcdsaError::NotInitialized)?;
        let Key::Verifying { g, q } = &state.key else {
            return Err(EcdsaError::NotForVerifying);
        };
        let params = &state.params;
        let n = params.modulus();
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || *s == zero || r >= n || s >= n {
            return Ok(false);
        }

        let Some(c) = PaddedMontyForm::new(s, params).invert() else {
            return Ok(false);
        };
        let u1 = (PaddedMontyForm::new(&calculate_e(n, message), params) * &c).retrieve();
        let u2 = (PaddedMontyForm::new(r, params) * &c).retrieve();
        let point = g.multiply(&u1).add(&q.multiply(&u2));
        let Some(x) = point.x() else {
            return Ok(false);
        };
        Ok(field_to_integer(&x) % n == *r)
    }
}

// BC's `CalculateE`: the leftmost bits of the message, as many as n has.
fn calculate_e(n: &PaddedBigUint, message: &[u8]) -> PaddedBigUint {
    let Ok(mut e) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(message);
    let excess = (message.len() * 8).saturating_sub(n.bits() as usize);
    if excess > 0 {
        e >>= excess as u32;
    }
    e
}

// A field element as the integer its SEC 1 encoding reads as.
fn field_to_integer<F: FieldElement>(x: &F) -> PaddedBigUint {
    let mut bytes = Zeroizing::new(vec![0; x.encoded_length()]);
    x.encode_to(&mut bytes);
    let Ok(value) = <PaddedBigUint as ArrayEncoding<u8>>::from_be(&bytes);
    value
}
