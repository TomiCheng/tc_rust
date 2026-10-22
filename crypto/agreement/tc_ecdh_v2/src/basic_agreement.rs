use crate::EcdhError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC's `ECDHBasicAgreement`, IEEE P1363's ECSVDP-DH: the x coordinate of dQ. Initialize it
/// with a key on a Ct curve to keep d secret.
pub struct EcdhBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    key: Option<EcPrivateKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcdhBasicAgreement<C> {
    pub fn new() -> Self {
        Self { key: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcdhBasicAgreement<C> {
    fn default() -> Self {
        Self::new()
    }
}

/// Keeps a copy of the key, whose d is wiped when the agreement is dropped.
impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<EcPrivateKey<C>> for EcdhBasicAgreement<C> {
    type Error = EcdhError;

    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcdhError> {
        self.key = Some(key.clone());
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcdhBasicAgreement<C> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcdhError;

    /// BC's `GetFieldSize`: the bytes of a coordinate. Panics before `init`.
    fn agreement_size(&self) -> usize {
        let key = self.key.as_ref().expect("the agreement is initialized");
        key.g().curve().one().encoded_length()
    }

    /// The x coordinate of dQ, big-endian, into the front of `output`. As constant time in d
    /// as the curve's multiplication.
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcdhError> {
        let key = self.key.as_ref().ok_or(EcdhError::NotInitialized)?;
        let x = agreement_x(key, public_key)?;
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcdhError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}

// BC's `CalculateAgreementFieldElement`. With a cofactor h other than one, Q is first
// multiplied by h, which takes any small-subgroup part away, and d by the inverse of h
// modulo n, which leaves dQ unchanged; that product is constant time.
fn agreement_x<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
) -> Result<C::Field, EcdhError> {
    if key.g() != public_key.g() {
        return Err(EcdhError::WrongDomain);
    }
    let curve = key.g().curve();
    let mut q =
        clean_point(curve.clone(), public_key.q()).map_err(|_| EcdhError::InvalidPublicKey)?;
    if q.is_infinity() {
        return Err(EcdhError::InvalidPublicKey);
    }

    let mut scaled = None;
    if let Some(h) = curve.cofactor().filter(|h| **h != PaddedBigUint::from(1u8)) {
        let n = curve.order().expect("a private key's curve has an order");
        let params = PaddedMontyParams::new(Odd::new(n.clone()).expect("n is an odd prime"));
        let h_inverse = PaddedMontyForm::new(h, &params)
            .invert()
            .ok_or(EcdhError::InvalidCofactor)?;
        let mut d = PaddedMontyForm::new(key.d(), &params);
        d *= &h_inverse;
        scaled = Some(Zeroizing::new(d.retrieve()));
        d.zeroize();
        q = C::multiply(&q, h);
    }

    let d = scaled.as_deref().unwrap_or(key.d());
    let p = C::multiply(&q, d);
    if p.is_infinity() {
        return Err(EcdhError::InvalidAgreement);
    }
    Ok(p.x().expect("a finite point"))
}
