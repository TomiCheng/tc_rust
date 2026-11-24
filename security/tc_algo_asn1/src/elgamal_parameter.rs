use tc_algo::params::key::ElGamalParameters;
use tc_asn1::{Asn1Integer, Asn1Object, NamedOid};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_zeroize::Zeroizing;

use crate::AlgoAsn1Error;

// ElGamalAlgorithm of OIW, the OID of Bouncy Castle's PublicKeyFactory and PrivateKeyFactory
pub(crate) const ELGAMAL_ALGORITHM: NamedOid = NamedOid::new(
    &[0x2b, 0x0e, 0x07, 0x02, 0x01, 0x01],
    "1.3.14.7.2.1.1",
    "ElGamalAlgorithm",
);

// Bouncy Castle's ElGamalParameter, SEQUENCE { p INTEGER, g INTEGER }. The length of the private
// value is not in it, so a group read back has none
pub(crate) fn object(params: &ElGamalParameters) -> Asn1Object {
    Asn1Object::sequence(vec![
        Asn1Object::Integer(integer(params.p())),
        Asn1Object::Integer(integer(params.g())),
    ])
}

// The group and the width of p, to pad the key to; None when the parameters are not an
// ElGamalParameter of positive integers
pub(crate) fn read(parameters: Option<&Asn1Object>) -> Option<(ElGamalParameters, usize)> {
    let Some(Asn1Object::SequenceOf(sequence)) = parameters else {
        return None;
    };
    let [Asn1Object::Integer(p), Asn1Object::Integer(g)] = sequence.elements() else {
        return None;
    };
    if p.is_negative() || g.is_negative() {
        return None;
    }
    let width = p.as_unsigned_bytes().ok()?.len();
    let params = ElGamalParameters::new(padded(p, width).ok()?, padded(g, width).ok()?);
    Some((params, width))
}

pub(crate) fn integer(value: &PaddedBigUint) -> Asn1Integer {
    Asn1Integer::from_unsigned_bytes(&ArrayEncoding::<u8>::to_be(value))
}

// `value` at the width of p, as the DSA rows pad
pub(crate) fn padded(value: &Asn1Integer, width: usize) -> Result<PaddedBigUint, AlgoAsn1Error> {
    let bytes = value.as_unsigned_bytes()?;
    let mut buffer = Zeroizing::new(vec![0; width.max(bytes.len())]);
    let start = buffer.len() - bytes.len();
    buffer[start..].copy_from_slice(bytes);
    let Ok(value) = PaddedBigUint::from_be(&buffer[..]);
    Ok(value)
}
