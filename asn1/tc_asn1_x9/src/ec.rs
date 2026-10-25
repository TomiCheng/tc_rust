//! X9.62 and SEC 1 elliptic-curve structures: explicit, named or inherited
//! curve parameters, private keys, ECDSA signatures and named-curve
//! identifiers.
//!
//! A P-256 private key in the RFC 5915 form, written and read back:
//!
//! ```
//! use tc_asn1::{Asn1BitString, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions};
//! use tc_asn1_x9::ec::{EcNamedCurve, EcPrivateKey, X962Parameters};
//!
//! // The scalar, the curve it belongs to, and the uncompressed public point.
//! let mut point = vec![0x04];
//! point.extend_from_slice(&[0x22; 64]);
//! let key = EcPrivateKey::new(Asn1OctetString::new(&[0x11; 32]))?
//!     .with_parameters(EcNamedCurve::PRIME256V1.oid().into())
//!     .with_public_key(Asn1BitString::from_bytes(&point));
//! let der = key.encode_to_vec(&EncodingOptions::DER)?;
//!
//! // The reader learns the curve from the parameters.
//! let key = EcPrivateKey::decode_der(&der, &DecodingOptions::default())?.1;
//! let Some(X962Parameters::NamedCurve(oid)) = key.parameters() else {
//!     unreachable!("written with a named curve");
//! };
//! assert_eq!(EcNamedCurve::from_oid(oid), Some(EcNamedCurve::PRIME256V1));
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```

mod characteristic_two;
mod curve;
mod ec_named_curve;
mod ec_private_key;
mod ecdsa_sig_value;
mod encoding;
mod field_id;
mod x962_parameters;
mod x9_ec_parameters;

pub use characteristic_two::{Basis, CharacteristicTwo, Pentanomial, UnknownBasis};
pub use curve::Curve;
pub use ec_named_curve::EcNamedCurve;
pub use ec_private_key::EcPrivateKey;
pub use ecdsa_sig_value::EcdsaSigValue;
pub use field_id::{FieldId, UnknownField};
pub use x9_ec_parameters::X9EcParameters;
pub use x962_parameters::X962Parameters;
