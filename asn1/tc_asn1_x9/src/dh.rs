//! X9.42 Diffie-Hellman domain parameters and public keys, the key format
//! of `dhpublicnumber`.
//!
//! In a SubjectPublicKeyInfo, the algorithm is [`X9Algorithm::DH_PUBLIC_NUMBER`]
//! with the domain parameters as its parameters, and the BIT STRING holds the
//! encoded public value:
//!
//! ```
//! use tc_asn1::{Asn1BitString, Decode, DecodingOptions, Encode, EncodingOptions};
//! use tc_asn1_x9::X9Algorithm;
//! use tc_asn1_x9::dh::{DhPublicKey, DomainParameters};
//!
//! // A toy group: p = 2·11 + 1, and 4 generates the subgroup of order 11.
//! let params = DomainParameters::new(23.into(), 4.into(), 11.into()).with_j(2.into());
//! // y = 4^3 mod 23.
//! let public = DhPublicKey::new(18.into());
//!
//! let algorithm = X9Algorithm::DH_PUBLIC_NUMBER.oid();
//! let parameters = params.encode_to_vec(&EncodingOptions::DER)?;
//! let subject_public_key =
//!     Asn1BitString::from_bytes(&public.encode_to_vec(&EncodingOptions::DER)?);
//!
//! // The receiver decodes both halves before checking y against the group.
//! assert_eq!(algorithm.to_string(), "1.2.840.10046.2.1");
//! let params = DomainParameters::decode_der(&parameters, &DecodingOptions::default())?.1;
//! let public = DhPublicKey::decode_der(subject_public_key.as_bytes(), &DecodingOptions::default())?.1;
//! assert_eq!((params.p(), public.y()), (&23.into(), &18.into()));
//! # Ok::<(), tc_asn1::Asn1Error>(())
//! ```
//!
//! [`X9Algorithm::DH_PUBLIC_NUMBER`]: crate::X9Algorithm::DH_PUBLIC_NUMBER

mod dh_public_key;
mod domain_parameters;
mod validation_params;

pub use dh_public_key::DhPublicKey;
pub use domain_parameters::DomainParameters;
pub use validation_params::ValidationParams;
