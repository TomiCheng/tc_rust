//! RFC 5280 §4.1.2 `TBSCertificate`, the signed part of a certificate.
//!
//! ```text
//! TBSCertificate ::= SEQUENCE {
//!     version              [0] EXPLICIT Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     issuerUniqueID       [1] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     subjectUniqueID      [2] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     extensions           [3] EXPLICIT Extensions OPTIONAL         -- v3
//! }
//!
//! Version ::= INTEGER { v1(0), v2(1), v3(2) }
//! CertificateSerialNumber ::= INTEGER
//! UniqueIdentifier ::= BIT STRING
//! ```
//!
//! The version is implied by what is present: extensions need v3, unique
//! identifiers need v2 or v3. The serial number is meant to be positive and
//! at most 20 octets, but RFC 5280 asks decoders to accept what CAs have
//! issued, so it is kept as is. The unique identifiers are obsolete; they
//! are read for old certificates and MUST NOT be generated.
//!
//! Signature verification needs the octets exactly as received, not a
//! re-encoding; the enclosing `Certificate` keeps those.

use tc_asn1::{Asn1BitString, Asn1Integer};
use tc_asn1_x500::Name;

use crate::{AlgorithmIdentifier, Extensions, SubjectPublicKeyInfo, Validity};

/// The certificate version, `Version ::= INTEGER { v1(0), v2(1), v3(2) }`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Version {
    V1,
    V2,
    V3,
}

/// The fields a CA signs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsCertificate {
    version: Version,
    serial_number: Asn1Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: Option<Asn1BitString>,
    subject_unique_id: Option<Asn1BitString>,
    extensions: Option<Extensions>,
}
