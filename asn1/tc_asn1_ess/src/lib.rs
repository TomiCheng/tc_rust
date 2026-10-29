//! Enhanced security services (RFC 2634, RFC 5035) and S/MIME (RFC 8551)
//! attribute values, after Bouncy Castle's `Asn1.Ess` and `Asn1.Smime`:
//! signing certificate references, content hints and identifiers, and S/MIME
//! capabilities and key preferences.
//!
//! These types are attribute values; wrapping them in an X.501 `Attribute` with
//! the identifier from [`EssAttribute`] or [`SmimeAttribute`] is the caller's
//! job.

#![no_std]

extern crate alloc;

mod content_hints;
mod content_identifier;
mod ess_attribute;
mod ess_cert_id;
mod ess_cert_id_v2;
mod signing_certificate;
mod signing_certificate_v2;
mod smime_attribute;
mod smime_capabilities;
mod smime_capability;
mod smime_capability_id;
mod smime_encryption_key_preference;

pub use content_hints::ContentHints;
pub use content_identifier::ContentIdentifier;
pub use ess_attribute::EssAttribute;
pub use ess_cert_id::EssCertId;
pub use ess_cert_id_v2::EssCertIdV2;
pub use signing_certificate::SigningCertificate;
pub use signing_certificate_v2::SigningCertificateV2;
pub use smime_attribute::SmimeAttribute;
pub use smime_capabilities::SmimeCapabilities;
pub use smime_capability::SmimeCapability;
pub use smime_capability_id::SmimeCapabilityId;
pub use smime_encryption_key_preference::SmimeEncryptionKeyPreference;
