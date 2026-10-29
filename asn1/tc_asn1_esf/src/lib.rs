//! CAdES electronic signature formats (RFC 5126, formerly RFC 3126) attribute
//! values, after Bouncy Castle's `Asn1.Esf`: signature policies, commitment
//! types, signer location and attributes, and the certificate and revocation
//! references and values of long-term signatures.
//!
//! These types are attribute values; wrapping them in an X.501 `Attribute` with
//! the identifier from [`EsfAttribute`] is the caller's job.

#![no_std]

extern crate alloc;

mod certificate_values;
mod commitment_type_identifier;
mod commitment_type_indication;
mod commitment_type_qualifier;
mod complete_certificate_refs;
mod complete_revocation_refs;
mod crl_identifier;
mod crl_list_id;
mod crl_ocsp_ref;
mod crl_validated_id;
mod esf_attribute;
mod ocsp_identifier;
mod ocsp_list_id;
mod ocsp_responses_id;
mod other_cert_id;
mod other_hash;
mod other_hash_alg_and_value;
mod other_rev_refs;
mod other_rev_vals;
mod other_signing_certificate;
mod revocation_values;
mod sig_policy_qualifier_info;
mod signature_policy_id;
mod signature_policy_identifier;
mod signer_attribute;
mod signer_attribute_entry;
mod signer_location;

pub use certificate_values::CertificateValues;
pub use commitment_type_identifier::CommitmentTypeIdentifier;
pub use commitment_type_indication::CommitmentTypeIndication;
pub use commitment_type_qualifier::CommitmentTypeQualifier;
pub use complete_certificate_refs::CompleteCertificateRefs;
pub use complete_revocation_refs::CompleteRevocationRefs;
pub use crl_identifier::CrlIdentifier;
pub use crl_list_id::CrlListId;
pub use crl_ocsp_ref::CrlOcspRef;
pub use crl_validated_id::CrlValidatedId;
pub use esf_attribute::EsfAttribute;
pub use ocsp_identifier::OcspIdentifier;
pub use ocsp_list_id::OcspListId;
pub use ocsp_responses_id::OcspResponsesId;
pub use other_cert_id::OtherCertId;
pub use other_hash::OtherHash;
pub use other_hash_alg_and_value::OtherHashAlgAndValue;
pub use other_rev_refs::OtherRevRefs;
pub use other_rev_vals::OtherRevVals;
pub use other_signing_certificate::OtherSigningCertificate;
pub use revocation_values::RevocationValues;
pub use sig_policy_qualifier_info::SigPolicyQualifierInfo;
pub use signature_policy_id::SignaturePolicyId;
pub use signature_policy_identifier::SignaturePolicyIdentifier;
pub use signer_attribute::SignerAttribute;
pub use signer_attribute_entry::SignerAttributeEntry;
pub use signer_location::SignerLocation;
