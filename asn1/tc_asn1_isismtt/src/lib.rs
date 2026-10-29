//! Common PKI (formerly ISIS-MTT) certificate attributes and OCSP extensions,
//! after Bouncy Castle's `Asn1.IsisMtt`: admissions and professions,
//! procuration, monetary limits, declarations of majority, and the certHash
//! and requestedCertificate OCSP extensions.

#![no_std]

extern crate alloc;

mod additional_information_syntax;
mod admission_syntax;
mod admissions;
mod cert_hash;
mod declaration_of_majority;
mod full_age_at_country;
mod isis_mtt_id;
mod monetary_limit;
mod naming_authority;
mod procuration_syntax;
mod profession_info;
mod requested_certificate;
mod restriction;
mod signing_for;

pub use additional_information_syntax::AdditionalInformationSyntax;
pub use admission_syntax::AdmissionSyntax;
pub use admissions::Admissions;
pub use cert_hash::CertHash;
pub use declaration_of_majority::DeclarationOfMajority;
pub use full_age_at_country::FullAgeAtCountry;
pub use isis_mtt_id::IsisMttId;
pub use monetary_limit::MonetaryLimit;
pub use naming_authority::NamingAuthority;
pub use procuration_syntax::ProcurationSyntax;
pub use profession_info::ProfessionInfo;
pub use requested_certificate::RequestedCertificate;
pub use restriction::Restriction;
pub use signing_for::SigningFor;
