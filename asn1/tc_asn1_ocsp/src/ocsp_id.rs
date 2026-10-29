//! RFC 6960 identifiers under `id-pkix-ocsp`, as Bouncy Castle's
//! `OcspObjectIdentifiers` names them: the basic response type and the OCSP
//! extensions.
//!
//! This table names known identifiers without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// The OCSP response types and extensions.
///
/// ```
/// use tc_asn1_ocsp::OcspId;
///
/// assert_eq!(OcspId::NONCE.dotted(), "1.3.6.1.5.5.7.48.1.2");
/// assert_eq!(
///     OcspId::from_oid(&OcspId::PKIX_OCSP.oid()),
///     Some(OcspId::PKIX_OCSP),
/// );
/// ```
pub struct OcspId;

impl OcspId {
    /// The id-pkix-ocsp arc, also the OCSP access method.
    pub const PKIX_OCSP: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01],
        "1.3.6.1.5.5.7.48.1",
        "id-pkix-ocsp",
    );

    /// The basic response type, a `BasicOCSPResponse`.
    pub const BASIC: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
        "1.3.6.1.5.5.7.48.1.1",
        "id-pkix-ocsp-basic",
    );

    /// The nonce extension, binding a response to its request.
    pub const NONCE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02],
        "1.3.6.1.5.5.7.48.1.2",
        "id-pkix-ocsp-nonce",
    );

    /// The CRL References extension, a `CrlID`.
    pub const CRL: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x03],
        "1.3.6.1.5.5.7.48.1.3",
        "id-pkix-ocsp-crl",
    );

    /// The Acceptable Response Types extension.
    pub const RESPONSE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x04],
        "1.3.6.1.5.5.7.48.1.4",
        "id-pkix-ocsp-response",
    );

    /// The certificate extension that exempts a responder certificate from checks.
    pub const NOCHECK: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05],
        "1.3.6.1.5.5.7.48.1.5",
        "id-pkix-ocsp-nocheck",
    );

    /// The Archive Cutoff extension.
    pub const ARCHIVE_CUTOFF: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x06],
        "1.3.6.1.5.5.7.48.1.6",
        "id-pkix-ocsp-archive-cutoff",
    );

    /// The Service Locator extension, a `ServiceLocator`.
    pub const SERVICE_LOCATOR: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x07],
        "1.3.6.1.5.5.7.48.1.7",
        "id-pkix-ocsp-service-locator",
    );

    /// The Preferred Signature Algorithms extension.
    pub const PREF_SIG_ALGS: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x08],
        "1.3.6.1.5.5.7.48.1.8",
        "id-pkix-ocsp-pref-sig-algs",
    );

    /// The Extended Revoked Definition extension.
    pub const EXTENDED_REVOKE: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x09],
        "1.3.6.1.5.5.7.48.1.9",
        "id-pkix-ocsp-extended-revoke",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::PKIX_OCSP,
        Self::BASIC,
        Self::NONCE,
        Self::CRL,
        Self::RESPONSE,
        Self::NOCHECK,
        Self::ARCHIVE_CUTOFF,
        Self::SERVICE_LOCATOR,
        Self::PREF_SIG_ALGS,
        Self::EXTENDED_REVOKE,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
