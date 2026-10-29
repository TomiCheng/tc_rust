//! ESS attribute types under `id-aa`, as Bouncy Castle's `PkcsObjectIdentifiers`
//! names them.
//!
//! `id-aa-contentHint` is in tc_asn1_cms; this table names known attributes
//! without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// RFC 2634 and RFC 5035 signed attribute types.
///
/// ```
/// use tc_asn1_ess::EssAttribute;
///
/// assert_eq!(EssAttribute::SIGNING_CERTIFICATE_V2.dotted(), "1.2.840.113549.1.9.16.2.47");
/// assert_eq!(
///     EssAttribute::from_oid(&EssAttribute::RECEIPT_REQUEST.oid()),
///     Some(EssAttribute::RECEIPT_REQUEST),
/// );
/// ```
pub struct EssAttribute;

impl EssAttribute {
    /// A request for a signed receipt.
    pub const RECEIPT_REQUEST: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x01,
        ],
        "1.2.840.113549.1.9.16.2.1",
        "id-aa-receiptRequest",
    );

    /// A security label.
    pub const SECURITY_LABEL: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x02,
        ],
        "1.2.840.113549.1.9.16.2.2",
        "id-aa-securityLabel",
    );

    /// The mail lists a message was expanded by.
    pub const ML_EXPAND_HISTORY: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x03,
        ],
        "1.2.840.113549.1.9.16.2.3",
        "id-aa-mlExpandHistory",
    );

    /// The digest of the signed attributes a receipt answers.
    pub const MSG_SIG_DIGEST: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x05,
        ],
        "1.2.840.113549.1.9.16.2.5",
        "id-aa-msgSigDigest",
    );

    /// A `ContentIdentifier`.
    pub const CONTENT_IDENTIFIER: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x07,
        ],
        "1.2.840.113549.1.9.16.2.7",
        "id-aa-contentIdentifier",
    );

    /// Security labels equivalent to the one given.
    pub const EQUIVALENT_LABELS: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x09,
        ],
        "1.2.840.113549.1.9.16.2.9",
        "id-aa-equivalentLabels",
    );

    /// A reference to the original content.
    pub const CONTENT_REFERENCE: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0a,
        ],
        "1.2.840.113549.1.9.16.2.10",
        "id-aa-contentReference",
    );

    /// A `SigningCertificate`.
    pub const SIGNING_CERTIFICATE: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c,
        ],
        "1.2.840.113549.1.9.16.2.12",
        "id-aa-signingCertificate",
    );

    /// A `SigningCertificateV2`.
    pub const SIGNING_CERTIFICATE_V2: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
        ],
        "1.2.840.113549.1.9.16.2.47",
        "id-aa-signingCertificateV2",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::RECEIPT_REQUEST,
        Self::SECURITY_LABEL,
        Self::ML_EXPAND_HISTORY,
        Self::MSG_SIG_DIGEST,
        Self::CONTENT_IDENTIFIER,
        Self::EQUIVALENT_LABELS,
        Self::CONTENT_REFERENCE,
        Self::SIGNING_CERTIFICATE,
        Self::SIGNING_CERTIFICATE_V2,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
