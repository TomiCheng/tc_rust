//! CAdES attribute types under `id-aa-ets`, as Bouncy Castle's `EsfAttributes`
//! names them.
//!
//! This table names known attributes without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// RFC 5126 signed and unsigned attribute types.
///
/// ```
/// use tc_asn1_esf::EsfAttribute;
///
/// assert_eq!(EsfAttribute::SIG_POLICY_ID.dotted(), "1.2.840.113549.1.9.16.2.15");
/// assert_eq!(
///     EsfAttribute::from_oid(&EsfAttribute::SIG_POLICY_ID.oid()),
///     Some(EsfAttribute::SIG_POLICY_ID),
/// );
/// ```
pub struct EsfAttribute;

impl EsfAttribute {
    /// A `SignaturePolicyIdentifier`.
    pub const SIG_POLICY_ID: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0f,
        ],
        "1.2.840.113549.1.9.16.2.15",
        "id-aa-ets-sigPolicyId",
    );

    /// A `CommitmentTypeIndication`.
    pub const COMMITMENT_TYPE: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x10,
        ],
        "1.2.840.113549.1.9.16.2.16",
        "id-aa-ets-commitmentType",
    );

    /// A `SignerLocation`.
    pub const SIGNER_LOCATION: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x11,
        ],
        "1.2.840.113549.1.9.16.2.17",
        "id-aa-ets-signerLocation",
    );

    /// A `SignerAttribute`.
    pub const SIGNER_ATTR: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x12,
        ],
        "1.2.840.113549.1.9.16.2.18",
        "id-aa-ets-signerAttr",
    );

    /// An `OtherSigningCertificate`.
    pub const OTHER_SIG_CERT: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x13,
        ],
        "1.2.840.113549.1.9.16.2.19",
        "id-aa-ets-otherSigCert",
    );

    /// A time-stamp token over the content.
    pub const CONTENT_TIMESTAMP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x14,
        ],
        "1.2.840.113549.1.9.16.2.20",
        "id-aa-ets-contentTimestamp",
    );

    /// A `CompleteCertificateRefs`.
    pub const CERTIFICATE_REFS: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x15,
        ],
        "1.2.840.113549.1.9.16.2.21",
        "id-aa-ets-CertificateRefs",
    );

    /// A `CompleteRevocationRefs`.
    pub const REVOCATION_REFS: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x16,
        ],
        "1.2.840.113549.1.9.16.2.22",
        "id-aa-ets-revocationRefs",
    );

    /// A `CertificateValues`.
    pub const CERT_VALUES: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x17,
        ],
        "1.2.840.113549.1.9.16.2.23",
        "id-aa-ets-certValues",
    );

    /// A `RevocationValues`.
    pub const REVOCATION_VALUES: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x18,
        ],
        "1.2.840.113549.1.9.16.2.24",
        "id-aa-ets-revocationValues",
    );

    /// A time-stamp over the signature and references.
    pub const ESC_TIME_STAMP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x19,
        ],
        "1.2.840.113549.1.9.16.2.25",
        "id-aa-ets-escTimeStamp",
    );

    /// A time-stamp over the references alone.
    pub const CERT_CRL_TIMESTAMP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x1a,
        ],
        "1.2.840.113549.1.9.16.2.26",
        "id-aa-ets-certCRLTimestamp",
    );

    /// An archive time-stamp, version 1.
    pub const ARCHIVE_TIMESTAMP: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x1b,
        ],
        "1.2.840.113549.1.9.16.2.27",
        "id-aa-ets-archiveTimestamp",
    );

    /// An archive time-stamp, version 2.
    pub const ARCHIVE_TIMESTAMP_V2: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x30,
        ],
        "1.2.840.113549.1.9.16.2.48",
        "id-aa-ets-archiveTimestampV2",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::SIG_POLICY_ID,
        Self::COMMITMENT_TYPE,
        Self::SIGNER_LOCATION,
        Self::SIGNER_ATTR,
        Self::OTHER_SIG_CERT,
        Self::CONTENT_TIMESTAMP,
        Self::CERTIFICATE_REFS,
        Self::REVOCATION_REFS,
        Self::CERT_VALUES,
        Self::REVOCATION_VALUES,
        Self::ESC_TIME_STAMP,
        Self::CERT_CRL_TIMESTAMP,
        Self::ARCHIVE_TIMESTAMP,
        Self::ARCHIVE_TIMESTAMP_V2,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
