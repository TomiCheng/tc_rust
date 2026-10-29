//! PKCS #9 (RFC 2985) attribute types, as Bouncy Castle's `PkcsObjectIdentifiers`
//! names them.
//!
//! This table names known attributes without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// PKCS #9 attribute types for certification requests, signers and PKCS #12 bags.
///
/// ```
/// use tc_asn1_pkcs::Pkcs9Attribute;
///
/// assert_eq!(Pkcs9Attribute::FRIENDLY_NAME.dotted(), "1.2.840.113549.1.9.20");
/// assert_eq!(
///     Pkcs9Attribute::from_oid(&Pkcs9Attribute::EMAIL_ADDRESS.oid()),
///     Some(Pkcs9Attribute::EMAIL_ADDRESS),
/// );
/// ```
pub struct Pkcs9Attribute;

impl Pkcs9Attribute {
    /// An e-mail address, as an IA5String.
    pub const EMAIL_ADDRESS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01],
        "1.2.840.113549.1.9.1",
        "emailAddress",
    );

    /// A name in free form.
    pub const UNSTRUCTURED_NAME: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x02],
        "1.2.840.113549.1.9.2",
        "unstructuredName",
    );

    /// The type of the content signed.
    pub const CONTENT_TYPE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03],
        "1.2.840.113549.1.9.3",
        "contentType",
    );

    /// The digest of the content signed.
    pub const MESSAGE_DIGEST: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04],
        "1.2.840.113549.1.9.4",
        "messageDigest",
    );

    /// When the signer says it signed.
    pub const SIGNING_TIME: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05],
        "1.2.840.113549.1.9.5",
        "signingTime",
    );

    /// A signature over another signature.
    pub const COUNTER_SIGNATURE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06],
        "1.2.840.113549.1.9.6",
        "counterSignature",
    );

    /// A password to revoke the certificate requested.
    pub const CHALLENGE_PASSWORD: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x07],
        "1.2.840.113549.1.9.7",
        "challengePassword",
    );

    /// An address in free form.
    pub const UNSTRUCTURED_ADDRESS: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x08],
        "1.2.840.113549.1.9.8",
        "unstructuredAddress",
    );

    /// Attributes for an extended certificate.
    pub const EXTENDED_CERTIFICATE_ATTRIBUTES: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x09],
        "1.2.840.113549.1.9.9",
        "extendedCertificateAttributes",
    );

    /// A description of the content signed.
    pub const SIGNING_DESCRIPTION: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0d],
        "1.2.840.113549.1.9.13",
        "signingDescription",
    );

    /// The extensions requested for a certificate.
    pub const EXTENSION_REQUEST: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e],
        "1.2.840.113549.1.9.14",
        "extensionRequest",
    );

    /// The algorithms an S/MIME agent supports.
    pub const SMIME_CAPABILITIES: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0f],
        "1.2.840.113549.1.9.15",
        "smimeCapabilities",
    );

    /// A name for a PKCS #12 bag, as a BMPString.
    pub const FRIENDLY_NAME: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14],
        "1.2.840.113549.1.9.20",
        "friendlyName",
    );

    /// A value that pairs a PKCS #12 key with its certificate.
    pub const LOCAL_KEY_ID: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15],
        "1.2.840.113549.1.9.21",
        "localKeyId",
    );

    /// An X.509 certificate in a PKCS #12 certificate bag.
    pub const X509_CERTIFICATE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01],
        "1.2.840.113549.1.9.22.1",
        "x509Certificate",
    );

    /// An SDSI certificate in a PKCS #12 certificate bag.
    pub const SDSI_CERTIFICATE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x02],
        "1.2.840.113549.1.9.22.2",
        "sdsiCertificate",
    );

    /// An X.509 CRL in a PKCS #12 CRL bag.
    pub const X509_CRL: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x17, 0x01],
        "1.2.840.113549.1.9.23.1",
        "x509Crl",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::EMAIL_ADDRESS,
        Self::UNSTRUCTURED_NAME,
        Self::CONTENT_TYPE,
        Self::MESSAGE_DIGEST,
        Self::SIGNING_TIME,
        Self::COUNTER_SIGNATURE,
        Self::CHALLENGE_PASSWORD,
        Self::UNSTRUCTURED_ADDRESS,
        Self::EXTENDED_CERTIFICATE_ATTRIBUTES,
        Self::SIGNING_DESCRIPTION,
        Self::EXTENSION_REQUEST,
        Self::SMIME_CAPABILITIES,
        Self::FRIENDLY_NAME,
        Self::LOCAL_KEY_ID,
        Self::X509_CERTIFICATE,
        Self::SDSI_CERTIFICATE,
        Self::X509_CRL,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
