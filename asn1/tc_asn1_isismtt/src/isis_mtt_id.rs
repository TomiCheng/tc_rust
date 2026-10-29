//! Common PKI (ISIS-MTT) identifiers, as Bouncy Castle's
//! `IsisMttObjectIdentifiers` names them.
//!
//! This table names known identifiers without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// The Common PKI certificate policy and its attribute and extension types.
///
/// ```
/// use tc_asn1_isismtt::IsisMttId;
///
/// assert_eq!(IsisMttId::ADMISSION.dotted(), "1.3.36.8.3.3");
/// assert_eq!(
///     IsisMttId::from_oid(&IsisMttId::ISIS_MTT.oid()),
///     Some(IsisMttId::ISIS_MTT),
/// );
/// ```
pub struct IsisMttId;

impl IsisMttId {
    /// The Common PKI arc.
    pub const ISIS_MTT: NamedOid = NamedOid::new(&[0x2b, 0x24, 0x08], "1.3.36.8", "id-isismtt");

    /// The arc of certificate policies.
    pub const CP: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x08, 0x01], "1.3.36.8.1", "id-isismtt-cp");

    /// The policy of accredited CAs.
    pub const CP_ACCREDITED: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x01, 0x01],
        "1.3.36.8.1.1",
        "id-isismtt-cp-accredited",
    );

    /// The arc of attributes and extensions.
    pub const AT: NamedOid =
        NamedOid::new(&[0x2b, 0x24, 0x08, 0x03], "1.3.36.8.3", "id-isismtt-at");

    /// When the certificate was generated.
    pub const DATE_OF_CERT_GEN: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x01],
        "1.3.36.8.3.1",
        "id-isismtt-at-dateOfCertGen",
    );

    /// A `ProcurationSyntax`.
    pub const PROCURATION: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x02],
        "1.3.36.8.3.2",
        "id-isismtt-at-procuration",
    );

    /// An `AdmissionSyntax`.
    pub const ADMISSION: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x03],
        "1.3.36.8.3.3",
        "id-isismtt-at-admission",
    );

    /// A `MonetaryLimit`.
    pub const MONETARY_LIMIT: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x04],
        "1.3.36.8.3.4",
        "id-isismtt-at-monetaryLimit",
    );

    /// A `DeclarationOfMajority`.
    pub const DECLARATION_OF_MAJORITY: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x05],
        "1.3.36.8.3.5",
        "id-isismtt-at-declarationOfMajority",
    );

    /// The serial number of the smart card.
    pub const ICCSN: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x06],
        "1.3.36.8.3.6",
        "id-isismtt-at-iCCSN",
    );

    /// A reference to the public key.
    pub const PK_REFERENCE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x07],
        "1.3.36.8.3.7",
        "id-isismtt-at-PKReference",
    );

    /// A `Restriction`.
    pub const RESTRICTION: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x08],
        "1.3.36.8.3.8",
        "id-isismtt-at-restriction",
    );

    /// Whether to return the certificate in OCSP.
    pub const RETRIEVE_IF_ALLOWED: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x09],
        "1.3.36.8.3.9",
        "id-isismtt-at-retrieveIfAllowed",
    );

    /// A `RequestedCertificate`.
    pub const REQUESTED_CERTIFICATE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0a],
        "1.3.36.8.3.10",
        "id-isismtt-at-requestedCertificate",
    );

    /// The naming authorities of the CA.
    pub const NAMING_AUTHORITIES: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0b],
        "1.3.36.8.3.11",
        "id-isismtt-at-namingAuthorities",
    );

    /// Since when the certificate is in the directory.
    pub const CERT_IN_DIR_SINCE: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0c],
        "1.3.36.8.3.12",
        "id-isismtt-at-certInDirSince",
    );

    /// A `CertHash`.
    pub const CERT_HASH: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0d],
        "1.3.36.8.3.13",
        "id-isismtt-at-certHash",
    );

    /// The holder's name at birth.
    pub const NAME_AT_BIRTH: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0e],
        "1.3.36.8.3.14",
        "id-isismtt-at-nameAtBirth",
    );

    /// An `AdditionalInformationSyntax`.
    pub const ADDITIONAL_INFORMATION: NamedOid = NamedOid::new(
        &[0x2b, 0x24, 0x08, 0x03, 0x0f],
        "1.3.36.8.3.15",
        "id-isismtt-at-additionalInformation",
    );

    /// Whether liability is limited.
    pub const LIABILITY_LIMITATION_FLAG: NamedOid = NamedOid::new(
        &[0x02, 0x82, 0x06, 0x01, 0x0a, 0x0c, 0x00],
        "0.2.262.1.10.12.0",
        "id-isismtt-at-liabilityLimitationFlag",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::ISIS_MTT,
        Self::CP,
        Self::CP_ACCREDITED,
        Self::AT,
        Self::DATE_OF_CERT_GEN,
        Self::PROCURATION,
        Self::ADMISSION,
        Self::MONETARY_LIMIT,
        Self::DECLARATION_OF_MAJORITY,
        Self::ICCSN,
        Self::PK_REFERENCE,
        Self::RESTRICTION,
        Self::RETRIEVE_IF_ALLOWED,
        Self::REQUESTED_CERTIFICATE,
        Self::NAMING_AUTHORITIES,
        Self::CERT_IN_DIR_SINCE,
        Self::CERT_HASH,
        Self::NAME_AT_BIRTH,
        Self::ADDITIONAL_INFORMATION,
        Self::LIABILITY_LIMITATION_FLAG,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
