//! ICAO machine readable travel document identifiers, as Bouncy Castle's
//! `IcaoObjectIdentifiers` names them.
//!
//! This table names known identifiers without restricting which are used.

use tc_asn1::{Asn1Oid, NamedOid};

/// The MRTD security content types and extensions.
///
/// ```
/// use tc_asn1_icao::IcaoId;
///
/// assert_eq!(IcaoId::LDS_SECURITY_OBJECT.dotted(), "2.23.136.1.1.1");
/// assert_eq!(
///     IcaoId::from_oid(&IcaoId::ICAO.oid()),
///     Some(IcaoId::ICAO),
/// );
/// ```
pub struct IcaoId;

impl IcaoId {
    /// The ICAO arc.
    pub const ICAO: NamedOid = NamedOid::new(&[0x67, 0x81, 0x08], "2.23.136", "id-icao");

    /// The machine readable travel document arc.
    pub const MRTD: NamedOid =
        NamedOid::new(&[0x67, 0x81, 0x08, 0x01], "2.23.136.1", "id-icao-mrtd");

    /// The MRTD security arc.
    pub const MRTD_SECURITY: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01],
        "2.23.136.1.1",
        "id-icao-mrtd-security",
    );

    /// The content type of an `LdsSecurityObject`.
    pub const LDS_SECURITY_OBJECT: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x01],
        "2.23.136.1.1.1",
        "id-icao-ldsSecurityObject",
    );

    /// The content type of a `CscaMasterList`.
    pub const CSCA_MASTER_LIST: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x02],
        "2.23.136.1.1.2",
        "id-icao-cscaMasterList",
    );

    /// The key purpose of a master list signer.
    pub const CSCA_MASTER_LIST_SIGNING_KEY: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x03],
        "2.23.136.1.1.3",
        "id-icao-cscaMasterListSigningKey",
    );

    /// The document types a signer may sign.
    pub const DOCUMENT_TYPE_LIST: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x04],
        "2.23.136.1.1.4",
        "id-icao-documentTypeList",
    );

    /// Active authentication protocol information.
    pub const AA_PROTOCOL_OBJECT: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x05],
        "2.23.136.1.1.5",
        "id-icao-aaProtocolObject",
    );

    /// The arc of ICAO certificate extensions.
    pub const EXTENSIONS: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x06],
        "2.23.136.1.1.6",
        "id-icao-extensions",
    );

    /// A CSCA name change at key rollover.
    pub const EXTENSIONS_NAME_CHANGE_KEY_ROLLOVER: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x08, 0x01, 0x01, 0x06, 0x01],
        "2.23.136.1.1.6.1",
        "id-icao-extensions-namechangekeyrollover",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::ICAO,
        Self::MRTD,
        Self::MRTD_SECURITY,
        Self::LDS_SECURITY_OBJECT,
        Self::CSCA_MASTER_LIST,
        Self::CSCA_MASTER_LIST_SIGNING_KEY,
        Self::DOCUMENT_TYPE_LIST,
        Self::AA_PROTOCOL_OBJECT,
        Self::EXTENSIONS,
        Self::EXTENSIONS_NAME_CHANGE_KEY_ROLLOVER,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
