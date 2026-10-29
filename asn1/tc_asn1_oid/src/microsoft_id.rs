//! Microsoft certificate extension and attribute identifiers, as Bouncy
//! Castle's `MicrosoftObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// Microsoft certificate extension and attribute identifiers.
///
/// ```
/// use tc_asn1_oid::MicrosoftId;
///
/// assert_eq!(MicrosoftId::MICROSOFT_CERT_TEMPLATE_V1.dotted(), "1.3.6.1.4.1.311.20.2");
/// assert_eq!(
///     MicrosoftId::from_oid(&MicrosoftId::MICROSOFT_CERT_TEMPLATE_V1.oid()),
///     Some(MicrosoftId::MICROSOFT_CERT_TEMPLATE_V1),
/// );
/// ```
pub struct MicrosoftId;

impl MicrosoftId {
    /// Bouncy Castle's `Microsoft`.
    pub const MICROSOFT: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37],
        "1.3.6.1.4.1.311",
        "Microsoft",
    );

    /// Bouncy Castle's `MicrosoftCertTemplateV1`.
    pub const MICROSOFT_CERT_TEMPLATE_V1: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02],
        "1.3.6.1.4.1.311.20.2",
        "MicrosoftCertTemplateV1",
    );

    /// Bouncy Castle's `MicrosoftCAVersion`.
    pub const MICROSOFT_CA_VERSION: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01],
        "1.3.6.1.4.1.311.21.1",
        "MicrosoftCAVersion",
    );

    /// Bouncy Castle's `MicrosoftPrevCACertHash`.
    pub const MICROSOFT_PREV_CA_CERT_HASH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x02],
        "1.3.6.1.4.1.311.21.2",
        "MicrosoftPrevCACertHash",
    );

    /// Bouncy Castle's `MicrosoftCrlNextPublish`.
    pub const MICROSOFT_CRL_NEXT_PUBLISH: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x04],
        "1.3.6.1.4.1.311.21.4",
        "MicrosoftCrlNextPublish",
    );

    /// Bouncy Castle's `MicrosoftCertTemplateV2`.
    pub const MICROSOFT_CERT_TEMPLATE_V2: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x07],
        "1.3.6.1.4.1.311.21.7",
        "MicrosoftCertTemplateV2",
    );

    /// Bouncy Castle's `MicrosoftAppPolicies`.
    pub const MICROSOFT_APP_POLICIES: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x0a],
        "1.3.6.1.4.1.311.21.10",
        "MicrosoftAppPolicies",
    );

    /// Bouncy Castle's `MicrosoftTimeStampRequest`.
    pub const MICROSOFT_TIME_STAMP_REQUEST: NamedOid = NamedOid::new(
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x03, 0x02, 0x01],
        "1.3.6.1.4.1.311.3.2.1",
        "MicrosoftTimeStampRequest",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::MICROSOFT,
        Self::MICROSOFT_CERT_TEMPLATE_V1,
        Self::MICROSOFT_CA_VERSION,
        Self::MICROSOFT_PREV_CA_CERT_HASH,
        Self::MICROSOFT_CRL_NEXT_PUBLISH,
        Self::MICROSOFT_CERT_TEMPLATE_V2,
        Self::MICROSOFT_APP_POLICIES,
        Self::MICROSOFT_TIME_STAMP_REQUEST,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
