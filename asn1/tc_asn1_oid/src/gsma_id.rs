//! GSMA post-quantum algorithm identifiers, as Bouncy Castle's
//! `GsmaObjectIdentifiers` names them.
//!
//! Labels are Bouncy Castle's field names. This table names known identifiers
//! without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// GSMA post-quantum algorithm identifiers.
///
/// ```
/// use tc_asn1_oid::GsmaId;
///
/// assert_eq!(GsmaId::ID_RSP.dotted(), "2.23.146.1");
/// assert_eq!(
///     GsmaId::from_oid(&GsmaId::ID_RSP.oid()),
///     Some(GsmaId::ID_RSP),
/// );
/// ```
pub struct GsmaId;

impl GsmaId {
    /// Bouncy Castle's `id_gsma`.
    pub const ID_GSMA: NamedOid = NamedOid::new(&[0x67, 0x81, 0x12], "2.23.146", "id_gsma");

    /// Bouncy Castle's `id_rsp`.
    pub const ID_RSP: NamedOid = NamedOid::new(&[0x67, 0x81, 0x12, 0x01], "2.23.146.1", "id_rsp");

    /// Bouncy Castle's `id_rsp_cert_objects`.
    pub const ID_RSP_CERT_OBJECTS: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02],
        "2.23.146.1.2",
        "id_rsp_cert_objects",
    );

    /// Bouncy Castle's `id_rspExt`.
    pub const ID_RSP_EXT: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x00],
        "2.23.146.1.2.0",
        "id_rspExt",
    );

    /// Bouncy Castle's `id_rsp_expDate`.
    pub const ID_RSP_EXP_DATE: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x00, 0x01],
        "2.23.146.1.2.0.1",
        "id_rsp_expDate",
    );

    /// Bouncy Castle's `id_rsp_totalPartialCrlNumber`.
    pub const ID_RSP_TOTAL_PARTIAL_CRL_NUMBER: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x00, 0x02],
        "2.23.146.1.2.0.2",
        "id_rsp_totalPartialCrlNumber",
    );

    /// Bouncy Castle's `id_rsp_partialCrlNumber`.
    pub const ID_RSP_PARTIAL_CRL_NUMBER: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x00, 0x03],
        "2.23.146.1.2.0.3",
        "id_rsp_partialCrlNumber",
    );

    /// Bouncy Castle's `id_rspRole`.
    pub const ID_RSP_ROLE: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01],
        "2.23.146.1.2.1",
        "id_rspRole",
    );

    /// Bouncy Castle's `id_rspRole_ci`.
    pub const ID_RSP_ROLE_CI: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x00],
        "2.23.146.1.2.1.0",
        "id_rspRole_ci",
    );

    /// Bouncy Castle's `id_rspRole_euicc`.
    pub const ID_RSP_ROLE_EUICC: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x01],
        "2.23.146.1.2.1.1",
        "id_rspRole_euicc",
    );

    /// Bouncy Castle's `id_rspRole_eum`.
    pub const ID_RSP_ROLE_EUM: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x02],
        "2.23.146.1.2.1.2",
        "id_rspRole_eum",
    );

    /// Bouncy Castle's `id_rspRole_dp_tls`.
    pub const ID_RSP_ROLE_DP_TLS: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x03],
        "2.23.146.1.2.1.3",
        "id_rspRole_dp_tls",
    );

    /// Bouncy Castle's `id_rspRole_dp_auth`.
    pub const ID_RSP_ROLE_DP_AUTH: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x04],
        "2.23.146.1.2.1.4",
        "id_rspRole_dp_auth",
    );

    /// Bouncy Castle's `id_rspRole_dp_pb`.
    pub const ID_RSP_ROLE_DP_PB: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x05],
        "2.23.146.1.2.1.5",
        "id_rspRole_dp_pb",
    );

    /// Bouncy Castle's `id_rspRole_ds_tls`.
    pub const ID_RSP_ROLE_DS_TLS: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x06],
        "2.23.146.1.2.1.6",
        "id_rspRole_ds_tls",
    );

    /// Bouncy Castle's `id_rspRole_ds_auth`.
    pub const ID_RSP_ROLE_DS_AUTH: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x07],
        "2.23.146.1.2.1.7",
        "id_rspRole_ds_auth",
    );

    /// Bouncy Castle's `id_rsp_metadata`.
    pub const ID_RSP_METADATA: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x03],
        "2.23.146.1.3",
        "id_rsp_metadata",
    );

    /// Bouncy Castle's `id_rsp_metadata_serviceSpecificOIDs`.
    pub const ID_RSP_METADATA_SERVICE_SPECIFIC_OIDS: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x03, 0x01],
        "2.23.146.1.3.1",
        "id_rsp_metadata_serviceSpecificOIDs",
    );

    /// Bouncy Castle's `id_rsp_metadata_activationCodeRetrievalInfo`.
    pub const ID_RSP_METADATA_ACTIVATION_CODE_RETRIEVAL_INFO: NamedOid = NamedOid::new(
        &[0x67, 0x81, 0x12, 0x01, 0x03, 0x01, 0x01],
        "2.23.146.1.3.1.1",
        "id_rsp_metadata_activationCodeRetrievalInfo",
    );

    /// Every identifier above, without repeats.
    pub const ALL: &'static [NamedOid] = &[
        Self::ID_GSMA,
        Self::ID_RSP,
        Self::ID_RSP_CERT_OBJECTS,
        Self::ID_RSP_EXT,
        Self::ID_RSP_EXP_DATE,
        Self::ID_RSP_TOTAL_PARTIAL_CRL_NUMBER,
        Self::ID_RSP_PARTIAL_CRL_NUMBER,
        Self::ID_RSP_ROLE,
        Self::ID_RSP_ROLE_CI,
        Self::ID_RSP_ROLE_EUICC,
        Self::ID_RSP_ROLE_EUM,
        Self::ID_RSP_ROLE_DP_TLS,
        Self::ID_RSP_ROLE_DP_AUTH,
        Self::ID_RSP_ROLE_DP_PB,
        Self::ID_RSP_ROLE_DS_TLS,
        Self::ID_RSP_ROLE_DS_AUTH,
        Self::ID_RSP_METADATA,
        Self::ID_RSP_METADATA_SERVICE_SPECIFIC_OIDS,
        Self::ID_RSP_METADATA_ACTIVATION_CODE_RETRIEVAL_INFO,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
