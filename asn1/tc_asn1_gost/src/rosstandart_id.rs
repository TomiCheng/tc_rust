//! Technical committee 26 identifiers (RFC 9215), as Bouncy Castle's
//! `RosstandartObjectIdentifiers` names them.
//!
//! This table names known identifiers without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// GOST R 34.10-2012, GOST R 34.11-2012 and TC 26 parameter set identifiers.
///
/// ```
/// use tc_asn1_gost::RosstandartId;
///
/// assert_eq!(RosstandartId::GOST_3410_12_256_PARAM_SET_A.dotted(), "1.2.643.7.1.2.1.1.1");
/// assert_eq!(
///     RosstandartId::from_oid(&RosstandartId::ROSSTANDART.oid()),
///     Some(RosstandartId::ROSSTANDART),
/// );
/// ```
pub struct RosstandartId;

impl RosstandartId {
    /// The Rosstandart arc.
    pub const ROSSTANDART: NamedOid =
        NamedOid::new(&[0x2a, 0x85, 0x03, 0x07], "1.2.643.7", "rosstandart");

    /// The TC 26 arc.
    pub const TC26: NamedOid =
        NamedOid::new(&[0x2a, 0x85, 0x03, 0x07, 0x01], "1.2.643.7.1", "id-tc26");

    /// Streebog-256.
    pub const GOST_3411_12_256: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02],
        "1.2.643.7.1.1.2.2",
        "id-tc26-gost3411-12-256",
    );

    /// Streebog-512.
    pub const GOST_3411_12_512: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03],
        "1.2.643.7.1.1.2.3",
        "id-tc26-gost3411-12-512",
    );

    /// HMAC with Streebog-256.
    pub const HMAC_GOST_3411_12_256: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x01],
        "1.2.643.7.1.1.4.1",
        "id-tc26-hmac-gost-3411-12-256",
    );

    /// HMAC with Streebog-512.
    pub const HMAC_GOST_3411_12_512: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x04, 0x02],
        "1.2.643.7.1.1.4.2",
        "id-tc26-hmac-gost-3411-12-512",
    );

    /// GOST R 34.10-2012 256-bit keys.
    pub const GOST_3410_12_256: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01],
        "1.2.643.7.1.1.1.1",
        "id-tc26-gost3410-12-256",
    );

    /// GOST R 34.10-2012 512-bit keys.
    pub const GOST_3410_12_512: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x01, 0x02],
        "1.2.643.7.1.1.1.2",
        "id-tc26-gost3410-12-512",
    );

    /// 256-bit signatures with Streebog-256.
    pub const SIGNWITHDIGEST_GOST_3410_12_256: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x02],
        "1.2.643.7.1.1.3.2",
        "id-tc26-signwithdigest-gost3410-12-256",
    );

    /// 512-bit signatures with Streebog-512.
    pub const SIGNWITHDIGEST_GOST_3410_12_512: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03, 0x03],
        "1.2.643.7.1.1.3.3",
        "id-tc26-signwithdigest-gost3410-12-512",
    );

    /// The key agreement arc.
    pub const AGREEMENT: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x06],
        "1.2.643.7.1.1.6",
        "id-tc26-agreement",
    );

    /// 256-bit key agreement.
    pub const AGREEMENT_GOST_3410_12_256: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x06, 0x01],
        "1.2.643.7.1.1.6.1",
        "id-tc26-agreement-gost-3410-12-256",
    );

    /// 512-bit key agreement.
    pub const AGREEMENT_GOST_3410_12_512: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x06, 0x02],
        "1.2.643.7.1.1.6.2",
        "id-tc26-agreement-gost-3410-12-512",
    );

    /// The 256-bit curve arc.
    pub const GOST_3410_12_256_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01],
        "1.2.643.7.1.2.1.1",
        "id-tc26-gost-3410-12-256-constants",
    );

    /// 256-bit curve A.
    pub const GOST_3410_12_256_PARAM_SET_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01],
        "1.2.643.7.1.2.1.1.1",
        "id-tc26-gost-3410-12-256-paramSetA",
    );

    /// 256-bit curve B.
    pub const GOST_3410_12_256_PARAM_SET_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x02],
        "1.2.643.7.1.2.1.1.2",
        "id-tc26-gost-3410-12-256-paramSetB",
    );

    /// 256-bit curve C.
    pub const GOST_3410_12_256_PARAM_SET_C: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x03],
        "1.2.643.7.1.2.1.1.3",
        "id-tc26-gost-3410-12-256-paramSetC",
    );

    /// 256-bit curve D.
    pub const GOST_3410_12_256_PARAM_SET_D: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x04],
        "1.2.643.7.1.2.1.1.4",
        "id-tc26-gost-3410-12-256-paramSetD",
    );

    /// The 512-bit curve arc.
    pub const GOST_3410_12_512_PARAM_SET: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02],
        "1.2.643.7.1.2.1.2",
        "id-tc26-gost-3410-12-512-constants",
    );

    /// 512-bit curve A.
    pub const GOST_3410_12_512_PARAM_SET_A: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01],
        "1.2.643.7.1.2.1.2.1",
        "id-tc26-gost-3410-12-512-paramSetA",
    );

    /// 512-bit curve B.
    pub const GOST_3410_12_512_PARAM_SET_B: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02],
        "1.2.643.7.1.2.1.2.2",
        "id-tc26-gost-3410-12-512-paramSetB",
    );

    /// 512-bit curve C.
    pub const GOST_3410_12_512_PARAM_SET_C: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03],
        "1.2.643.7.1.2.1.2.3",
        "id-tc26-gost-3410-12-512-paramSetC",
    );

    /// The TC 26 Z S-boxes.
    pub const GOST_28147_PARAM_Z: NamedOid = NamedOid::new(
        &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x05, 0x01, 0x01],
        "1.2.643.7.1.2.5.1.1",
        "id-tc26-gost-28147-param-Z",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::ROSSTANDART,
        Self::TC26,
        Self::GOST_3411_12_256,
        Self::GOST_3411_12_512,
        Self::HMAC_GOST_3411_12_256,
        Self::HMAC_GOST_3411_12_512,
        Self::GOST_3410_12_256,
        Self::GOST_3410_12_512,
        Self::SIGNWITHDIGEST_GOST_3410_12_256,
        Self::SIGNWITHDIGEST_GOST_3410_12_512,
        Self::AGREEMENT,
        Self::AGREEMENT_GOST_3410_12_256,
        Self::AGREEMENT_GOST_3410_12_512,
        Self::GOST_3410_12_256_PARAM_SET,
        Self::GOST_3410_12_256_PARAM_SET_A,
        Self::GOST_3410_12_256_PARAM_SET_B,
        Self::GOST_3410_12_256_PARAM_SET_C,
        Self::GOST_3410_12_256_PARAM_SET_D,
        Self::GOST_3410_12_512_PARAM_SET,
        Self::GOST_3410_12_512_PARAM_SET_A,
        Self::GOST_3410_12_512_PARAM_SET_B,
        Self::GOST_3410_12_512_PARAM_SET_C,
        Self::GOST_28147_PARAM_Z,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
