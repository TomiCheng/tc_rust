//! Ukrainian identifiers, as Bouncy Castle's `UAObjectIdentifiers` names them:
//! DSTU 4145 signatures, DSTU 7564 (Kupyna) hashes and DSTU 7624 (Kalyna)
//! modes.
//!
//! This table names known identifiers without restricting algorithm policy.

use tc_asn1::{Asn1Oid, NamedOid};

/// DSTU 4145, DSTU 7564 and DSTU 7624 identifiers.
///
/// ```
/// use tc_asn1_dstu::UaId;
///
/// assert_eq!(UaId::DSTU4145_BE.dotted(), "1.2.804.2.1.1.1.1.3.1.1.1.1");
/// assert_eq!(
///     UaId::from_oid(&UaId::UA_OID.oid()),
///     Some(UaId::UA_OID),
/// );
/// ```
pub struct UaId;

impl UaId {
    /// The arc of Ukrainian standards.
    pub const UA_OID: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01],
        "1.2.804.2.1.1.1",
        "ua",
    );

    /// DSTU 4145 signatures, little-endian.
    pub const DSTU4145_LE: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
        ],
        "1.2.804.2.1.1.1.1.3.1.1",
        "dstu4145le",
    );

    /// DSTU 4145 signatures, big-endian.
    pub const DSTU4145_BE: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x01, 0x01,
        ],
        "1.2.804.2.1.1.1.1.3.1.1.1.1",
        "dstu4145be",
    );

    /// Kupyna-256.
    pub const DSTU7564_DIGEST_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x01,
        ],
        "1.2.804.2.1.1.1.1.2.2.1",
        "dstu7564digest_256",
    );

    /// Kupyna-384.
    pub const DSTU7564_DIGEST_384: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02,
        ],
        "1.2.804.2.1.1.1.1.2.2.2",
        "dstu7564digest_384",
    );

    /// Kupyna-512.
    pub const DSTU7564_DIGEST_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x03,
        ],
        "1.2.804.2.1.1.1.1.2.2.3",
        "dstu7564digest_512",
    );

    /// Kupyna-256 MAC.
    pub const DSTU7564_MAC_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x04,
        ],
        "1.2.804.2.1.1.1.1.2.2.4",
        "dstu7564mac_256",
    );

    /// Kupyna-384 MAC.
    pub const DSTU7564_MAC_384: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x05,
        ],
        "1.2.804.2.1.1.1.1.2.2.5",
        "dstu7564mac_384",
    );

    /// Kupyna-512 MAC.
    pub const DSTU7564_MAC_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x06,
        ],
        "1.2.804.2.1.1.1.1.2.2.6",
        "dstu7564mac_512",
    );

    /// Kalyna with a 128-bit block in ECB mode.
    pub const DSTU7624_ECB_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.1.1",
        "dstu7624ecb_128",
    );

    /// Kalyna with a 256-bit block in ECB mode.
    pub const DSTU7624_ECB_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.1.2",
        "dstu7624ecb_256",
    );

    /// Kalyna with a 512-bit block in ECB mode.
    pub const DSTU7624_ECB_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x01, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.1.3",
        "dstu7624ecb_512",
    );

    /// Kalyna with a 128-bit block in CTR mode.
    pub const DSTU7624_CTR_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.2.1",
        "dstu7624ctr_128",
    );

    /// Kalyna with a 256-bit block in CTR mode.
    pub const DSTU7624_CTR_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x02, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.2.2",
        "dstu7624ctr_256",
    );

    /// Kalyna with a 512-bit block in CTR mode.
    pub const DSTU7624_CTR_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x02, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.2.3",
        "dstu7624ctr_512",
    );

    /// Kalyna with a 128-bit block in CFB mode.
    pub const DSTU7624_CFB_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x03, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.3.1",
        "dstu7624cfb_128",
    );

    /// Kalyna with a 256-bit block in CFB mode.
    pub const DSTU7624_CFB_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x03, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.3.2",
        "dstu7624cfb_256",
    );

    /// Kalyna with a 512-bit block in CFB mode.
    pub const DSTU7624_CFB_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x03, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.3.3",
        "dstu7624cfb_512",
    );

    /// Kalyna with a 128-bit block in CMAC mode.
    pub const DSTU7624_CMAC_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.4.1",
        "dstu7624cmac_128",
    );

    /// Kalyna with a 256-bit block in CMAC mode.
    pub const DSTU7624_CMAC_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.4.2",
        "dstu7624cmac_256",
    );

    /// Kalyna with a 512-bit block in CMAC mode.
    pub const DSTU7624_CMAC_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x04, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.4.3",
        "dstu7624cmac_512",
    );

    /// Kalyna with a 128-bit block in CBC mode.
    pub const DSTU7624_CBC_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x05, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.5.1",
        "dstu7624cbc_128",
    );

    /// Kalyna with a 256-bit block in CBC mode.
    pub const DSTU7624_CBC_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x05, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.5.2",
        "dstu7624cbc_256",
    );

    /// Kalyna with a 512-bit block in CBC mode.
    pub const DSTU7624_CBC_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x05, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.5.3",
        "dstu7624cbc_512",
    );

    /// Kalyna with a 128-bit block in OFB mode.
    pub const DSTU7624_OFB_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x06, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.6.1",
        "dstu7624ofb_128",
    );

    /// Kalyna with a 256-bit block in OFB mode.
    pub const DSTU7624_OFB_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x06, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.6.2",
        "dstu7624ofb_256",
    );

    /// Kalyna with a 512-bit block in OFB mode.
    pub const DSTU7624_OFB_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x06, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.6.3",
        "dstu7624ofb_512",
    );

    /// Kalyna with a 128-bit block in GMAC mode.
    pub const DSTU7624_GMAC_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x07, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.7.1",
        "dstu7624gmac_128",
    );

    /// Kalyna with a 256-bit block in GMAC mode.
    pub const DSTU7624_GMAC_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x07, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.7.2",
        "dstu7624gmac_256",
    );

    /// Kalyna with a 512-bit block in GMAC mode.
    pub const DSTU7624_GMAC_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x07, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.7.3",
        "dstu7624gmac_512",
    );

    /// Kalyna with a 128-bit block in CCM mode.
    pub const DSTU7624_CCM_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x08, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.8.1",
        "dstu7624ccm_128",
    );

    /// Kalyna with a 256-bit block in CCM mode.
    pub const DSTU7624_CCM_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x08, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.8.2",
        "dstu7624ccm_256",
    );

    /// Kalyna with a 512-bit block in CCM mode.
    pub const DSTU7624_CCM_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x08, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.8.3",
        "dstu7624ccm_512",
    );

    /// Kalyna with a 128-bit block in XTS mode.
    pub const DSTU7624_XTS_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x09, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.9.1",
        "dstu7624xts_128",
    );

    /// Kalyna with a 256-bit block in XTS mode.
    pub const DSTU7624_XTS_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x09, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.9.2",
        "dstu7624xts_256",
    );

    /// Kalyna with a 512-bit block in XTS mode.
    pub const DSTU7624_XTS_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x09, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.9.3",
        "dstu7624xts_512",
    );

    /// Kalyna with a 128-bit block in KW mode.
    pub const DSTU7624_KW_128: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x0a, 0x01,
        ],
        "1.2.804.2.1.1.1.1.1.3.10.1",
        "dstu7624kw_128",
    );

    /// Kalyna with a 256-bit block in KW mode.
    pub const DSTU7624_KW_256: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x0a, 0x02,
        ],
        "1.2.804.2.1.1.1.1.1.3.10.2",
        "dstu7624kw_256",
    );

    /// Kalyna with a 512-bit block in KW mode.
    pub const DSTU7624_KW_512: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x24, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x0a, 0x03,
        ],
        "1.2.804.2.1.1.1.1.1.3.10.3",
        "dstu7624kw_512",
    );

    /// Every identifier above.
    pub const ALL: &'static [NamedOid] = &[
        Self::UA_OID,
        Self::DSTU4145_LE,
        Self::DSTU4145_BE,
        Self::DSTU7564_DIGEST_256,
        Self::DSTU7564_DIGEST_384,
        Self::DSTU7564_DIGEST_512,
        Self::DSTU7564_MAC_256,
        Self::DSTU7564_MAC_384,
        Self::DSTU7564_MAC_512,
        Self::DSTU7624_ECB_128,
        Self::DSTU7624_ECB_256,
        Self::DSTU7624_ECB_512,
        Self::DSTU7624_CTR_128,
        Self::DSTU7624_CTR_256,
        Self::DSTU7624_CTR_512,
        Self::DSTU7624_CFB_128,
        Self::DSTU7624_CFB_256,
        Self::DSTU7624_CFB_512,
        Self::DSTU7624_CMAC_128,
        Self::DSTU7624_CMAC_256,
        Self::DSTU7624_CMAC_512,
        Self::DSTU7624_CBC_128,
        Self::DSTU7624_CBC_256,
        Self::DSTU7624_CBC_512,
        Self::DSTU7624_OFB_128,
        Self::DSTU7624_OFB_256,
        Self::DSTU7624_OFB_512,
        Self::DSTU7624_GMAC_128,
        Self::DSTU7624_GMAC_256,
        Self::DSTU7624_GMAC_512,
        Self::DSTU7624_CCM_128,
        Self::DSTU7624_CCM_256,
        Self::DSTU7624_CCM_512,
        Self::DSTU7624_XTS_128,
        Self::DSTU7624_XTS_256,
        Self::DSTU7624_XTS_512,
        Self::DSTU7624_KW_128,
        Self::DSTU7624_KW_256,
        Self::DSTU7624_KW_512,
    ];

    /// The entry with this identifier, if any.
    /// Variable time; for public values.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}
