//! The attribute types CMS defines for signer and authenticated attributes, as
//! Bouncy Castle's `CmsAttributes`.

use tc_asn1::{Asn1Oid, NamedOid};

/// CMS attribute-type constants and lookup.
///
/// ```
/// use tc_asn1_cms::signed::CmsAttribute;
///
/// assert_eq!(CmsAttribute::MESSAGE_DIGEST.dotted(), "1.2.840.113549.1.9.4");
/// assert_eq!(CmsAttribute::from_oid(&CmsAttribute::SIGNING_TIME.oid()), Some(CmsAttribute::SIGNING_TIME));
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CmsAttribute;

impl CmsAttribute {
    /// The type of the content signed or authenticated (RFC 5652 §11.1).
    pub const CONTENT_TYPE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03],
        "1.2.840.113549.1.9.3",
        "contentType",
    );

    /// The digest of the content (RFC 5652 §11.2).
    pub const MESSAGE_DIGEST: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04],
        "1.2.840.113549.1.9.4",
        "messageDigest",
    );

    /// When the signer says it signed (RFC 5652 §11.3).
    pub const SIGNING_TIME: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05],
        "1.2.840.113549.1.9.5",
        "signingTime",
    );

    /// A signature over another signer's signature (RFC 5652 §11.4).
    pub const COUNTERSIGNATURE: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06],
        "1.2.840.113549.1.9.6",
        "countersignature",
    );

    /// A description of the innermost content (RFC 2634 §2.9).
    pub const CONTENT_HINT: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x04,
        ],
        "1.2.840.113549.1.9.16.2.4",
        "id-aa-contentHint",
    );

    /// The algorithms the signature or MAC used, protected by it (RFC 6211).
    pub const CMS_ALGORITHM_PROTECT: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x34],
        "1.2.840.113549.1.9.52",
        "id-aa-CMSAlgorithmProtection",
    );

    /// All 6 attribute types.
    pub const ALL: &'static [NamedOid] = &[
        Self::CONTENT_TYPE,
        Self::MESSAGE_DIGEST,
        Self::SIGNING_TIME,
        Self::COUNTERSIGNATURE,
        Self::CONTENT_HINT,
        Self::CMS_ALGORITHM_PROTECT,
    ];

    /// Returns the table entry, or None for an attribute type outside it.
    /// Variable time: branches only on the encoding structure.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::CmsAttribute;

    #[test]
    fn every_attribute_type_encodes_its_dotted_oid_and_is_found_again() {
        assert_eq!(CmsAttribute::ALL.len(), 6);
        for entry in CmsAttribute::ALL {
            let oid: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(entry.oid(), oid, "{}", entry.dotted());
            let wire = oid.encode_to_vec(&EncodingOptions::DER).unwrap();
            let back = Asn1Oid::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back.to_string(), entry.dotted());
            assert_eq!(CmsAttribute::from_oid(&back), Some(*entry));
        }
        assert_eq!(CmsAttribute::from_oid(&"1.2.3".parse().unwrap()), None);
    }
}
