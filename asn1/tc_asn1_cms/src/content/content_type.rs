//! RFC 5652 content-type identifiers, the content types of Bouncy Castle's
//! `CmsObjectIdentifiers`.

use tc_asn1::{Asn1Oid, NamedOid};

/// CMS content-type constants and lookup.
///
/// ```
/// use tc_asn1_cms::content::ContentType;
///
/// let oid = ContentType::SIGNED_DATA.oid();
/// assert_eq!(ContentType::from_oid(&oid), Some(ContentType::SIGNED_DATA));
/// assert_eq!(ContentType::SIGNED_DATA.name(), "id-signedData");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ContentType;

impl ContentType {
    /// Arbitrary octets, `id-data`.
    pub const DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
        "1.2.840.113549.1.7.1",
        "id-data",
    );

    /// Signed data, `id-signedData`.
    pub const SIGNED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
        "1.2.840.113549.1.7.2",
        "id-signedData",
    );

    /// Enveloped data, `id-envelopedData`.
    pub const ENVELOPED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03],
        "1.2.840.113549.1.7.3",
        "id-envelopedData",
    );

    /// PKCS #7 signed-and-enveloped data, which CMS dropped.
    pub const SIGNED_AND_ENVELOPED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x04],
        "1.2.840.113549.1.7.4",
        "signedAndEnvelopedData",
    );

    /// Digested data, `id-digestedData`.
    pub const DIGESTED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x05],
        "1.2.840.113549.1.7.5",
        "id-digestedData",
    );

    /// Encrypted data, `id-encryptedData`.
    pub const ENCRYPTED_DATA: NamedOid = NamedOid::new(
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06],
        "1.2.840.113549.1.7.6",
        "id-encryptedData",
    );

    /// Authenticated data, `id-ct-authData`.
    pub const AUTHENTICATED_DATA: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x02,
        ],
        "1.2.840.113549.1.9.16.1.2",
        "id-ct-authData",
    );

    /// Compressed data (RFC 3274), `id-ct-compressedData`.
    pub const COMPRESSED_DATA: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x09,
        ],
        "1.2.840.113549.1.9.16.1.9",
        "id-ct-compressedData",
    );

    /// Authenticated-enveloped data (RFC 5083), `id-ct-authEnvelopedData`.
    pub const AUTH_ENVELOPED_DATA: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x17,
        ],
        "1.2.840.113549.1.9.16.1.23",
        "id-ct-authEnvelopedData",
    );

    /// Time-stamped data (RFC 5544), `id-ct-timestampedData`.
    pub const TIMESTAMPED_DATA: NamedOid = NamedOid::new(
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x1f,
        ],
        "1.2.840.113549.1.9.16.1.31",
        "id-ct-timestampedData",
    );

    /// All 10 content types.
    pub const ALL: &'static [NamedOid] = &[
        Self::DATA,
        Self::SIGNED_DATA,
        Self::ENVELOPED_DATA,
        Self::SIGNED_AND_ENVELOPED_DATA,
        Self::DIGESTED_DATA,
        Self::ENCRYPTED_DATA,
        Self::AUTHENTICATED_DATA,
        Self::COMPRESSED_DATA,
        Self::AUTH_ENVELOPED_DATA,
        Self::TIMESTAMPED_DATA,
    ];

    /// Returns the table entry, or None for a content type outside it.
    /// Variable time: branches only on the encoding structure.
    pub fn from_oid(oid: &Asn1Oid) -> Option<NamedOid> {
        NamedOid::find(Self::ALL, oid)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use tc_asn1::{Asn1Oid, Decode, DecodingOptions, Encode, EncodingOptions};

    use super::ContentType;

    #[test]
    fn every_content_type_encodes_its_dotted_oid_and_is_found_again() {
        assert_eq!(ContentType::ALL.len(), 10);
        for entry in ContentType::ALL {
            let oid: Asn1Oid = entry.dotted().parse().unwrap();
            assert_eq!(entry.oid(), oid, "{}", entry.dotted());
            let wire = oid.encode_to_vec(&EncodingOptions::DER).unwrap();
            let back = Asn1Oid::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1;
            assert_eq!(back.to_string(), entry.dotted());
            assert_eq!(ContentType::from_oid(&back), Some(*entry));
        }
    }

    #[test]
    fn content_types_have_unique_oids_and_unknown_oids_return_none() {
        for (i, a) in ContentType::ALL.iter().enumerate() {
            for b in &ContentType::ALL[..i] {
                assert_ne!(a.oid(), b.oid());
            }
        }
        assert_eq!(ContentType::from_oid(&"1.2.3".parse().unwrap()), None);
    }
}
