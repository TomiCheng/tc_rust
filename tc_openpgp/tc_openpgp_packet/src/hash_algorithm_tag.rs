/// OpenPGP hash algorithm identifiers used in packet fields.
///
/// Numeric values are the one-octet IDs encoded by OpenPGP.
/// See [RFC 9580, Section 9.5][rfc9580-hash-registry] for the hash algorithm registry.
/// The named values mirror Bouncy Castle's `HashAlgorithmTag` where they fit in the wire field;
/// its non-standard identifiers above 255 are intentionally not included.
///
/// [rfc9580-hash-registry]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum HashAlgorithmTag {
    Md5,
    Sha1,
    RipeMd160,
    DoubleSha,
    Md2,
    Tiger192,
    Haval5Pass160,
    Sha256,
    Sha384,
    Sha512,
    Sha224,
    Sha3_256,
    Sha3_512,
    /// A hash algorithm ID not named by this enum.
    Unknown(u8),
}

impl From<u8> for HashAlgorithmTag {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Md5,
            2 => Self::Sha1,
            3 => Self::RipeMd160,
            4 => Self::DoubleSha,
            5 => Self::Md2,
            6 => Self::Tiger192,
            7 => Self::Haval5Pass160,
            8 => Self::Sha256,
            9 => Self::Sha384,
            10 => Self::Sha512,
            11 => Self::Sha224,
            12 => Self::Sha3_256,
            14 => Self::Sha3_512,
            other => Self::Unknown(other),
        }
    }
}

impl From<HashAlgorithmTag> for u8 {
    fn from(tag: HashAlgorithmTag) -> Self {
        match tag {
            HashAlgorithmTag::Md5 => 1,
            HashAlgorithmTag::Sha1 => 2,
            HashAlgorithmTag::RipeMd160 => 3,
            HashAlgorithmTag::DoubleSha => 4,
            HashAlgorithmTag::Md2 => 5,
            HashAlgorithmTag::Tiger192 => 6,
            HashAlgorithmTag::Haval5Pass160 => 7,
            HashAlgorithmTag::Sha256 => 8,
            HashAlgorithmTag::Sha384 => 9,
            HashAlgorithmTag::Sha512 => 10,
            HashAlgorithmTag::Sha224 => 11,
            HashAlgorithmTag::Sha3_256 => 12,
            HashAlgorithmTag::Sha3_512 => 14,
            HashAlgorithmTag::Unknown(value) => value,
        }
    }
}