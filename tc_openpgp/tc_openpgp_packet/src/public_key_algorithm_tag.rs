/// OpenPGP public-key algorithm identifiers.
///
/// The numeric values are the algorithm IDs encoded in OpenPGP packets. The names
/// follow Bouncy Castle's `PublicKeyAlgorithmTag` where practical.
/// See [RFC 9580, Section 9.1][rfc9580-public-key-algorithms] for the registry.
///
/// [rfc9580-public-key-algorithms]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PublicKeyAlgorithmTag {
    RsaGeneral,
    RsaEncrypt,
    RsaSign,
    ElGamalEncrypt,
    Dsa,
    Ecdh,
    Ecdsa,
    ElGamalGeneral,
    DiffieHellman,
    EdDsaLegacy,
    X25519,
    X448,
    Ed25519,
    Ed448,
    Experimental1,
    Experimental2,
    Experimental3,
    Experimental4,
    Experimental5,
    Experimental6,
    Experimental7,
    Experimental8,
    Experimental9,
    Experimental10,
    Experimental11,
    /// An algorithm ID not named by this enum.
    Unknown(u8),
}

impl From<u8> for PublicKeyAlgorithmTag {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RsaGeneral,
            2 => Self::RsaEncrypt,
            3 => Self::RsaSign,
            16 => Self::ElGamalEncrypt,
            17 => Self::Dsa,
            18 => Self::Ecdh,
            19 => Self::Ecdsa,
            20 => Self::ElGamalGeneral,
            21 => Self::DiffieHellman,
            22 => Self::EdDsaLegacy,
            25 => Self::X25519,
            26 => Self::X448,
            27 => Self::Ed25519,
            28 => Self::Ed448,
            100 => Self::Experimental1,
            101 => Self::Experimental2,
            102 => Self::Experimental3,
            103 => Self::Experimental4,
            104 => Self::Experimental5,
            105 => Self::Experimental6,
            106 => Self::Experimental7,
            107 => Self::Experimental8,
            108 => Self::Experimental9,
            109 => Self::Experimental10,
            110 => Self::Experimental11,
            other => Self::Unknown(other),
        }
    }
}

impl From<PublicKeyAlgorithmTag> for u8 {
    fn from(tag: PublicKeyAlgorithmTag) -> Self {
        match tag {
            PublicKeyAlgorithmTag::RsaGeneral => 1,
            PublicKeyAlgorithmTag::RsaEncrypt => 2,
            PublicKeyAlgorithmTag::RsaSign => 3,
            PublicKeyAlgorithmTag::ElGamalEncrypt => 16,
            PublicKeyAlgorithmTag::Dsa => 17,
            PublicKeyAlgorithmTag::Ecdh => 18,
            PublicKeyAlgorithmTag::Ecdsa => 19,
            PublicKeyAlgorithmTag::ElGamalGeneral => 20,
            PublicKeyAlgorithmTag::DiffieHellman => 21,
            PublicKeyAlgorithmTag::EdDsaLegacy => 22,
            PublicKeyAlgorithmTag::X25519 => 25,
            PublicKeyAlgorithmTag::X448 => 26,
            PublicKeyAlgorithmTag::Ed25519 => 27,
            PublicKeyAlgorithmTag::Ed448 => 28,
            PublicKeyAlgorithmTag::Experimental1 => 100,
            PublicKeyAlgorithmTag::Experimental2 => 101,
            PublicKeyAlgorithmTag::Experimental3 => 102,
            PublicKeyAlgorithmTag::Experimental4 => 103,
            PublicKeyAlgorithmTag::Experimental5 => 104,
            PublicKeyAlgorithmTag::Experimental6 => 105,
            PublicKeyAlgorithmTag::Experimental7 => 106,
            PublicKeyAlgorithmTag::Experimental8 => 107,
            PublicKeyAlgorithmTag::Experimental9 => 108,
            PublicKeyAlgorithmTag::Experimental10 => 109,
            PublicKeyAlgorithmTag::Experimental11 => 110,
            PublicKeyAlgorithmTag::Unknown(value) => value,
        }
    }
}
