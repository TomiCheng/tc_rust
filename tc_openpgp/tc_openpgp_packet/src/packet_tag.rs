#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PacketTag {
    Reserved,
    PublicKeyEncryptedSession,
    Signature,
    SymmetricKeyEncryptedSessionKey,
    OnePassSignature,
    SecretKey,
    PublicKey,
    SecretSubkey,
    CompressedData,
    SymmetricKeyEncrypted,
    Marker,
    LiteralData,
    Trust,
    UserId,
    PublicSubkey,
    UserAttribute,
    SymmetricEncryptedIntegrityProtected,
    ModificationDetectionCode,
    AeadEncData,
    Padding,
    Experimental1,
    Experimental2,
    Experimental3,
    Experimental4,
    Unknown(u8),
}

impl PacketTag {
    pub fn is_critical(self) -> bool {
        u8::from(self) <= 39
    }
}

impl From<u8> for PacketTag {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::PublicKeyEncryptedSession,
            2 => Self::Signature,
            3 => Self::SymmetricKeyEncryptedSessionKey,
            4 => Self::OnePassSignature,
            5 => Self::SecretKey,
            6 => Self::PublicKey,
            7 => Self::SecretSubkey,
            8 => Self::CompressedData,
            9 => Self::SymmetricKeyEncrypted,
            10 => Self::Marker,
            11 => Self::LiteralData,
            12 => Self::Trust,
            13 => Self::UserId,
            14 => Self::PublicSubkey,
            17 => Self::UserAttribute,
            18 => Self::SymmetricEncryptedIntegrityProtected,
            19 => Self::ModificationDetectionCode,
            20 => Self::AeadEncData,
            21 => Self::Padding,
            60 => Self::Experimental1,
            61 => Self::Experimental2,
            62 => Self::Experimental3,
            63 => Self::Experimental4,
            other => Self::Unknown(other),
        }
    }
}

impl From<PacketTag> for u8 {
    fn from(tag: PacketTag) -> Self {
        match tag {
            PacketTag::Reserved => 0,
            PacketTag::PublicKeyEncryptedSession => 1,
            PacketTag::Signature => 2,
            PacketTag::SymmetricKeyEncryptedSessionKey => 3,
            PacketTag::OnePassSignature => 4,
            PacketTag::SecretKey => 5,
            PacketTag::PublicKey => 6,
            PacketTag::SecretSubkey => 7,
            PacketTag::CompressedData => 8,
            PacketTag::SymmetricKeyEncrypted => 9,
            PacketTag::Marker => 10,
            PacketTag::LiteralData => 11,
            PacketTag::Trust => 12,
            PacketTag::UserId => 13,
            PacketTag::PublicSubkey => 14,
            PacketTag::UserAttribute => 17,
            PacketTag::SymmetricEncryptedIntegrityProtected => 18,
            PacketTag::ModificationDetectionCode => 19,
            PacketTag::AeadEncData => 20,
            PacketTag::Padding => 21,
            PacketTag::Experimental1 => 60,
            PacketTag::Experimental2 => 61,
            PacketTag::Experimental3 => 62,
            PacketTag::Experimental4 => 63,
            PacketTag::Unknown(value) => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PacketTag;

    #[test]
    fn every_byte_converts_to_a_tag_and_back_to_itself() {
        for value in 0..=u8::MAX {
            assert_eq!(u8::from(PacketTag::from(value)), value);
        }
    }

    #[test]
    fn a_value_with_a_name_never_converts_to_unknown() {
        let named = (0..=14).chain(17..=21).chain(60..=63);
        for value in named {
            assert!(!matches!(PacketTag::from(value), PacketTag::Unknown(_)));
        }
    }

    #[test]
    fn tags_up_to_39_are_critical_and_later_ones_are_not() {
        assert!(PacketTag::from(39).is_critical());
        assert!(!PacketTag::from(40).is_critical());
        assert!(!PacketTag::Experimental1.is_critical());
    }

    #[test]
    fn a_value_without_a_name_is_kept_in_unknown() {
        assert_eq!(PacketTag::from(15), PacketTag::Unknown(15));
        assert_eq!(PacketTag::from(40), PacketTag::Unknown(40));
    }
}
