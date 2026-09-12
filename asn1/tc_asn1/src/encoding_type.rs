//! X.690 encoding rules.
//!
//! All three share the BER syntax of §8. CER (§9) and DER (§10) each pin the
//! sender's options down to one encoding, in opposite directions: CER chooses
//! indefinite lengths so a writer need not know the total length up front, DER
//! chooses definite lengths so a verifier can compare bytes. Bouncy Castle's
//! `DL` is not a separate rule set — it is definite-length BER, which is what
//! `Ber` here produces.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    /// X.690 §8. Where the sender has a choice this crate always picks: definite
    /// lengths, primitive strings, SET members in stored order, values not
    /// normalised. Re-encoding a decoded BER value gives an equivalent, not
    /// necessarily identical, byte string.
    Ber,
    /// X.690 §9. Constructed values use indefinite length; strings longer than
    /// 1000 octets are split into 1000-octet primitive segments; SETs are
    /// sorted and values normalised as in DER.
    Cer,
    /// X.690 §10. Exactly one encoding per value: shortest definite lengths,
    /// primitive strings, sorted SETs, normalised values.
    Der,
}

impl EncodingType {
    /// Whether the §11 canonical restrictions apply (CER and DER). Constant time.
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Cer | Self::Der)
    }
}

#[cfg(test)]
mod tests {
    use super::EncodingType;

    #[test]
    fn canonical_restrictions_apply_to_cer_and_der_but_not_ber() {
        assert!(!EncodingType::Ber.is_canonical());
        assert!(EncodingType::Cer.is_canonical());
        assert!(EncodingType::Der.is_canonical());
    }
}
