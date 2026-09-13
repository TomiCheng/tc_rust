//! Encoding rules and BER length forms.

/// Length form for constructed BER values; primitive values always use definite length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthForm {
    /// Write the content length.
    Definite,
    /// Write `80` instead of the content length and terminate the contents with `00 00`.
    Indefinite,
}

/// The encoding rules selected by [`crate::EncodingOptions`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingType {
    /// BER: apply the selected length form to constructed values at every level.
    /// Strings remain primitive and SETs retain their stored order. Re-encoding
    /// preserves the value, but does not guarantee identical bytes.
    Ber(LengthForm),
    /// CER: use indefinite lengths for constructed values, segment supported
    /// strings longer than 1000 content octets, and apply canonical ordering
    /// and value normalization.
    Cer,
    /// DER: use shortest definite lengths, primitive strings, canonical ordering,
    /// and normalized values.
    Der,
}

impl EncodingType {
    /// Return whether canonical restrictions apply (CER and DER). Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{EncodingType, LengthForm};
    /// assert!(EncodingType::Cer.is_canonical());
    /// assert!(EncodingType::Der.is_canonical());
    /// assert!(!EncodingType::Ber(LengthForm::Definite).is_canonical());
    /// assert!(!EncodingType::Ber(LengthForm::Indefinite).is_canonical());
    /// ```
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Cer | Self::Der)
    }
}
