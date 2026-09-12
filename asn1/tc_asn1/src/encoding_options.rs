//! X.690 encoding options: BER allows a choice of length form; CER and DER prescribe it.

/// Length form for constructed BER values; primitive values always use definite length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthForm {
    /// Write the content length.
    Definite,
    /// Write `80` instead of the content length and terminate the contents with `00 00`.
    Indefinite,
}

/// Options to pass consistently to length calculation and encoding methods.
///
/// [`crate::Asn1Any`] and [`crate::Asn1Object::Unknown`] preserve their raw encodings;
/// these options do not rewrite their original length forms or canonicalize their contents.
///
/// # Examples
///
/// Indefinite-length BER preserves stored SET order, whereas CER sorts the members.
///
/// ```
/// use tc_asn1::{Asn1Integer, Asn1Object, Encode, EncodingOptions, LengthForm};
/// let set = Asn1Object::Set(vec![
///     Asn1Integer::from(5_u8).into(),
///     Asn1Integer::from(3_u8).into(),
/// ]);
/// let options = EncodingOptions::Ber(LengthForm::Indefinite);
/// let mut buffer = vec![0; set.encoded_len(options)];
/// set.encode(options, &mut buffer)?;
/// assert_eq!(buffer, [0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingOptions {
    /// X.690 §8. The length form applies to constructed values at every nesting level.
    /// Strings remain primitive and SETs retain their stored order. Re-encoding preserves
    /// the value, but does not guarantee identical bytes.
    Ber(LengthForm),
    /// X.690 §9. Constructed values use indefinite length; strings longer than
    /// 1000 octets are split into 1000-octet primitive segments; SETs are
    /// sorted and values normalized as in DER.
    Cer,
    /// X.690 §10. Exactly one encoding per value: shortest definite lengths,
    /// primitive strings, sorted SETs, normalized values.
    Der,
}

impl EncodingOptions {
    /// Whether the §11 canonical restrictions apply (CER and DER). Constant time.
    pub const fn is_canonical(self) -> bool {
        matches!(self, Self::Cer | Self::Der)
    }
}

#[cfg(test)]
mod tests {
    use super::EncodingOptions;

    #[test]
    fn canonical_restrictions_apply_to_cer_and_der_but_not_ber() {
        assert!(!EncodingOptions::Ber(crate::LengthForm::Definite).is_canonical());
        assert!(!EncodingOptions::Ber(crate::LengthForm::Indefinite).is_canonical());
        assert!(EncodingOptions::Cer.is_canonical());
        assert!(EncodingOptions::Der.is_canonical());
    }
}
