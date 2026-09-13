//! Shared configuration for length calculation and encoding.

use crate::EncodingType;

/// Options borrowed by length calculation and encoding methods.
///
/// Pass the same options to both operations. The encoding rules are selected
/// separately through [`EncodingType`], leaving this structure extensible for
/// additional settings. This type is not `Copy`; encoders borrow it instead.
///
/// [`crate::Asn1Any`] and [`crate::Asn1Object::Unknown`] preserve their raw encodings;
/// these options do not rewrite their original length forms or canonicalize their contents.
///
/// # Examples
///
/// Indefinite-length BER preserves stored SET order, whereas CER sorts the members.
///
/// ```
/// use tc_asn1::{Asn1Integer, Asn1Object, Encode, EncodingOptions, EncodingType, LengthForm};
/// let set = Asn1Object::Set(vec![
///     Asn1Integer::from(5_u8).into(),
///     Asn1Integer::from(3_u8).into(),
/// ]);
/// let options = EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite));
/// let mut buffer = vec![0; set.encoded_len(&options)];
/// set.encode(&options, &mut buffer)?;
/// assert_eq!(buffer, [0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingOptions {
    encoding_type: EncodingType,
}

impl EncodingOptions {
    /// Construct options for the selected encoding rules. Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{EncodingOptions, EncodingType};
    /// let options = EncodingOptions::new(EncodingType::Der);
    /// assert_eq!(options.encoding_type(), EncodingType::Der);
    /// ```
    pub const fn new(encoding_type: EncodingType) -> Self {
        Self { encoding_type }
    }

    /// Return the selected encoding rules without copying the options. Constant time.
    pub const fn encoding_type(&self) -> EncodingType {
        self.encoding_type
    }

    /// Return whether canonical restrictions apply (CER and DER). Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{EncodingOptions, EncodingType};
    /// let options = EncodingOptions::new(EncodingType::Cer);
    /// assert!(options.is_canonical());
    /// ```
    pub const fn is_canonical(&self) -> bool {
        self.encoding_type.is_canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::EncodingOptions;
    use crate::{EncodingType, LengthForm};

    #[test]
    fn canonical_restrictions_apply_to_cer_and_der_but_not_ber() {
        assert!(!EncodingOptions::new(EncodingType::Ber(LengthForm::Definite)).is_canonical());
        assert!(!EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite)).is_canonical());
        assert!(EncodingOptions::new(EncodingType::Cer).is_canonical());
        assert!(EncodingOptions::new(EncodingType::Der).is_canonical());
    }
}
