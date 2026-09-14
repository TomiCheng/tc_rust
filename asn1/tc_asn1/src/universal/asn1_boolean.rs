//! ASN.1 BOOLEAN values with BER decoding and canonical content encoding.

use crate::DecodingContext;
use crate::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// An ASN.1 BOOLEAN stored as a Rust `bool`, without retaining its original encoding.
///
/// Construct values with [`From<bool>`], and inspect them with [`Self::is_true`]
/// or [`Self::is_false`]. Equality and hashing operate on the logical value;
/// different nonzero content octets decode to equal values with equal hashes.
/// [`core::fmt::Display`] writes lowercase `true` or `false`.
///
/// Decoding accepts exactly one content octet: zero means false and any nonzero
/// value means true. The full TLV decoder requires primitive form, while the
/// caller's schema checks the tag class and number. This type does not implement
/// [`crate::DecodeConstructed`]. Decoding does not enforce DER canonicality.
///
/// Encoding always writes `00` for false or `FF` for true under BER, CER, and DER.
/// The default tag is [`Self::TAG`]; the complete encoding has a definite length
/// and no EOC, even with indefinite-length BER options. To preserve the original
/// bytes instead of the logical value, use [`crate::Asn1Any`].
///
/// # Examples
/// ```
/// use tc_asn1::{Decode, Asn1Boolean, DecodeInner, DecodingOptions, Encode, EncodingOptions, EncodingType};
/// let (used, value) = Asn1Boolean::decode(
///     &[0x01, 0x01, 0x7F], &DecodingOptions::default(),
/// )?;
/// assert_eq!(used, 3);
/// assert!(value.is_true());
/// assert_eq!(value, Asn1Boolean::from(true));
/// assert_eq!(value.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?, [0x01, 0x01, 0xFF]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Boolean(bool);

impl Asn1Boolean {
    /// Universal primitive identifier octets (`01`) for BOOLEAN.
    pub const TAG: &'static [u8] = super::tag::BOOLEAN;

    /// Return whether this value is true. Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::Asn1Boolean;
    /// assert!(Asn1Boolean::from(true).is_true());
    /// assert!(!Asn1Boolean::from(false).is_true());
    /// ```
    pub const fn is_true(&self) -> bool {
        self.0
    }

    /// Return whether this value is false. Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::Asn1Boolean;
    /// assert!(Asn1Boolean::from(false).is_false());
    /// assert!(!Asn1Boolean::from(true).is_false());
    /// ```
    pub const fn is_false(&self) -> bool {
        !self.0
    }
}

impl From<bool> for Asn1Boolean {
    /// Construct a BOOLEAN from a Rust `bool` without allocation. Constant time.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::Asn1Boolean;
    /// let value: Asn1Boolean = true.into();
    /// assert!(value.is_true());
    /// assert!(Asn1Boolean::from(false).is_false());
    /// ```
    fn from(value: bool) -> Self {
        Self(value)
    }
}

/// Format the value as `true` or `false`, matching Rust's `bool` formatting.
/// Variable time: public values only; no constant-time alternative is provided.
///
/// # Examples
/// ```
/// use tc_asn1::Asn1Boolean;
/// assert_eq!(Asn1Boolean::from(true).to_string(), "true");
/// assert_eq!(Asn1Boolean::from(false).to_string(), "false");
/// ```
impl core::fmt::Display for Asn1Boolean {
    /// Delegate formatting to the stored `bool`, including formatter options.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl<'a> crate::DecodeInner<'a> for Asn1Boolean {
    /// Decode the first primitive TLV and return its consumed byte count and value.
    ///
    /// The result does not borrow from `buff`. Bytes after the first TLV are left
    /// to the caller; all contents inside that TLV must form a single octet.
    /// The schema must validate the identifier: this method accepts IMPLICIT tags
    /// and does not require [`Self::TAG`].
    /// Variable time: public input only; no constant-time alternative is provided.
    ///
    /// # Errors
    /// Propagates parsing and limit errors from [`crate::Asn1Ref::parse`]. After
    /// parsing, returns [`Asn1Error::UnexpectedTag`] for constructed form, or
    /// [`Asn1Error::MalformedValue`] for a content length other than one.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Decode, Asn1Boolean, Asn1Error, DecodeInner, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// // The schema selected context-specific [0] IMPLICIT BOOLEAN.
    /// let input = [0x80, 1, 0xFF, 0];
    /// let (used, value) = Asn1Boolean::decode(&input, &options)?;
    /// assert!(value.is_true());
    /// assert_eq!(&input[used..], &[0]);
    /// assert_eq!(
    ///     Asn1Boolean::decode(&[0x01, 2, 0xFF, 0], &options),
    ///     Err(Asn1Error::MalformedValue),
    /// );
    /// assert_eq!(
    ///     Asn1Boolean::decode(&[0x21, 0], &options),
    ///     Err(Asn1Error::UnexpectedTag),
    /// );
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn decode_inner(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = <Self as DecodeContent<'a>>::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.is_constructed() {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = <Self as DecodeContent<'a>>::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl<'a> crate::Decode<'a> for Asn1Boolean {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl<'a> DecodeContent<'a> for Asn1Boolean {
    /// Decode one content octet without an outer tag or length field.
    ///
    /// Zero becomes false; every nonzero octet becomes true. The original octet
    /// is not retained, and the result does not borrow from the input.
    /// Variable time: public input only; no constant-time alternative is provided.
    ///
    /// # Errors
    /// Returns [`Asn1Error::ContentLengthExceeded`] if the configured content
    /// limit is exceeded; otherwise returns [`Asn1Error::MalformedValue`] unless
    /// the input contains exactly one octet.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Asn1Error, DecodeContent, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// assert!(Asn1Boolean::decode_content(&[0], &mut context)?.is_false());
    /// assert!(Asn1Boolean::decode_content(&[1], &mut context)?.is_true());
    /// assert_eq!(
    ///     Asn1Boolean::decode_content(&[], &mut context),
    ///     Err(Asn1Error::MalformedValue),
    /// );
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        match value {
            // Accept BER truth values; re-encoding normalizes nonzero octets to FF.
            [octet] => Ok(Asn1Boolean(*octet != 0)),
            _ => Err(Asn1Error::MalformedValue),
        }
    }

    fn decode_content_der(
        value: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<Self, crate::Asn1Error> {
        crate::decoding::decode_der_content::<Self>(value, context)
    }
}

impl crate::EncodeContent for Asn1Boolean {
    /// Return one, independently of the value and encoding rules.
    /// This is the content length only, excluding the outer header.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        1
    }

    /// Write `FF` for true or `00` for false, without the outer header or EOC.
    /// All encoding rules produce the same content octet. Returns one on success
    /// and leaves any remaining output bytes unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    /// Returns [`Asn1Error::BufferTooSmall`] for an empty output buffer.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Asn1Error, EncodeContent, EncodingOptions, EncodingType};
    /// let value = Asn1Boolean::from(false);
    /// let mut out = [0xAA; 2];
    /// assert_eq!(value.content_len(&EncodingOptions::new(EncodingType::Der)), 1);
    /// assert_eq!(value.encode_content(&EncodingOptions::new(EncodingType::Der), &mut out)?, 1);
    /// assert_eq!(out, [0, 0xAA]);
    /// assert_eq!(
    ///     value.encode_content(&EncodingOptions::new(EncodingType::Der), &mut []),
    ///     Err(Asn1Error::BufferTooSmall),
    /// );
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let octet = out.first_mut().ok_or(Asn1Error::BufferTooSmall)?;
        *octet = u8::from(self.0).wrapping_neg();
        Ok(1)
    }
}

/// Encode with a schema-selected IMPLICIT identifier and canonical BOOLEAN contents.
///
/// The caller must supply complete, nonempty, valid primitive identifier octets.
/// The inherited methods copy the tag without validation; see
/// [`crate::EncodeTagged`] for their error and panic contracts.
/// Variable time: public values only; no constant-time alternative is provided.
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Boolean, EncodeTagged, EncodingOptions, EncodingType};
/// let value = Asn1Boolean::from(true);
/// let mut out = [0; 3];
/// value.encode_tagged(&[0xC1], &EncodingOptions::new(EncodingType::Der), &mut out)?;
/// assert_eq!(out, [0xC1, 1, 0xFF]); // Private [1] IMPLICIT BOOLEAN.
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
impl crate::EncodeTagged for Asn1Boolean {}

impl Encode for Asn1Boolean {
    /// Return three: one identifier octet, one length octet, and one content octet.
    /// The result is the same under every encoding rule.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    /// Write a complete BOOLEAN TLV using [`Self::TAG`] and a definite length.
    ///
    /// Writes `01 01 00` for false or `01 01 FF` for true under every encoding
    /// rule, including indefinite-length BER. Returns three on success and
    /// leaves any remaining output bytes unchanged.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    /// Returns [`Asn1Error::BufferTooSmall`] without writing if `out` has fewer
    /// than three bytes.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Asn1Error, Encode, EncodingOptions, EncodingType, LengthForm};
    /// let value = Asn1Boolean::from(true);
    /// for rules in [
    ///     &EncodingOptions::new(EncodingType::Ber(LengthForm::Definite)),
    ///     &EncodingOptions::new(EncodingType::Ber(LengthForm::Indefinite)),
    ///     &EncodingOptions::new(EncodingType::Cer),
    ///     &EncodingOptions::new(EncodingType::Der),
    /// ] {
    ///     let mut out = [0xAA; 4];
    ///     assert_eq!(value.encoded_len(rules), 3);
    ///     assert_eq!(value.encode(rules, &mut out)?, 3);
    ///     assert_eq!(out, [0x01, 0x01, 0xFF, 0xAA]);
    /// }
    /// let mut short = [0xAA; 2];
    /// assert_eq!(
    ///     value.encode(&EncodingOptions::new(EncodingType::Der), &mut short),
    ///     Err(Asn1Error::BufferTooSmall),
    /// );
    /// assert_eq!(short, [0xAA; 2]);
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodingOptions;
    use crate::EncodeContent;
    use crate::EncodingType;
    use crate::traits::Decode;

    #[test]
    fn content_encoding_supports_trait_objects_and_preserves_buffer_boundaries() {
        for rules in [
            &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
            &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Indefinite)),
            &EncodingOptions::new(EncodingType::Cer),
            &EncodingOptions::new(EncodingType::Der),
        ] {
            for (value, expected) in [(Asn1Boolean(false), 0x00), (Asn1Boolean(true), 0xFF)] {
                let encoder: &dyn EncodeContent = &value;
                assert_eq!(encoder.content_len(rules), 1);
                assert_eq!(encoder.encode_content_to_vec(rules).unwrap(), [expected]);

                let mut out = [0xAA; 3];
                assert_eq!(encoder.encode_content(rules, &mut out), Ok(1));
                assert_eq!(out, [expected, 0xAA, 0xAA]);
                assert_eq!(
                    encoder.encode_content(rules, &mut []),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
        }
    }

    #[test]
    fn true_is_written_as_all_ones_and_false_as_zero() {
        let mut out = [0_u8; 4];
        assert_eq!(
            Asn1Boolean(true)
                .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
                .unwrap(),
            3
        );
        assert_eq!(&out[..3], &[0x01, 0x01, 0xFF]);
        assert_eq!(
            Asn1Boolean(false)
                .encode(
                    &EncodingOptions::new(EncodingType::Ber(crate::LengthForm::Definite)),
                    &mut out
                )
                .unwrap(),
            3
        );
        assert_eq!(&out[..3], &[0x01, 0x01, 0x00]);
    }

    #[test]
    fn a_non_canonical_true_re_encodes_as_der() {
        // Re-encoding exposes the noncanonical TRUE octet: 01 becomes FF.
        let (_, b) = Asn1Boolean::decode(&[0x01, 0x01, 0x01], &OPTIONS).unwrap();
        let mut out = [0_u8; 4];
        b.encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..3], &[0x01, 0x01, 0xFF]);
    }

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT.get(), 16 * 1024 * 1024, 65_536);

    #[test]
    fn true_and_false_decode_from_their_single_octet() {
        assert_eq!(
            Asn1Boolean::decode(&[0x01, 0x01, 0xFF], &OPTIONS),
            Ok((3, Asn1Boolean(true)))
        );
        assert_eq!(
            Asn1Boolean::decode(&[0x01, 0x01, 0x00], &OPTIONS),
            Ok((3, Asn1Boolean(false)))
        );
    }

    #[test]
    fn any_non_zero_octet_is_true_under_ber() {
        for octet in [0x01_u8, 0x7F, 0x80, 0xFE] {
            assert_eq!(
                Asn1Boolean::decode_content(&[octet], &mut DecodingContext::new(&OPTIONS)),
                Ok(Asn1Boolean(true))
            );
        }
    }

    #[test]
    fn contents_of_any_length_but_one_are_rejected() {
        assert_eq!(
            Asn1Boolean::decode_content(&[], &mut DecodingContext::new(&OPTIONS)),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Boolean::decode_content(&[0xFF, 0xFF], &mut DecodingContext::new(&OPTIONS)),
            Err(Asn1Error::MalformedValue)
        );
    }
}
