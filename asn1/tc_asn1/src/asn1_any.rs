//! Owned storage for a complete ASN.1 TLV whose content type is not interpreted.
//!
//! Use [`Asn1Any`] for schema fields of type ANY, unknown tags, or known values
//! whose typed decoding is deferred. It preserves the original encoding and
//! exposes a borrowed [`Asn1Ref`] when inspection or typed decoding is needed.
//! Construct new typed values with their corresponding ASN.1 value types.

use alloc::vec::Vec;

use crate::EncodingOptions;
use crate::asn1_ref::Asn1Ref;
use crate::decoding_options::DecodingOptions;
use crate::error::Asn1Error;
use crate::traits::{Decode, Encode};

/// An owned counterpart of [`Asn1Ref`] that preserves one complete encoded element.
///
/// The stored bytes include the identifier, length field, contents, and any
/// closing EOC. Boundary offsets allow [`as_ref`](Self::as_ref) to borrow these
/// parts without copying or reparsing, including for indefinite-length encodings.
/// The value is independent of the input buffer after construction.
///
/// Parsing checks TLV boundaries and the supplied decoding limits, not the
/// validity of the contents for a particular ASN.1 type. Definite-length opaque
/// descendants remain unchecked until traversed or decoded.
///
/// [`Encode`] preserves the original bytes under every encoding rule, including
/// DER and CER; selecting a rule does not canonicalize this value. Equality
/// compares the stored representation, not the abstract value after typed decoding.
///
/// This type implements [`Decode`], but not [`crate::DecodeContent`]: contents
/// alone do not supply the identifier or original header needed to preserve a TLV.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Any, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType};
///
/// let saved = {
///     let input = vec![0x83, 0x81, 1, 0xAA]; // Unknown tag, long-form length.
///     let (used, saved) = Asn1Any::try_decode(&input, DecodingOptions::default())?;
///     assert_eq!(used, input.len());
///     saved
/// };
/// assert_eq!(saved.as_ref().tag(), &[0x83]);
/// assert_eq!(saved.as_ref().value(), &[0xAA]);
/// assert_eq!(saved.encode_to_vec(&EncodingOptions::new(EncodingType::Der))?, &[0x83, 0x81, 1, 0xAA]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Any {
    /// Complete original encoding of exactly one element.
    raw: Vec<u8>,
    /// Start of the length field, immediately after the identifier.
    length_offset: usize,
    /// Start of the contents, immediately after the length field.
    value_offset: usize,
    /// Start of the closing EOC, or `raw.len()` for a definite-length element.
    eoc_offset: usize,
}

impl Asn1Any {
    /// Borrow the complete original encoding, including any closing EOC.
    /// Constant time: borrows the stored vector without copying.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Decode, DecodingOptions};
    /// let (_, saved) = Asn1Any::try_decode(&[5, 0, 2, 1, 7], DecodingOptions::default())?;
    /// assert_eq!(saved.raw(), &[5, 0]); // Following elements are not retained.
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Borrow a view for inspecting tags, traversing children, or typed decoding.
    ///
    /// Uses the boundaries saved when the TLV was parsed, without resetting limits
    /// or reparsing an indefinite-length value. Constant time.
    /// The returned view borrows `self`; its lifetime cannot outlive this value.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Asn1Boolean, Decode, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let (_, saved) = Asn1Any::try_decode(&[1, 1, 0xFF], options)?;
    /// let view = saved.as_ref();
    /// assert_eq!(view.tag(), Asn1Boolean::TAG); // Validate the schema's tag first.
    /// assert!(view.decode_as::<Asn1Boolean>(options)?.is_true());
    /// assert_eq!(view.raw().as_ptr(), saved.raw().as_ptr());
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn as_ref(&self) -> Asn1Ref<'_> {
        Asn1Ref::from_validated_parts(
            &self.raw,
            self.length_offset,
            self.value_offset,
            self.eoc_offset,
        )
    }
}

impl From<&Asn1Ref<'_>> for Asn1Any {
    /// Copy a parsed element and retain its validated boundary offsets.
    /// No additional parsing or content validation is performed.
    /// Variable time: allocation and copying depend on public input length;
    /// no constant-time alternative is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Asn1Ref, DecodingOptions};
    /// let input = [0x30, 0x80, 5, 0, 0, 0];
    /// let view = Asn1Ref::parse(&input, DecodingOptions::default())?;
    /// let saved = Asn1Any::from(&view);
    /// assert_eq!(saved.raw(), &input);
    /// assert_eq!(saved.as_ref().value(), &[5, 0]);
    /// assert_eq!(saved.as_ref().eoc(), &[0, 0]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn from(element: &Asn1Ref<'_>) -> Self {
        let eoc_offset = element.total_len() - element.eoc().len();
        Self {
            raw: element.raw().to_vec(),
            length_offset: element.tag().len(),
            value_offset: eoc_offset - element.value().len(),
            eoc_offset,
        }
    }
}

/// Preserve one complete TLV without assigning a content type.
impl<'a> Decode<'a> for Asn1Any {
    /// Parse and copy the first complete element, returning its consumed length.
    /// Trailing input is left to the caller. Errors from [`Asn1Ref::parse`] are
    /// propagated, including truncation, malformed headers, and exceeded limits.
    /// Variable time: public input only; no constant-time alternative is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Asn1Error, Decode, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let input = [0x83, 1, 0xAA, 5, 0];
    /// let (used, saved) = Asn1Any::try_decode(&input, options)?;
    /// assert_eq!(used, 3);
    /// assert_eq!(saved.raw(), &input[..used]);
    /// assert_eq!(&input[used..], &[5, 0]);
    /// assert_eq!(Asn1Any::try_decode(&[4, 1], options), Err(Asn1Error::Truncated));
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn try_decode(buff: &'a [u8], options: DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, options)?;
        Ok((element.total_len(), Self::from(&element)))
    }
}

/// Copy the preserved contents without interpreting or canonicalising them.
impl crate::EncodeContent for Asn1Any {
    /// Return the content length, excluding this element's header and closing EOC.
    /// Nested TLVs remain complete. Encoding rules do not affect the result.
    /// Constant time: obtains the length from saved boundaries.
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.as_ref().value().len()
    }

    /// Copy only the contents, leaving any unused output tail untouched.
    /// Returns [`Asn1Error::BufferTooSmall`] if the output cannot hold them.
    /// Variable time: copies public content bytes; no constant-time alternative.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Asn1Error, Decode, DecodingOptions, EncodeContent, EncodingOptions, EncodingType};
    /// let (_, saved) = Asn1Any::try_decode(
    ///     &[0x30, 0x80, 5, 0, 0, 0], DecodingOptions::default(),
    /// )?;
    /// let mut out = [0xAA; 3];
    /// assert_eq!(saved.content_len(&EncodingOptions::new(EncodingType::Der)), 2);
    /// assert_eq!(saved.encode_content(&EncodingOptions::new(EncodingType::Der), &mut out)?, 2);
    /// assert_eq!(out, [5, 0, 0xAA]);
    /// assert_eq!(
    ///     saved.encode_content(&EncodingOptions::new(EncodingType::Der), &mut [0]),
    ///     Err(Asn1Error::BufferTooSmall),
    /// );
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let len = crate::EncodeContent::content_len(self, rules);
        let out = out.get_mut(..len).ok_or(Asn1Error::BufferTooSmall)?;
        let value = self.as_ref().value();
        out[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }
}

/// Rebuild the outer header using the caller's tag and encoding options.
///
/// The contents are copied unchanged. Unlike [`Encode`], this operation does not
/// preserve the original header. It does not canonicalize nested contents;
/// the caller is responsible for choosing an appropriate identifier and form.
/// Variable time: public values only; no constant-time alternative is provided.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Any, Decode, DecodingOptions, EncodeTagged, EncodingOptions, EncodingType};
/// let (_, saved) = Asn1Any::try_decode(&[4, 0x81, 1, 0xAA], DecodingOptions::default())?;
/// let mut out = [0; 3];
/// assert_eq!(saved.encode_tagged(&[0x80], &EncodingOptions::new(EncodingType::Der), &mut out)?, 3);
/// assert_eq!(out, [0x80, 1, 0xAA]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
impl crate::EncodeTagged for Asn1Any {}

impl Encode for Asn1Any {
    /// Return the size of the complete original TLV under any encoding rule.
    /// Constant time: reads the stored vector's length.
    fn encoded_len(&self, _: &EncodingOptions) -> usize {
        self.raw.len()
    }

    /// Copy the complete original TLV, ignoring the selected encoding rules.
    ///
    /// DER or CER selection does not validate or canonicalize the stored bytes.
    /// Returns [`Asn1Error::BufferTooSmall`] without writing if the output is too
    /// short; otherwise any unused output tail is left untouched.
    /// Variable time: copies public input bytes; no constant-time alternative.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Any, Decode, DecodingOptions, Encode, EncodingOptions, EncodingType};
    /// let (_, saved) = Asn1Any::try_decode(&[1, 1, 1], DecodingOptions::default())?;
    /// for rules in [&EncodingOptions::new(EncodingType::Der), &EncodingOptions::new(EncodingType::Cer)] {
    ///     let mut out = [0xAA; 4];
    ///     assert_eq!(saved.encoded_len(rules), 3);
    ///     assert_eq!(saved.encode(rules, &mut out)?, 3);
    ///     assert_eq!(out, [1, 1, 1, 0xAA]); // The original TRUE octet is preserved.
    /// }
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn encode(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.raw.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.raw);
        Ok(self.raw.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodeTagged;
    use crate::EncodingType;
    use crate::asn1_ref::Asn1Class;
    use crate::universal::Asn1Boolean;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn an_unknown_context_specific_value_survives_a_round_trip_untouched() {
        // [3] IMPLICIT 某個東西，內容不知道是什麼；後面還有別的
        let input = [0x83, 0x03, 0xDE, 0xAD, 0x01, 0xAA];
        let (used, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();

        assert_eq!(used, 5);
        assert_eq!(any.raw(), &input[..5]);
        assert_eq!(any.as_ref().tag(), &[0x83]);
        assert_eq!(any.as_ref().value(), &[0xDE, 0xAD, 0x01]);
        assert_eq!(any.as_ref().class(), Asn1Class::ContextSpecific);

        let mut out = [0_u8; 8];
        let written = any
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &input[..5]);
    }

    #[test]
    fn even_the_length_form_is_preserved_on_re_emission() {
        // 81 03 不是最短的長度寫法。原樣留著。
        let input = [0x04, 0x81, 0x03, 0xAA, 0xBB, 0xCC];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();

        let mut out = [0_u8; 8];
        let written = any
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &input);
        assert_eq!(any.encoded_len(&EncodingOptions::new(EncodingType::Der)), 6);
    }

    #[test]
    fn retagging_rebuilds_the_header_but_keeps_the_contents() {
        let (_, any) = Asn1Any::try_decode(&[0x04, 0x81, 0x01, 0xAA], OPTIONS).unwrap();
        let mut out = [0_u8; 8];
        let written = any
            .encode_tagged(&[0x80], &EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &[0x80, 0x01, 0xAA], "換 tag 就得重寫表頭");
    }

    #[test]
    fn a_known_type_can_be_recovered_later_through_as_ref() {
        let (_, any) = Asn1Any::try_decode(&[0x01, 0x01, 0xFF], OPTIONS).unwrap();
        assert_eq!(
            any.as_ref().decode_as::<Asn1Boolean>(OPTIONS),
            Ok(Asn1Boolean::from(true))
        );
    }

    #[test]
    fn a_constructed_value_keeps_its_children_reachable() {
        let (_, any) = Asn1Any::try_decode(&[0x30, 0x04, 0x05, 0x00, 0x05, 0x00], OPTIONS).unwrap();
        assert!(any.as_ref().is_constructed());
        assert_eq!(any.as_ref().children(OPTIONS).count(), 2);
    }

    #[test]
    fn an_indefinite_length_value_re_parses_to_the_same_shape() {
        let input = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();
        assert_eq!(any.as_ref().value(), &[0x05, 0x00]);
        assert_eq!(any.as_ref().children(OPTIONS).count(), 1);
    }

    #[test]
    fn non_der_input_is_re_emitted_as_is_not_normalised() {
        // BOOLEAN 真寫成 01 不是 DER；Asn1Any 不知道那是 BOOLEAN，所以原樣重送。
        let input = [0x01, 0x01, 0x01];
        let (_, any) = Asn1Any::try_decode(&input, OPTIONS).unwrap();
        let mut out = [0_u8; 8];
        let written = any
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &input, "保真優先於正規化");
    }
}
