//! Encoding contracts. These traits have no associated constants and support trait objects.
//!
//! [`EncodeContent`] writes only contents, [`EncodeTagged`] adds a caller-supplied
//! tag and the outer framing, and [`Encode`] selects the value's own tag.
//! Implementing a prerequisite trait does not automatically implement the next
//! trait: each type opts in explicitly and may override the default methods.

use alloc::vec::Vec;

use crate::encoding::{default_encode, default_encoded_len};
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;

/// Encode contents without the outer tag, length field, or end-of-contents marker.
///
/// Contents depend on the encoding rules. Constructed values contain complete child
/// TLVs, and long CER strings contain segment TLVs. Only the outer framing is omitted.
///
/// For the same value and rules, [`content_len`](Self::content_len) must equal the
/// number of bytes successfully written by [`encode_content`](Self::encode_content).
/// Variable-time contract: public values only; no constant-time alternative is provided.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Boolean, EncodeContent, EncodingOptions};
///
/// let value: &dyn EncodeContent = &Asn1Boolean::from(true);
/// assert_eq!(value.encode_content_to_vec(EncodingOptions::Der)?, [0xff]);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub trait EncodeContent {
    /// Allocate a Vec and encode only the contents, without the outer header or EOC.
    ///
    /// Allocates the length reported by [`content_len`](Self::content_len).
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    ///
    /// Returns errors from [`encode_content`](Self::encode_content) unchanged.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the reported and written content lengths disagree.
    fn encode_content_to_vec(&self, rules: EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.content_len(rules)];
        let written = self.encode_content(rules, &mut out)?;
        debug_assert_eq!(
            written,
            out.len(),
            "content_len and encode_content disagree"
        );
        Ok(out)
    }

    /// Content length in bytes; use the same options for length calculation and encoding.
    ///
    /// Includes any child or segment TLVs, but excludes the outer tag, length field,
    /// and end-of-contents marker. Must match [`encode_content`](Self::encode_content).
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn content_len(&self, rules: EncodingOptions) -> usize;

    /// Write only the contents and return the number of bytes written.
    ///
    /// The caller must provide at least `content_len(rules)` bytes in `out`.
    /// On success, writes exactly that many bytes and leaves the remaining output unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    ///
    /// Returns errors encountered while encoding the contents or their children.
    /// The crate's implementations return [`Asn1Error::BufferTooSmall`] for insufficient
    /// output space. Output may be partially written when an encoding error occurs.
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
}

/// Encode a complete TLV using a caller-supplied tag.
///
/// Used for IMPLICIT tagging: the supplied tag replaces the value's usual tag.
/// To wrap the original TLV in another TLV, use [`Explicit`](crate::Explicit).
///
/// The default methods frame the contents provided by [`EncodeContent`], using
/// indefinite lengths for constructed tags under CER or indefinite-length BER.
/// Types with special framing, such as CER string segmentation, can override them.
/// Overrides must keep the length calculation and encoded output consistent.
/// Variable-time contract: public values only; no constant-time alternative is provided.
///
/// # Tag requirements
///
/// The caller supplies complete, nonempty, valid ASN.1 identifier octets, including
/// the class and primitive/constructed bit. The default methods copy the tag without
/// validation; its form must be appropriate for the contents and encoding rules.
/// String implementations may adjust the constructed bit for CER segmentation.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Integer, EncodeTagged, EncodingOptions};
///
/// let value = Asn1Integer::from(5_u8);
/// let mut out = [0; 3];
/// let written = value.encode_tagged(&[0x80], EncodingOptions::Der, &mut out)?;
/// assert_eq!(written, 3);
/// assert_eq!(out, [0x80, 1, 5]); // Context-specific [0] IMPLICIT INTEGER.
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
pub trait EncodeTagged: EncodeContent {
    /// Complete TLV length in bytes using the caller-supplied tag.
    ///
    /// Includes the outer tag, length field, contents, and any end-of-contents marker.
    /// Use the same tag and rules when calling [`encode_tagged`](Self::encode_tagged).
    /// The tag must satisfy the [trait's requirements](EncodeTagged#tag-requirements).
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Panics
    ///
    /// The default implementation may panic if `tag` is empty.
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
        default_encoded_len(self, tag, rules)
    }

    /// Write a complete TLV using the caller-supplied tag, as used by IMPLICIT tagging.
    ///
    /// The caller must provide at least `encoded_len_tagged(tag, rules)` bytes in `out`.
    /// Returns the number of bytes written and leaves the remaining output unchanged.
    /// The tag must satisfy the [trait's requirements](EncodeTagged#tag-requirements).
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    ///
    /// The default implementation returns [`Asn1Error::BufferTooSmall`] before writing
    /// if `out` is too short, and propagates errors from [`EncodeContent::encode_content`].
    /// An error from content encoding may leave the header and part of the contents written.
    ///
    /// # Panics
    ///
    /// The default implementation may panic if `tag` is empty. In debug builds, it
    /// also panics if the reported and written content lengths disagree.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, tag, rules, out)
    }
}

/// Encode a complete TLV using the value's own tag.
///
/// Each type implements [`encoded_len`](Self::encoded_len) and [`encode`](Self::encode)
/// and selects its tag internally; no tag accessor is required by this trait.
/// Ordinary values can delegate these methods to [`EncodeTagged`] with their own tag.
/// Raw values such as [`Asn1Any`](crate::Asn1Any) may preserve the original framing instead.
///
/// The reported length must match the number of bytes successfully written for the
/// same value and rules. All three encoding traits support trait objects, including
/// `&dyn Encode` for heterogeneous values.
/// Variable-time contract: public values only; no constant-time alternative is provided.
pub trait Encode: EncodeTagged {
    /// Allocate an exactly sized Vec and encode a complete TLV.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// Corresponds to Bouncy Castle's `GetEncoded(encoding)`.
    ///
    /// # Errors
    ///
    /// Returns errors from [`encode`](Self::encode) unchanged.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the reported and written encoded lengths disagree.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Boolean, Encode, EncodingOptions};
    /// assert_eq!(Asn1Boolean::from(true).encode_to_vec(EncodingOptions::Der)?, [1, 1, 255]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn encode_to_vec(&self, rules: EncodingOptions) -> Result<Vec<u8>, Asn1Error> {
        let mut out = alloc::vec![0; self.encoded_len(rules)];
        let written = self.encode(rules, &mut out)?;
        debug_assert_eq!(written, out.len(), "encoded_len and encode disagree");
        Ok(out)
    }

    /// Complete TLV length in bytes.
    ///
    /// Includes the outer framing and any end-of-contents marker. Must match
    /// [`encode`](Self::encode) for the same value and encoding rules.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    fn encoded_len(&self, rules: EncodingOptions) -> usize;

    /// Write a complete TLV using the value's own tag.
    ///
    /// The caller must provide at least `encoded_len(rules)` bytes in `out`.
    /// Returns that length on success and leaves the remaining output unchanged.
    /// Variable-time contract: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    ///
    /// Returns errors encountered during encoding, including [`Asn1Error::BufferTooSmall`]
    /// in the crate's implementations when the output is too short. Output may be
    /// partially written when an encoding error occurs.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Integer, Encode, EncodingOptions};
    ///
    /// let value = Asn1Integer::from(5_u8);
    /// let mut out = [0; 3];
    /// assert_eq!(value.encode(EncodingOptions::Der, &mut out)?, 3);
    /// assert_eq!(out, [2, 1, 5]); // Universal INTEGER tag.
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Boolean, Asn1Object, Asn1Tagged, Decode, DecodingOptions};
    use alloc::boxed::Box;
    use alloc::vec;

    impl<T: ?Sized + EncodeContent> EncodeContent for Box<T> {
        fn content_len(&self, rules: EncodingOptions) -> usize {
            (**self).content_len(rules)
        }

        fn encode_content(
            &self,
            rules: EncodingOptions,
            out: &mut [u8],
        ) -> Result<usize, Asn1Error> {
            (**self).encode_content(rules, out)
        }
    }

    impl<T: ?Sized + EncodeTagged> EncodeTagged for Box<T> {
        fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
            (**self).encoded_len_tagged(tag, rules)
        }

        fn encode_tagged(
            &self,
            tag: &[u8],
            rules: EncodingOptions,
            out: &mut [u8],
        ) -> Result<usize, Asn1Error> {
            (**self).encode_tagged(tag, rules, out)
        }
    }

    impl<T: ?Sized + Encode> Encode for Box<T> {
        fn encoded_len(&self, rules: EncodingOptions) -> usize {
            (**self).encoded_len(rules)
        }

        fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
            (**self).encode(rules, out)
        }
    }

    #[test]
    fn indefinite_ber_preserves_nested_set_order_and_accounts_for_every_end_marker() {
        use crate::{Asn1Integer, LengthForm};
        let options = EncodingOptions::Ber(LengthForm::Indefinite);
        let set = Asn1Object::Set(vec![
            Asn1Integer::from(5_u8).into(),
            Asn1Integer::from(3_u8).into(),
        ]);
        for (tree, expected) in [
            (Asn1Object::Set(vec![]), vec![0x31, 0x80, 0, 0]),
            (set.clone(), vec![0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0]),
            (
                Asn1Object::Sequence(vec![set]),
                vec![0x30, 0x80, 0x31, 0x80, 2, 1, 5, 2, 1, 3, 0, 0, 0, 0],
            ),
        ] {
            let boxed: Box<dyn Encode> = Box::new(tree.clone());
            for encoder in [&tree as &dyn Encode, boxed.as_ref()] {
                assert_eq!(encoder.encoded_len(options), expected.len());
                assert_eq!(encoder.encode_to_vec(options).unwrap(), expected);
                let mut out = vec![0xaa; expected.len() + 3];
                assert_eq!(encoder.encode(options, &mut out).unwrap(), expected.len());
                assert_eq!(&out[..expected.len()], expected);
                assert_eq!(&out[expected.len()..], &[0xaa; 3]);
                assert_eq!(
                    encoder.encode(options, &mut vec![0; expected.len() - 1]),
                    Err(Asn1Error::BufferTooSmall)
                );
            }
            assert_eq!(
                Asn1Object::try_decode(&expected, DecodingOptions::default())
                    .map(|(_, value)| value)
                    .unwrap(),
                tree
            );
        }
    }

    #[test]
    fn indefinite_ber_does_not_apply_canonical_set_of_sorting() {
        use crate::{Asn1SetOf, LengthForm};
        let set = Asn1SetOf::from(vec![Asn1Boolean::from(true), Asn1Boolean::from(false)]);
        for (options, expected) in [
            (
                EncodingOptions::Ber(LengthForm::Definite),
                vec![0x31, 6, 1, 1, 255, 1, 1, 0],
            ),
            (
                EncodingOptions::Ber(LengthForm::Indefinite),
                vec![0x31, 0x80, 1, 1, 255, 1, 1, 0, 0, 0],
            ),
            (
                EncodingOptions::Cer,
                vec![0x31, 0x80, 1, 1, 0, 1, 1, 255, 0, 0],
            ),
            (EncodingOptions::Der, vec![0x31, 6, 1, 1, 0, 1, 1, 255]),
        ] {
            assert_eq!(set.encoded_len(options), expected.len());
            assert_eq!(set.encode_to_vec(options).unwrap(), expected);
            if !options.is_canonical() {
                assert_eq!(
                    Asn1SetOf::<Asn1Boolean>::try_decode(&expected, DecodingOptions::default())
                        .map(|(_, value)| value)
                        .unwrap(),
                    set
                );
            }
        }
    }

    #[test]
    fn indefinite_ber_keeps_long_strings_primitive_and_only_wraps_constructed_tags() {
        use crate::{
            Asn1BitString, Asn1OctetString, Asn1Utf8String, Explicit, Implicit, LengthForm,
        };
        let options = EncodingOptions::Ber(LengthForm::Indefinite);
        let octets = Asn1OctetString::new(&vec![0xaa; 1001]);
        let bits = Asn1BitString::from_bytes(&vec![0xaa; 1001]);
        let text = Asn1Utf8String::new(&"a".repeat(1001));
        for value in [&octets as &dyn Encode, &bits, &text] {
            let wire = value.encode_to_vec(options).unwrap();
            assert_eq!(
                wire,
                value
                    .encode_to_vec(EncodingOptions::Ber(LengthForm::Definite))
                    .unwrap()
            );
            assert_eq!(wire.len(), value.encoded_len(options));
            assert_eq!(wire[0] & 0x20, 0);
        }
        let sequence = Asn1Object::Sequence(vec![Asn1Boolean::from(true).into()]);
        for (value, expected) in [
            (
                Explicit::new(&[0xa0], &sequence)
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0xa0, 0x80, 0x30, 0x80, 1, 1, 255, 0, 0, 0, 0],
            ),
            (
                Implicit::new(&[0xbf, 0x81, 0], &sequence)
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0xbf, 0x81, 0, 0x80, 1, 1, 255, 0, 0],
            ),
            (
                Implicit::new(&[0x80], &Asn1Boolean::from(true))
                    .encode_to_vec(options)
                    .unwrap(),
                vec![0x80, 1, 255],
            ),
        ] {
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn cer_constructed_values_use_indefinite_lengths_and_sorted_sets() {
        use crate::{Asn1Integer, Explicit};
        let sequence =
            Asn1Object::Sequence(vec![Asn1Integer::from(42_u8).into(), Asn1Object::Null]);
        let set = Asn1Object::Set(vec![
            Asn1Integer::from(5_u8).into(),
            Asn1Integer::from(3_u8).into(),
        ]);
        for (value, expected) in [
            (sequence, &[0x30, 0x80, 2, 1, 42, 5, 0, 0, 0][..]),
            (set, &[0x31, 0x80, 2, 1, 3, 2, 1, 5, 0, 0][..]),
        ] {
            assert_eq!(value.encoded_len(EncodingOptions::Cer), expected.len());
            assert_eq!(value.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
            assert_eq!(
                Asn1Object::try_decode(expected, DecodingOptions::default())
                    .map(|(_, value)| value)
                    .unwrap()
                    .encode_to_vec(EncodingOptions::Cer)
                    .unwrap(),
                expected
            );
            assert_eq!(
                value.encode(EncodingOptions::Cer, &mut vec![0; expected.len() - 1]),
                Err(Asn1Error::BufferTooSmall)
            );
            let mut out = vec![0xaa; expected.len() + 3];
            assert_eq!(
                value.encode(EncodingOptions::Cer, &mut out).unwrap(),
                expected.len()
            );
            assert_eq!(&out[expected.len()..], &[0xaa; 3]);
        }
        let integer = Asn1Integer::from(2_u8);
        assert_eq!(
            Explicit::new(&[0xa0], &integer)
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            [0xa0, 0x80, 2, 1, 2, 0, 0]
        );
    }

    #[test]
    fn cer_preserves_raw_unknown_encodings() {
        use crate::Asn1Any;
        let input = [0x1f, 0x25, 0x81, 0];
        assert_eq!(
            Asn1Any::try_decode(&input, DecodingOptions::default())
                .map(|(_, value)| value)
                .unwrap()
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            input
        );
        assert_eq!(
            Asn1Object::try_decode(&input, DecodingOptions::default())
                .map(|(_, value)| value)
                .unwrap()
                .encode_to_vec(EncodingOptions::Cer)
                .unwrap(),
            input
        );
    }

    #[test]
    fn vector_encoding_matches_manual_encoding_and_remains_available_through_trait_objects() {
        let value: &dyn Encode = &Asn1Boolean::from(true);
        assert_eq!(
            value.encode_to_vec(EncodingOptions::Der).unwrap(),
            [1, 1, 255]
        );
        let tree = Asn1Object::Sequence(vec![Asn1Object::Sequence(vec![
            Asn1Tagged::constructed(&[0x80], vec![Asn1Boolean::from(true).into()])
                .unwrap()
                .into(),
        ])]);
        for rules in [
            EncodingOptions::Der,
            EncodingOptions::Ber(crate::LengthForm::Definite),
        ] {
            let mut out = vec![0; tree.encoded_len(rules)];
            let written = tree.encode(rules, &mut out).unwrap();
            assert_eq!(written, out.len());
            assert_eq!(tree.encode_to_vec(rules).unwrap(), out);
        }
    }

    #[test]
    fn vector_encoding_preserves_unknown_headers_and_returns_sorting_errors() {
        let tree = Asn1Object::try_decode(&[0x1f, 0x25, 0x81, 0], DecodingOptions::default())
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(
            tree.encode_to_vec(EncodingOptions::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let value: &dyn Encode = &tree;
        assert_eq!(
            value.encode_to_vec(EncodingOptions::Der).unwrap(),
            [0x1f, 0x25, 0x81, 0]
        );
        let input = [
            0x1f, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0,
        ];
        let tree = Asn1Object::Set(vec![
            Asn1Object::try_decode(&input, DecodingOptions::default())
                .map(|(_, value)| value)
                .unwrap(),
        ]);
        assert_eq!(
            tree.encode_to_vec(EncodingOptions::Der),
            Err(Asn1Error::TagOverflow)
        );
        assert!(
            tree.encode_to_vec(EncodingOptions::Ber(crate::LengthForm::Definite))
                .is_ok()
        );
    }
}
