//! Decoding contracts for schema-selected types.

use crate::{Asn1Error, DecodingContext, DecodingOptions};

/// Decode contents without an outer identifier or length field.
/// The caller's schema selects the type and validates the outer tag.
/// For segmented strings, use [`DecodeConstructed`] instead.
pub trait DecodeContent<'a>: Sized {
    /// Decode and validate all content bytes, borrowing from them if needed.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error>;

    /// Decode contents subject to DER's type-specific restrictions.
    /// Nested ASN.1 elements must also satisfy DER. The caller checks the omitted
    /// outer header. Schema-specific constraints, including named BIT STRING
    /// semantics, remain the schema's responsibility.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Asn1Error, DecodeContent, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// assert!(Asn1Boolean::decode_content(&[1], &mut context)?.is_true());
    /// assert_eq!(Asn1Boolean::decode_content_der(&[1], &mut context), Err(Asn1Error::NotDer));
    /// assert!(Asn1Boolean::decode_content_der(&[0xff], &mut context)?.is_true());
    /// # Ok::<(), Asn1Error>(())
    /// ```
    fn decode_content_der(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error>;
}

/// Decode the contents of a BER constructed string, without its outer header.
/// Implemented only by types supporting segmented string encodings.
/// Implementors must also support unsegmented contents through [`DecodeContent`].
pub trait DecodeConstructed<'a>: DecodeContent<'a> {
    /// Decode and join component TLVs, including nested constructed components.
    /// Component identifiers must follow the string type's encoding rules.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn decode_constructed(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error>;
}

/// Decode a complete TLV using an existing context without resetting depth.
/// The input and configuration lifetimes are independent. The schema validates
/// the tag class and number; concrete decoders validate their form and contents.
pub trait DecodeInner<'a>: Sized {
    /// Decode the first element using the general decoding rules.
    /// Trailing bytes remain with the caller. Variable time: public values only;
    /// no constant-time alternative is provided.
    fn decode_inner(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error>;

    /// Require DER for the first element's header, contents, and nested elements.
    /// Explicitly call DER decoders for every nested ASN.1 element.
    /// Open types can validate only what their schema reveals; a concrete type
    /// is needed to validate IMPLICIT contents fully.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<(usize, Self), Asn1Error>;
}

/// Decode one complete TLV as the type selected by the caller's schema.
///
/// Implementations select the appropriate content decoder from the encoded form.
/// The schema checks the tag class and number; concrete value decoders can thus
/// accept IMPLICIT tags. Dynamic types such as [`crate::Asn1Object`] inspect tags
/// to select their variants. Implementing [`DecodeContent`] does not implement
/// this trait automatically.
/// Implementations borrow options to create a fresh context, then select their
/// general or DER inner decoder. No blanket implementation is provided.
pub trait Decode<'a>: Sized {
    /// Return the consumed byte count and decoded value. Bytes following the first
    /// TLV belong to the caller. Contents inside that TLV must be fully validated.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Decode, DecodingOptions};
    /// // The schema selected [0] IMPLICIT BOOLEAN. The last byte is a sibling.
    /// let (used, value) = Asn1Boolean::decode(&[0x80, 1, 0xff, 0], &DecodingOptions::default())?;
    /// assert_eq!(used, 3);
    /// assert!(value.is_true());
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn decode(buff: &'a [u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error>;
}
