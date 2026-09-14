//! Decoding contracts for schema-selected types.

use crate::{Asn1Error, DecodingOptions};

/// Decode contents without an outer identifier or length field.
/// The caller's schema selects the type and validates the outer tag.
/// For segmented strings, use [`DecodeConstructed`] instead.
pub trait DecodeContent<'a>: Sized {
    /// Decode and validate all content bytes, borrowing from them if needed.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error>;
}

/// Decode the contents of a BER constructed string, without its outer header.
/// Implemented only by types supporting segmented string encodings.
/// Implementors must also support unsegmented contents through [`DecodeContent`].
pub trait DecodeConstructed<'a>: DecodeContent<'a> {
    /// Decode and join component TLVs, including nested constructed components.
    /// Component identifiers must follow the string type's encoding rules.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn decode_constructed(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error>;
}

/// Decode one complete TLV as the type selected by the caller's schema.
///
/// Implementations select the appropriate content decoder from the encoded form.
/// The schema checks the tag class and number; concrete value decoders can thus
/// accept IMPLICIT tags. Dynamic types such as [`crate::Asn1Object`] inspect tags
/// to select their variants. Implementing [`DecodeContent`] does not implement
/// this trait automatically.
pub trait Decode<'a>: Sized {
    /// Return the consumed byte count and decoded value. Bytes following the first
    /// TLV belong to the caller. Contents inside that TLV must be fully validated.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Examples
    /// ```
    /// use tc_asn1::{Asn1Boolean, Decode, DecodingOptions};
    /// // The schema selected [0] IMPLICIT BOOLEAN. The last byte is a sibling.
    /// let (used, value) = Asn1Boolean::decode(&[0x80, 1, 0xff, 0], DecodingOptions::default())?;
    /// assert_eq!(used, 3);
    /// assert!(value.is_true());
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    fn decode(buff: &'a [u8], options: DecodingOptions) -> Result<(usize, Self), Asn1Error>;
}
