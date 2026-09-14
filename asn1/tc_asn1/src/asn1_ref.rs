//! Borrowed views of ASN.1 tag-length-value (TLV) encodings.
//!
//! [`Asn1Ref`] separates an element's identifier, contents, and closing
//! end-of-contents (EOC) marker without allocating or copying the input.
//! Parsing locates the element's boundaries; the caller's schema selects the
//! content type and validates its identifier before typed decoding.
//!
//! Definite-length contents are inspected lazily. Indefinite-length contents
//! must be traversed at TLV boundaries to find their closing EOC.

use crate::error::Asn1Error;
use crate::traits::{DecodeConstructed, DecodeInner};
use crate::{DecodingContext, DecodingOptions};

/// Tag class encoded by the two most significant bits of the first identifier octet.
///
/// The class is independent of the constructed bit and tag number.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Class, Asn1Ref, DecodingContext, DecodingOptions};
/// let options = DecodingOptions::default();
/// let mut context = DecodingContext::new(&options);
/// let element = Asn1Ref::parse(&[0xA0, 0], &mut context)?;
/// assert_eq!(element.class(), Asn1Class::ContextSpecific);
/// assert!(element.is_constructed());
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asn1Class {
    /// Types with universally assigned ASN.1 tag numbers.
    Universal,
    /// Tags assigned within an application.
    Application,
    /// Tags assigned within the surrounding ASN.1 schema.
    ContextSpecific,
    /// Tags assigned for private use.
    Private,
}

impl Asn1Class {
    pub(crate) fn of(first: u8) -> Self {
        match first >> 6 {
            0 => Self::Universal,
            1 => Self::Application,
            2 => Self::ContextSpecific,
            _ => Self::Private,
        }
    }
}

/// A borrowed view of the first complete TLV in an input slice.
///
/// All slices borrow the input for `'a`. [`raw`](Self::raw) includes the header
/// and any closing EOC; [`value`](Self::value) excludes both. Nested TLVs inside
/// the contents retain their own headers and EOCs. Copying a view copies only
/// its slice references and stored length.
///
/// This view describes encoding boundaries, not a fully validated ASN.1 value.
/// Use a schema-selected decoder to validate the contents.
///
/// # Examples
///
/// Walk a SEQUENCE and select each child's decoder using the type's tag constants.
/// The input array contains the raw wire encoding, including tags and lengths.
///
/// ```
/// use tc_asn1::{Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, DecodingContext, DecodingOptions};
///
/// fn main() -> Result<(), Asn1Error> {
///     let options = DecodingOptions::default();
///     let mut context = DecodingContext::new(&options);
///     let seq = Asn1Ref::parse(&[
///         0x30, 11,                // SEQUENCE
///         2, 1, 5,                 // INTEGER 5
///         0x24, 6,                 // Constructed OCTET STRING
///         4, 1, b'A', 4, 1, b'B', // Two segments
///     ], &mut context)?;
///
///     context.with_child(|context| {
///         let mut children = seq.children(context);
///         while let Some(child) = children.next() {
///             let child = child?;
///
///             match child.tag() {
///                 Asn1Integer::TAG => {
///                     let value = child.decode_as::<Asn1Integer>(children.context())?;
///                     println!("INTEGER: {}", i64::try_from(&value)?);
///                 }
///                 Asn1OctetString::TAG | Asn1OctetString::CONSTRUCTED_TAG => {
///                     let value = child
///                         .decode_constructed_as::<Asn1OctetString>(children.context())?;
///                     println!("OCTET STRING: {:?}", value.as_bytes());
///                 }
///                 _ => return Err(Asn1Error::UnexpectedTag),
///             }
///         }
///
///         Ok(())
///     })
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Asn1Ref<'a> {
    /// Total encoded length, including the header and any closing EOC.
    total_len: usize,
    /// Complete TLV, including the header and any closing EOC.
    raw: &'a [u8],
    /// Complete identifier octets, including any high-tag-number continuation octets.
    tag: &'a [u8],
    /// Contents without this element's closing EOC; nested TLVs remain complete.
    value: &'a [u8],
    /// Borrowed closing EOC, or an empty slice for a definite-length element.
    eoc: &'a [u8],
}

impl<'a> Asn1Ref<'a> {
    /// Restore boundaries previously obtained from a parsed element. Constant time.
    /// `raw` must contain exactly that element, with the identifier ending at
    /// `length_offset`, contents in `value_offset..eoc_offset`, and only the
    /// optional EOC after `eoc_offset`. The caller must preserve the validated offsets.
    pub(crate) fn from_validated_parts(
        raw: &'a [u8],
        length_offset: usize,
        value_offset: usize,
        eoc_offset: usize,
    ) -> Self {
        Self {
            raw,
            total_len: raw.len(),
            tag: &raw[..length_offset],
            value: &raw[value_offset..eoc_offset],
            eoc: &raw[eoc_offset..],
        }
    }

    /// Parse the first TLV with the supplied decoding limits.
    ///
    /// Bytes following the first element are left untouched. Use
    /// [`total_len`](Self::total_len) to locate the next element.
    /// Definite-length contents stay borrowed; their children are checked when
    /// traversed. Indefinite lengths require traversal to locate the closing EOC.
    /// Only constructed encodings may use indefinite lengths.
    ///
    /// Lengths must fit in `usize`, including the header and any closing EOC in
    /// the complete input slice. Content limits exclude this element's header
    /// and EOC. Recursive indefinite-length parsing consumes the depth budget
    /// and checks each traversed container's direct child count.
    ///
    /// Redundant length octets are accepted; this is not a DER validation entry.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Errors
    ///
    /// Returns [`Asn1Error::Truncated`] for incomplete input, including a missing
    /// EOC, [`Asn1Error::LengthOverflow`] for overflowing lengths, and
    /// [`Asn1Error::NonMinimalTag`] for a nonminimal identifier. Invalid length
    /// forms return [`Asn1Error::MalformedValue`]. Exceeded limits return
    /// [`Asn1Error::ContentLengthExceeded`], [`Asn1Error::ChildrenExceeded`], or
    /// [`Asn1Error::DepthExceeded`].
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Error, Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0x30, 0x80, 5, 0, 0, 0], &mut context)?;
    /// assert_eq!(element.value(), &[5, 0]);
    /// assert_eq!(element.eoc(), &[0, 0]);
    /// assert_eq!(
    ///     Asn1Ref::parse(&[0x30, 0x80, 5, 0], &mut context).err(),
    ///     Some(Asn1Error::Truncated),
    /// );
    /// # Ok::<(), Asn1Error>(())
    /// ```
    pub fn parse(buff: &'a [u8], context: &mut DecodingContext<'_>) -> Result<Self, Asn1Error> {
        let tag = parse_tag(buff)?;
        let (len_len, length) = parse_len(&buff[tag.len()..])?;
        let offset = tag.len() + len_len;

        match length {
            Some(n) => {
                let end = offset.checked_add(n).ok_or(Asn1Error::LengthOverflow)?;
                context.options().check_content_len(n)?;
                let value = buff.get(offset..end).ok_or(Asn1Error::Truncated)?;
                Ok(Self {
                    raw: &buff[..end],
                    total_len: end,
                    tag,
                    value,
                    eoc: &buff[end..end],
                })
            }
            None => {
                // Only constructed encodings may end with an EOC instead of a length.
                if tag[0] & 0x20 == 0 {
                    return Err(Asn1Error::MalformedValue);
                }
                context.with_child(|context| {
                    let mut at = offset;
                    let mut count = 0;
                    loop {
                        let rest = buff.get(at..).ok_or(Asn1Error::Truncated)?;
                        if rest.len() < 2 {
                            return Err(Asn1Error::Truncated);
                        }
                        if rest[..2] == [0x00, 0x00] {
                            break;
                        }
                        if count == context.options().max_children() {
                            return Err(Asn1Error::ChildrenExceeded);
                        }
                        at += Self::parse(rest, context)?.total_len(); // Skip the complete child TLV.
                        count += 1;
                        context.options().check_content_len(at - offset)?;
                    }
                    Ok(Self {
                        raw: &buff[..at + 2],
                        total_len: at + 2,
                        tag,
                        value: &buff[offset..at],
                        eoc: &buff[at..at + 2],
                    })
                })
            }
        }
    }
    /// Parse the first TLV with a definite, minimal DER header.
    /// This checks framing and known universal encoding forms, not schema contents.
    /// Variable time: public input only; no constant-time alternative is provided.
    pub fn parse_der(buff: &'a [u8], context: &mut DecodingContext<'_>) -> Result<Self, Asn1Error> {
        let tag = parse_tag(buff)?;
        crate::decoding::check_der_tag(tag)?;
        let (len_len, length) = parse_len(&buff[tag.len()..])?;
        if tag == [0]
            || length.is_none()
            || length.is_some_and(|n| len_len != crate::encoding::len_octets(n))
        {
            return Err(Asn1Error::NotDer);
        }
        Self::parse(buff, context)
    }

    /// Borrow the complete TLV, including the header and any closing EOC.
    /// Bytes following this element are excluded. Constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[5, 0, 2, 1, 7], &mut context)?;
    /// assert_eq!(element.raw(), &[5, 0]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Borrow the complete identifier, including its class and constructed bit.
    /// High tag numbers retain all continuation octets. Constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0x9F, 0x81, 0, 0], &mut context)?;
    /// assert_eq!(element.tag(), &[0x9F, 0x81, 0]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn tag(&self) -> &'a [u8] {
        self.tag
    }

    /// Return the identifier's class, independently of its constructed bit.
    /// Constant time: inspects the first identifier octet.
    /// See [`Asn1Class`] for an example.
    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.tag[0])
    }

    /// Return whether the identifier's constructed bit is set.
    /// This does not validate the contents as child TLVs. Constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// assert!(Asn1Ref::parse(&[0x30, 0], &mut context)?.is_constructed());
    /// assert!(!Asn1Ref::parse(&[5, 0], &mut context)?.is_constructed());
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn is_constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }

    /// Borrow the contents without this element's header or closing EOC.
    /// Nested elements retain their own headers and EOCs. Constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(
    ///     &[0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0], &mut context,
    /// )?;
    /// assert_eq!(element.value(), &[0x30, 0x80, 0, 0]);
    /// assert_eq!(element.eoc(), &[0, 0]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// Return the complete encoded length, including the header and any EOC.
    /// Constant time: reads the stored length.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let input = [2, 1, 5, 5, 0];
    /// let element = Asn1Ref::parse(&input, &mut context)?;
    /// assert_eq!(element.total_len(), element.raw().len());
    /// assert_eq!(&input[element.total_len()..], &[5, 0]);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// Borrow the closing EOC (`00 00`) of an indefinite-length element.
    /// Definite-length elements return an empty slice. Constant time.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    ///
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0x30, 0x80, 5, 0, 0, 0], &mut context)?;
    /// assert_eq!(element.value(), &[5, 0]);
    /// assert_eq!(element.eoc(), &[0, 0]);
    /// assert_eq!(element.total_len(), 6);
    /// let definite = Asn1Ref::parse(&[0x30, 2, 5, 0], &mut context)?;
    /// assert!(definite.eoc().is_empty());
    /// assert_eq!(definite.total_len(), 4);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn eoc(&self) -> &'a [u8] {
        self.eoc
    }

    /// Iterate over the direct child TLVs of a constructed element.
    /// Primitive elements return an empty iterator. The closing EOC is excluded.
    ///
    /// Enter the parent with [`DecodingContext::with_child`] before iterating.
    /// This method does not change depth. Decode yielded values through
    /// [`Children::context`] to retain the same active scope.
    /// Creating the iterator is constant time; advancing it is variable time
    /// on public input only, with no constant-time alternative.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0x30, 2, 5, 0], &mut context)?;
    /// let children = context.with_child(|context| {
    ///     element.children(context).collect::<Result<Vec<_>, _>>()
    /// })?;
    /// assert_eq!(children.len(), 1);
    /// assert_eq!(children[0].tag(), tc_asn1::Asn1Null::TAG);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn children<'c, 'o>(&self, options: &'c mut DecodingContext<'o>) -> Children<'a, 'c, 'o> {
        Children::new(
            if self.is_constructed() {
                self.value
            } else {
                &[]
            },
            options,
        )
    }

    /// Decode this complete element as the type selected by the caller's schema.
    /// The schema validates the identifier; this method requires full consumption
    /// of this element. Variable time: public values only; no constant-time alternative.
    /// Decoder errors are propagated; incomplete or excessive consumption returns
    /// [`Asn1Error::TrailingData`]. The decoder shares the caller's context.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1Integer, Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0x80, 1, 7], &mut context)?;
    /// assert_eq!(element.tag(), &[0x80]); // Schema: [0] IMPLICIT INTEGER.
    /// let integer = element.decode_as::<Asn1Integer>(&mut context)?;
    /// assert_eq!(i64::try_from(&integer)?, 7);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn decode_as<T: DecodeInner<'a>>(
        &self,
        context: &mut DecodingContext<'_>,
    ) -> Result<T, Asn1Error> {
        let (used, value) = T::decode_inner(self.raw, context)?;
        if used != self.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
    /// Decode the complete view using the selected type's DER decoder.
    /// Variable time: public input only; no constant-time alternative is provided.
    pub fn decode_as_der<T: DecodeInner<'a>>(
        &self,
        context: &mut DecodingContext<'_>,
    ) -> Result<T, Asn1Error> {
        let (used, value) = T::decode_inner_der(self.raw, context)?;
        if used != self.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }

    /// Decode primitive or constructed string contents as the schema-selected type.
    /// Uses [`DecodeConstructed::decode_constructed`] when the constructed bit
    /// is set, and [`crate::DecodeContent::decode_content`] otherwise.
    /// The caller validates the tag class and number.
    /// Returns [`Asn1Error::ContentLengthExceeded`] for oversized contents and propagates
    /// decoder errors. The decoder shares the caller's context and handles nesting.
    /// Variable time: public values only; no constant-time alternative is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// use tc_asn1::{Asn1OctetString, Asn1Ref, DecodingContext, DecodingOptions};
    /// let options = DecodingOptions::default();
    /// let mut context = DecodingContext::new(&options);
    /// let element = Asn1Ref::parse(&[0xA0, 6, 4, 1, b'A', 4, 1, b'B'], &mut context)?;
    /// assert_eq!(element.tag(), &[0xA0]); // Schema: [0] IMPLICIT OCTET STRING.
    /// let octets = element.decode_constructed_as::<Asn1OctetString>(&mut context)?;
    /// assert_eq!(octets.as_bytes(), b"AB");
    /// let primitive = Asn1Ref::parse(&[0x80, 2, b'A', b'B'], &mut context)?;
    /// assert_eq!(primitive.tag(), &[0x80]); // Same schema type, primitive form.
    /// assert_eq!(primitive.decode_constructed_as::<Asn1OctetString>(&mut context)?, octets);
    /// # Ok::<(), tc_asn1::Asn1Error>(())
    /// ```
    pub fn decode_constructed_as<T>(
        &self,
        context: &mut DecodingContext<'_>,
    ) -> Result<T, Asn1Error>
    where
        T: DecodeConstructed<'a>,
    {
        context.options().check_content_len(self.value.len())?;

        if self.is_constructed() {
            T::decode_constructed(self.value, context)
        } else {
            T::decode_content(self.value, context)
        }
    }
}

/// Match identifiers differing only by a newly set constructed bit.
/// Variable time on public identifiers; no constant-time alternative is provided.
pub(crate) fn is_constructed_form(tag: &[u8], primitive_tag: &[u8]) -> bool {
    !primitive_tag.is_empty()
        && tag.len() == primitive_tag.len()
        && primitive_tag[0] & 0x20 == 0
        && tag[0] == primitive_tag[0] | 0x20
        && tag[1..] == primitive_tag[1..]
}

/// A lazy iterator over adjacent child TLVs in a borrowed content slice.
///
/// Each item is a parsed view or an error. The first parse or limit error is
/// emitted once, after which iteration stops. Content-length and direct-child
/// limits are enforced during iteration; depth is passed to each child's parser.
/// Variable time on public encodings; no constant-time alternative is provided.
///
/// # Examples
///
/// ```
/// use tc_asn1::{Asn1Error, Children, DecodingContext, DecodingOptions};
/// let options = DecodingOptions::default();
/// let mut context = DecodingContext::new(&options);
/// let mut children = Children::new(&[5, 0, 2, 1], &mut context);
/// assert_eq!(children.next().unwrap()?.tag(), &[5]);
/// assert_eq!(children.next().unwrap().err(), Some(Asn1Error::Truncated));
/// assert!(children.next().is_none());
/// # Ok::<(), Asn1Error>(())
/// ```
pub struct Children<'a, 'c, 'o> {
    cursor: ChildCursor<'a>,
    context: &'c mut DecodingContext<'o>,
}

impl<'a, 'c, 'o> Children<'a, 'c, 'o> {
    /// Iterate over contents at the context's current depth. Constant time.
    /// The caller enters the parent's constructed scope before creating this iterator.
    pub fn new(rest: &'a [u8], context: &'c mut DecodingContext<'o>) -> Self {
        Self {
            cursor: ChildCursor::new(rest, context.options()),
            context,
        }
    }

    /// Borrow the active context to decode a yielded child without resetting depth.
    /// Constant time.
    pub fn context(&mut self) -> &mut DecodingContext<'o> {
        self.context
    }
}

impl<'a> Iterator for Children<'a, '_, '_> {
    type Item = Result<Asn1Ref<'a>, Asn1Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.cursor.next(self.context)
    }
}

pub(crate) struct ChildCursor<'a> {
    rest: &'a [u8],
    remaining: usize,
    oversized: bool,
}

impl<'a> ChildCursor<'a> {
    pub(crate) fn new(rest: &'a [u8], options: &DecodingOptions) -> Self {
        Self {
            rest,
            remaining: options.max_children(),
            oversized: rest.len() > options.max_content_len(),
        }
    }

    pub(crate) fn next(
        &mut self,
        context: &mut DecodingContext<'_>,
    ) -> Option<Result<Asn1Ref<'a>, Asn1Error>> {
        if self.rest.is_empty() {
            return None;
        }
        if self.oversized || self.remaining == 0 {
            self.rest = &[];
            return Some(Err(if self.oversized {
                Asn1Error::ContentLengthExceeded
            } else {
                Asn1Error::ChildrenExceeded
            }));
        }
        match Asn1Ref::parse(self.rest, context) {
            Ok(child) => {
                self.remaining -= 1;
                self.rest = &self.rest[child.total_len()..];
                Some(Ok(child))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

/// Borrow the identifier prefix without converting its tag number to an integer.
/// Variable time on public input; no constant-time alternative is provided.
pub(crate) fn parse_tag(buff: &[u8]) -> Result<&[u8], Asn1Error> {
    let first = *buff.first().ok_or(Asn1Error::Truncated)?;
    if first & 0x1F != 0x1F {
        return Ok(&buff[..1]);
    }

    // Each high-tag-number octet carries seven bits and a continuation bit.
    for (index, byte) in buff[1..].iter().enumerate() {
        if index == 0 && *byte == 0x80 {
            return Err(Asn1Error::NonMinimalTag); // Leading zero group.
        }
        if byte & 0x80 == 0 {
            if index == 0 && *byte <= 30 {
                return Err(Asn1Error::NonMinimalTag); // Numbers below 31 require short form.
            }
            return Ok(&buff[..index + 2]);
        }
    }
    Err(Asn1Error::Truncated)
}

/// Return the length field's size and its value, or `None` for indefinite length.
/// Variable time on public input; no constant-time alternative is provided.
fn parse_len(buff: &[u8]) -> Result<(usize, Option<usize>), Asn1Error> {
    let (first, rest) = buff.split_first().ok_or(Asn1Error::Truncated)?;
    match *first {
        0x00..=0x7F => Ok((1, Some(usize::from(*first)))),
        0x80 => Ok((1, None)),
        0xFF => Err(Asn1Error::MalformedValue), // Reserved by X.690.
        _ => {
            let count = usize::from(first & 0x7F);
            let octets = rest.get(..count).ok_or(Asn1Error::Truncated)?;
            let mut length: usize = 0;
            for byte in octets {
                // checked_shl would not detect discarded high bits.
                length = length
                    .checked_mul(256)
                    .and_then(|shifted| shifted.checked_add(usize::from(*byte)))
                    .ok_or(Asn1Error::LengthOverflow)?;
            }
            Ok((1 + count, Some(length)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT.get(), 16 * 1024 * 1024, 65_536);

    fn parse(bytes: &[u8]) -> Asn1Ref<'_> {
        Asn1Ref::parse(bytes, &mut DecodingContext::new(&OPTIONS)).unwrap()
    }

    // ---- parse_tag

    #[test]
    fn a_low_number_tag_is_one_byte_and_a_high_number_tag_keeps_all_of_its_bytes() {
        assert_eq!(parse_tag(&[0x05, 0x00]).unwrap(), &[0x05]);
        assert_eq!(parse_tag(&[0x1F, 0x1F]).unwrap(), &[0x1F, 0x1F]); // 31
        assert_eq!(
            parse_tag(&[0x1F, 0x81, 0x00, 0xAA]).unwrap(),
            &[0x1F, 0x81, 0x00]
        ); // 128
    }

    #[test]
    fn non_minimal_tag_encodings_are_rejected_even_under_ber() {
        assert_eq!(parse_tag(&[0x1F, 0x05]), Err(Asn1Error::NonMinimalTag)); // 5 用長式
        assert_eq!(
            parse_tag(&[0x1F, 0x80, 0x7F]),
            Err(Asn1Error::NonMinimalTag)
        ); // 前導零
    }

    #[test]
    fn a_truncated_tag_is_rejected() {
        assert_eq!(parse_tag(&[]), Err(Asn1Error::Truncated));
        assert_eq!(parse_tag(&[0x1F, 0x81]), Err(Asn1Error::Truncated));
    }

    // ---- parse_len

    #[test]
    fn short_long_and_indefinite_length_forms_are_told_apart() {
        assert_eq!(parse_len(&[0x05]).unwrap(), (1, Some(5)));
        assert_eq!(parse_len(&[0x7F]).unwrap(), (1, Some(127)));
        assert_eq!(parse_len(&[0x81, 0x80]).unwrap(), (2, Some(128)));
        assert_eq!(parse_len(&[0x82, 0x03, 0xE8]).unwrap(), (3, Some(1000)));
        assert_eq!(parse_len(&[0x80]).unwrap(), (1, None));
    }

    #[test]
    fn redundant_length_octets_are_accepted_because_decoding_is_lenient() {
        assert_eq!(parse_len(&[0x81, 0x05]).unwrap(), (2, Some(5)));
        assert_eq!(parse_len(&[0x82, 0x00, 0x05]).unwrap(), (3, Some(5)));
    }

    #[test]
    fn bad_length_octets_are_rejected() {
        assert_eq!(parse_len(&[]), Err(Asn1Error::Truncated));
        assert_eq!(parse_len(&[0x83, 0x01, 0x02]), Err(Asn1Error::Truncated));
        assert_eq!(parse_len(&[0xFF]), Err(Asn1Error::MalformedValue));

        let mut huge = [0xFF_u8; 17];
        huge[0] = 0x90; // 16 個長度位元組
        assert_eq!(parse_len(&huge), Err(Asn1Error::LengthOverflow));
    }

    // ---- Asn1Ref::parse，定長

    #[test]
    fn a_definite_length_tlv_yields_its_value_and_its_total_size() {
        let element = parse(&[0x02, 0x01, 0x05, 0xAA]); // INTEGER 5，後面還有東西

        assert_eq!(element.tag(), &[0x02]);
        assert_eq!(element.value(), &[0x05]);
        assert_eq!(element.total_len(), 3, "不含後面的 0xAA");
    }

    #[test]
    fn raw_is_the_whole_tlv_and_value_sits_inside_it() {
        let element = parse(&[0x02, 0x01, 0x05, 0xAA]);
        assert_eq!(element.raw(), &[0x02, 0x01, 0x05]);

        // 不定長：raw 含 EOC，value 不含
        let element = parse(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0xAA]);
        assert_eq!(element.raw(), &[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(element.value(), &[0x05, 0x00]);
    }

    #[test]
    fn a_length_promising_more_than_the_input_holds_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(
                &[0x04, 0x05, 0x01, 0x02],
                &mut DecodingContext::new(&OPTIONS)
            )
            .err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn a_length_that_overflows_when_added_to_the_header_is_rejected() {
        // 長度剛好 usize::MAX，加上表頭就溢位。
        let mut input = [0xFF_u8; 10];
        input[0] = 0x04;
        input[1] = 0x88; // 8 個長度位元組
        assert_eq!(
            Asn1Ref::parse(&input, &mut DecodingContext::new(&OPTIONS)).err(),
            Some(Asn1Error::LengthOverflow)
        );
    }

    // ---- Asn1Ref::parse，不定長

    #[test]
    fn an_indefinite_length_value_stops_at_the_end_of_contents_marker() {
        // 30 80  05 00  00 00  02 01 05
        let input = [0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x02, 0x01, 0x05];
        let element = parse(&input);

        assert_eq!(element.value(), &[0x05, 0x00], "不含 EOC");
        assert_eq!(element.total_len(), 6, "含 EOC，不含後面的 sibling");
        assert_eq!(&input[element.total_len()..], &[0x02, 0x01, 0x05]);
    }

    #[test]
    fn the_end_of_contents_marker_is_only_recognised_at_a_tlv_boundary() {
        // 31 80  31 03 01 01 00  00 00
        //                    ^^^^^ 相鄰的兩個 00 跨在成員內容與 EOC 之間。
        //                          掃描 00 00 會在這裡誤命中，照邊界走才會落在正確的位置。
        let input = [0x31, 0x80, 0x31, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(&input[6..8], &[0x00, 0x00], "誤命中的位置確實存在");

        let element = parse(&input);
        assert_eq!(element.total_len(), input.len());
        assert_eq!(
            element.value(),
            &[0x31, 0x03, 0x01, 0x01, 0x00],
            "內部的 SET 沒有被腰斬"
        );
    }

    #[test]
    fn nested_indefinite_lengths_each_find_their_own_marker() {
        // 30 80  30 80  05 00  00 00  00 00
        let input = [0x30, 0x80, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let outer = parse(&input);

        assert_eq!(outer.total_len(), input.len());
        assert_eq!(outer.value(), &[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn an_indefinite_length_without_its_marker_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(
                &[0x30, 0x80, 0x05, 0x00],
                &mut DecodingContext::new(&OPTIONS)
            )
            .err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn an_indefinite_length_on_a_primitive_tag_is_rejected() {
        assert_eq!(
            Asn1Ref::parse(
                &[0x04, 0x80, 0x00, 0x00],
                &mut DecodingContext::new(&OPTIONS)
            )
            .err(),
            Some(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn indefinite_nesting_deeper_than_the_budget_is_rejected() {
        // 八層 30 80，中間一個 05 00，然後八個 00 00。只有不定長會在 parse 裡遞迴。
        let levels = 8;
        let mut bytes = [0_u8; 64];
        let mut at = 0;
        for _ in 0..levels {
            bytes[at] = 0x30;
            bytes[at + 1] = 0x80;
            at += 2;
        }
        bytes[at] = 0x05;
        at += 2 + 2 * levels; // 05 00，然後 EOC 都是零
        let input = &bytes[..at];

        assert!(
            Asn1Ref::parse(
                input,
                &mut DecodingContext::new(&DecodingOptions::new(16, 16 * 1024 * 1024, 65_536))
            )
            .is_ok()
        );
        assert_eq!(
            Asn1Ref::parse(
                input,
                &mut DecodingContext::new(&DecodingOptions::new(4, 16 * 1024 * 1024, 65_536))
            )
            .err(),
            Some(Asn1Error::DepthExceeded)
        );
    }

    // ---- accessors

    #[test]
    fn string_decoding_accepts_primitive_and_single_segment_constructed_forms() {
        for wire in [
            &[0x80, 2, b'A', b'B'][..],
            &[0xa0, 4, 4, 2, b'A', b'B'],
            &[0xa0, 0x80, 4, 2, b'A', b'B', 0, 0],
        ] {
            let element = parse(wire);
            assert_eq!(
                element.decode_constructed_as::<crate::Asn1OctetString>(&mut DecodingContext::new(
                    &OPTIONS
                )),
                Ok(crate::Asn1OctetString::new(b"AB"))
            );
            let limited = DecodingOptions::new(crate::Depth::DEFAULT.get(), 1, 1);
            assert_eq!(
                element.decode_constructed_as::<crate::Asn1OctetString>(&mut DecodingContext::new(
                    &limited
                )),
                Err(Asn1Error::ContentLengthExceeded)
            );
        }
    }

    #[test]
    fn string_decoding_preserves_content_validation_and_constructed_depth_checks() {
        let zero_depth = DecodingOptions::new(0, 16, 1);
        assert!(
            parse(&[0x80, 1, b'A'])
                .decode_constructed_as::<crate::Asn1OctetString>(&mut DecodingContext::new(
                    &zero_depth
                ))
                .is_ok()
        );
        assert_eq!(
            parse(&[0xa0, 3, 4, 1, b'A']).decode_constructed_as::<crate::Asn1OctetString>(
                &mut DecodingContext::new(&zero_depth)
            ),
            Err(Asn1Error::DepthExceeded)
        );
        assert_eq!(
            parse(&[0x80, 1, 8])
                .decode_constructed_as::<crate::Asn1BitString>(&mut DecodingContext::new(&OPTIONS)),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            parse(&[0xa0, 3, 2, 1, 5]).decode_constructed_as::<crate::Asn1OctetString>(
                &mut DecodingContext::new(&OPTIONS)
            ),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn class_and_constructed_come_from_the_identifier_byte() {
        assert_eq!(parse(&[0x05, 0x00]).class(), Asn1Class::Universal);
        assert_eq!(parse(&[0x45, 0x00]).class(), Asn1Class::Application);
        assert_eq!(parse(&[0x85, 0x00]).class(), Asn1Class::ContextSpecific);
        assert_eq!(parse(&[0xC5, 0x00]).class(), Asn1Class::Private);

        assert!(!parse(&[0x05, 0x00]).is_constructed());
        assert!(parse(&[0x30, 0x00]).is_constructed());
        assert!(parse(&[0xA0, 0x00]).is_constructed());
        assert!(
            parse(&[0x30, 0x00]).class() == Asn1Class::Universal,
            "建構位不影響類別"
        );
    }

    // ---- children

    #[test]
    fn children_walk_a_constructed_value_exactly_once_each() {
        // 30 06  05 00  02 01 05
        let seq = parse(&[0x30, 0x05, 0x05, 0x00, 0x02, 0x01, 0x05]);
        let mut tags = [0_u8; 4];
        let mut count = 0;

        for child in seq.children(&mut DecodingContext::new(&OPTIONS)) {
            tags[count] = child.unwrap().tag()[0];
            count += 1;
        }

        assert_eq!(count, 2);
        assert_eq!(&tags[..2], &[0x05, 0x02]);
    }

    #[test]
    fn a_primitive_has_no_children() {
        assert_eq!(
            parse(&[0x02, 0x01, 0x05])
                .children(&mut DecodingContext::new(&OPTIONS))
                .count(),
            0
        );
    }

    #[test]
    fn a_broken_child_is_reported_once_and_then_iteration_stops() {
        // 30 04  05 00  02 05     ← 第二個子元素說有 5 個位元組，沒有
        let seq = parse(&[0x30, 0x04, 0x05, 0x00, 0x02, 0x05]);
        let mut context_12 = DecodingContext::new(&OPTIONS);
        let mut children = seq.children(&mut context_12);

        assert!(children.next().unwrap().is_ok());
        assert_eq!(children.next().unwrap().err(), Some(Asn1Error::Truncated));
        assert!(children.next().is_none(), "出錯之後不再產生任何東西");
    }

    #[test]
    fn children_of_an_indefinite_length_value_do_not_include_the_marker() {
        let seq = parse(&[0x30, 0x80, 0x05, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(seq.children(&mut DecodingContext::new(&OPTIONS)).count(), 2);
    }

    #[test]
    fn closing_markers_are_borrowed_separately_and_nested_encodings_remain_complete() {
        for wire in [
            &[0x30, 0x80, 0, 0, 5, 0][..],
            &[0x30, 0x80, 0x30, 0x80, 0, 0, 0, 0, 5, 0],
            &[0x30, 4, 0x30, 0x80, 0, 0, 5, 0],
        ] {
            let outer = parse(wire);
            assert_eq!(outer.raw(), &wire[..wire.len() - 2]);
            assert_eq!(outer.total_len(), wire.len() - 2);
            assert_eq!(outer.eoc(), if wire[1] == 0x80 { &[0, 0][..] } else { &[] });
            assert_eq!(
                outer.eoc().as_ptr(),
                wire[outer.total_len() - outer.eoc().len()..].as_ptr()
            );
            if !outer.value().is_empty() {
                assert_eq!(outer.value(), &[0x30, 0x80, 0, 0]);
                let inner = outer
                    .children(&mut DecodingContext::new(&OPTIONS))
                    .next()
                    .unwrap()
                    .unwrap();
                assert!(inner.value().is_empty());
                assert_eq!(inner.eoc(), &[0, 0]);
                assert_eq!(inner.total_len(), 4);
            }
            let owned = crate::Asn1Any::from(&outer);
            let restored = owned.as_ref();
            assert_eq!(restored.raw(), outer.raw());
            assert_eq!(restored.value(), outer.value());
            assert_eq!(restored.eoc(), outer.eoc());
            assert_eq!(restored.total_len(), outer.total_len());
            assert_eq!(
                restored.eoc().as_ptr(),
                owned.raw()[restored.total_len() - restored.eoc().len()..].as_ptr()
            );
        }
    }
    #[test]
    fn constructed_form_matching_changes_only_the_constructed_bit_of_a_complete_identifier() {
        assert!(is_constructed_form(&[0x24], &[4]));
        assert!(is_constructed_form(&[0xbf, 0x81, 0], &[0x9f, 0x81, 0]));
        for (tag, primitive) in [
            (&[][..], &[][..]),
            (&[0x24][..], &[][..]),
            (&[][..], &[4][..]),
            (&[0x24][..], &[0x24][..]),
            (&[4][..], &[4][..]),
            (&[0x64][..], &[4][..]),
            (&[0x24, 0][..], &[4][..]),
            (&[0xbf, 0x81, 1][..], &[0x9f, 0x81, 0][..]),
        ] {
            assert!(!is_constructed_form(tag, primitive));
        }
    }
}
