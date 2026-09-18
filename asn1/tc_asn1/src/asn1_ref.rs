use crate::decoding_context::DepthScope;
use crate::error::Asn1Error;
use crate::traits::DecodeInner;
use crate::traits::encode::len_octets;
use crate::{DecodingContext, DecodingOptions};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Asn1Class {
    Universal,
    Application,
    ContextSpecific,
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

#[derive(Clone, Copy, Debug)]
pub struct Asn1Ref<'a> {
    raw: &'a [u8],
    tag: &'a [u8],
    value: &'a [u8],
    eoc: &'a [u8],
}

impl<'a> Asn1Ref<'a> {
    pub(crate) fn from_validated_parts(
        raw: &'a [u8],
        length_offset: usize,
        value_offset: usize,
        eoc_offset: usize,
    ) -> Self {
        Self {
            raw,
            tag: &raw[..length_offset],
            value: &raw[value_offset..eoc_offset],
            eoc: &raw[eoc_offset..],
        }
    }

    /// Reads one TLV. With `context.is_der()` the identifier must be in DER
    /// form, the length definite and shortest (X.690 §10.1, §10.2).
    /// Variable time: branches only on the encoding structure.
    pub fn parse(buff: &'a [u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let tag = parse_tag(buff)?;
        let (len_len, length) = parse_len(&buff[tag.len()..])?;
        if context.is_der() {
            crate::decoding::check_der_tag(tag)?;
            if tag == [0] || length.is_none() || length.is_some_and(|n| len_len != len_octets(n)) {
                return Err(Asn1Error::NotDer);
            }
        }
        let offset = tag.len() + len_len;

        match length {
            Some(n) => {
                let end = offset.checked_add(n).ok_or(Asn1Error::LengthOverflow)?;
                context.options().check_content_len(n)?;
                let value = buff.get(offset..end).ok_or(Asn1Error::Truncated)?;
                Ok(Self {
                    raw: &buff[..end],
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

                let mut scope = context.enter()?;
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
                    if count == scope.options().max_children() {
                        return Err(Asn1Error::ChildrenExceeded);
                    }
                    at += Self::parse(rest, scope.context())?.total_len(); // Skip the complete child TLV.
                    count += 1;
                    scope.options().check_content_len(at - offset)?;
                }
                Ok(Self {
                    raw: &buff[..at + 2],
                    tag,
                    value: &buff[offset..at],
                    eoc: &buff[at..at + 2],
                })
            }
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    pub fn tag(&self) -> &'a [u8] {
        self.tag
    }

    pub fn class(&self) -> Asn1Class {
        Asn1Class::of(self.tag[0])
    }

    pub fn is_constructed(&self) -> bool {
        self.tag[0] & 0x20 != 0
    }

    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    pub fn total_len(&self) -> usize {
        self.raw().len()
    }

    pub fn eoc(&self) -> &'a [u8] {
        self.eoc
    }

    pub fn children<'b>(
        &self,
        context: &'b mut DecodingContext,
    ) -> Result<Children<'a, 'b>, Asn1Error> {
        let scope = context.enter()?;
        Ok(Children::new(
            if self.is_constructed() {
                self.value
            } else {
                &[]
            },
            scope,
        ))
    }

    pub fn decode_as<T: DecodeInner>(&self, context: &mut DecodingContext) -> Result<T, Asn1Error> {
        let (used, value) = T::decode_inner(self.raw, context)?;
        if used != self.total_len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
}

pub(crate) fn is_constructed_form(tag: &[u8], primitive_tag: &[u8]) -> bool {
    !primitive_tag.is_empty()
        && tag.len() == primitive_tag.len()
        && primitive_tag[0] & 0x20 == 0
        && tag[0] == primitive_tag[0] | 0x20
        && tag[1..] == primitive_tag[1..]
}

pub struct Children<'a, 'b> {
    cursor: ChildCursor<'a>,
    scope: DepthScope<'b>,
}

impl<'a, 'b> Children<'a, 'b> {
    pub fn new(rest: &'a [u8], scope: DepthScope<'b>) -> Self {
        Self {
            cursor: ChildCursor::new(rest, scope.options()),
            scope,
        }
    }

    pub fn context(&mut self) -> &mut DecodingContext {
        self.scope.context()
    }
}
impl<'a> Iterator for Children<'a, '_> {
    type Item = Result<Asn1Ref<'a>, Asn1Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.cursor.next(&mut self.scope)
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
        scope: &mut DepthScope,
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
        match Asn1Ref::parse(self.rest, scope.context()) {
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
