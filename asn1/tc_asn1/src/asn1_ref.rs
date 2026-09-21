use crate::decoding_context::DepthScope;
use crate::error::Asn1Error;
use crate::traits::DecodeInner;
use crate::traits::encode::len_octets;
use crate::{DecodeContent, DecodingContext, DecodingOptions, Tagged};

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

    pub fn assert_tag(self, tag: &[u8]) -> Result<Self, Asn1Error> {
        if self.tag != tag {
            Err(Asn1Error::UnexpectedTag)
        } else {
            Ok(self)
        }
    }
}

/// The elements of a constructed value, one level deeper in the context.
pub struct Children<'a, 'b> {
    cursor: ChildCursor<'a>,
    scope: DepthScope<'b>,
    /// An element read by `peek` and not yet handed out by `next`.
    lookahead: Option<Result<Asn1Ref<'a>, Asn1Error>>,
}

impl<'a, 'b> Children<'a, 'b> {
    pub(crate) fn new(rest: &'a [u8], scope: DepthScope<'b>) -> Self {
        Self {
            cursor: ChildCursor::new(rest, scope.options()),
            scope,
            lookahead: None,
        }
    }

    pub fn context(&mut self) -> &mut DecodingContext {
        self.scope.context()
    }

    pub fn peek(&mut self) -> Option<Result<Asn1Ref<'a>, Asn1Error>> {
        if self.lookahead.is_none() {
            self.lookahead = self.cursor.next(&mut self.scope);
        }
        self.lookahead
    }

    pub fn get<T: DecodeInner>(&mut self) -> Result<T, Asn1Error> {
        self.next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<T>(self.context())
    }

    pub fn get_opt<T: DecodeInner + Tagged>(&mut self) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == T::TAG => self.get().map(Some),
            _ => Ok(None),
        }
    }

    /// An OPTIONAL field with a DEFAULT: the value when present, `default`
    /// otherwise. Under DER a value equal to the default must not be written
    /// (X.690 §11.5), so one that is present is `NotDer`.
    /// Variable time: branches only on the encoding structure.
    pub fn get_default<T: DecodeInner + Tagged + PartialEq>(
        &mut self,
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_opt::<T>()? {
            Some(value) => {
                if value == default && self.context().is_der() {
                    return Err(Asn1Error::NotDer);
                }
                Ok(value)
            }
            None => Ok(default),
        }
    }

    pub fn get_any_opt<T: DecodeInner>(&mut self) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(_)) => self.get().map(Some),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// A `[n] EXPLICIT T OPTIONAL` field, `tag` being the wrapper's
    /// identifier octets (`[0xA0]` for `[0]`): the value inside when the
    /// next element carries that tag, `None` otherwise, leaving the element
    /// for the next field. The wrapper must hold exactly one element.
    /// Variable time: branches only on the encoding structure.
    pub fn get_explicit_opt<T: DecodeInner>(
        &mut self,
        tag: impl AsRef<[u8]>,
    ) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == tag.as_ref() => {
                self.next(); // the wrapper itself
                let mut inner = child.children(self.context())?;
                let value = inner.get::<T>()?;
                inner.end()?;
                Ok(Some(value))
            }
            _ => Ok(None),
        }
    }

    /// [`get_explicit_opt`](Self::get_explicit_opt) for a field with a
    /// DEFAULT: `default` when the wrapper is absent. Under DER a written
    /// value equal to the default is `NotDer` (X.690 §11.5).
    /// Variable time: branches only on the encoding structure.
    pub fn get_explicit_default<T: DecodeInner + PartialEq>(
        &mut self,
        tag: impl AsRef<[u8]>,
        default: T,
    ) -> Result<T, Asn1Error> {
        match self.get_explicit_opt::<T>(tag)? {
            Some(value) if value == default && self.context().is_der() => Err(Asn1Error::NotDer),
            Some(value) => Ok(value),
            None => Ok(default),
        }
    }

    /// A `[n] IMPLICIT T OPTIONAL` field, `tag` being the identifier octets
    /// that replace `T`'s own (`[0x81]` for `[1]` on a primitive type): the
    /// contents decoded as `T` when the next element carries that tag,
    /// `None` otherwise, leaving the element for the next field.
    /// Variable time: branches only on the encoding structure.
    pub fn get_implicit_opt<T: DecodeContent>(
        &mut self,
        tag: impl AsRef<[u8]>,
    ) -> Result<Option<T>, Asn1Error> {
        match self.peek() {
            Some(Ok(child)) if child.tag() == tag.as_ref() => {
                self.next();
                Ok(Some(T::decode_content(child.value(), self.context())?))
            }
            _ => Ok(None),
        }
    }

    pub fn end(mut self) -> Result<(), Asn1Error> {
        match self.next() {
            None => Ok(()),
            Some(Err(e)) => Err(e),
            Some(Ok(_)) => Err(Asn1Error::TrailingData),
        }
    }
}

impl<'a> Iterator for Children<'a, '_> {
    type Item = Result<Asn1Ref<'a>, Asn1Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.lookahead.take() {
            Some(item) => Some(item),
            None => self.cursor.next(&mut self.scope),
        }
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
