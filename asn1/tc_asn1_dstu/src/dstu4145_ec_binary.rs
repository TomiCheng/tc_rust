//! DSTU 4145 `ECBinary`, an explicit curve over a binary field.
//!
//! ```text
//! ECBinary ::= SEQUENCE {
//!     version [0] EXPLICIT INTEGER DEFAULT 0,
//!     f       BinaryField,
//!     a       INTEGER (0..1),
//!     b       OCTET STRING,
//!     n       INTEGER,
//!     bp      OCTET STRING }
//! ```
//!
//! A written default version is accepted under BER and rejected under DER;
//! encoding omits it.

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::Dstu4145BinaryField;

/// The field, the coefficients `a` and `b`, the order `n`, and the base point.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Dstu4145EcBinary {
    version: Option<Asn1Integer>,
    f: Dstu4145BinaryField,
    a: Asn1Integer,
    b: Asn1OctetString,
    n: Asn1Integer,
    bp: Asn1OctetString,
}

impl Dstu4145EcBinary {
    /// A version 0 curve.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        f: Dstu4145BinaryField,
        a: Asn1Integer,
        b: Asn1OctetString,
        n: Asn1Integer,
        bp: Asn1OctetString,
    ) -> Self {
        Self {
            version: None,
            f,
            a,
            b,
            n,
            bp,
        }
    }

    /// Sets the version.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = (version != Asn1Integer::from(0)).then_some(version);
        self
    }

    /// Returns the version, 0 when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version.clone().unwrap_or_else(|| 0.into())
    }

    /// Returns the field.
    /// Variable time: branches only on the encoding structure.
    pub fn f(&self) -> &Dstu4145BinaryField {
        &self.f
    }

    /// Returns the coefficient `a`, 0 or 1.
    /// Variable time: branches only on the encoding structure.
    pub fn a(&self) -> &Asn1Integer {
        &self.a
    }

    /// Returns the coefficient `b`.
    /// Variable time: branches only on the encoding structure.
    pub fn b(&self) -> &Asn1OctetString {
        &self.b
    }

    /// Returns the order of the base point.
    /// Variable time: branches only on the encoding structure.
    pub fn n(&self) -> &Asn1Integer {
        &self.n
    }

    /// Returns the compressed base point.
    /// Variable time: branches only on the encoding structure.
    pub fn bp(&self) -> &Asn1OctetString {
        &self.bp
    }
}

impl DecodeContent for Dstu4145EcBinary {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version = fields.get_explicit_opt::<Asn1Integer>([0xa0])?;
        if version == Some(Asn1Integer::from(0)) && fields.context().is_der() {
            return Err(Asn1Error::NotDer);
        }
        let version = version.filter(|version| *version != Asn1Integer::from(0));
        let f = fields.get()?;
        let a = fields.get()?;
        let b = fields.get()?;
        let n = fields.get()?;
        let bp = fields.get()?;
        fields.end()?;
        let value = Self {
            version,
            f,
            a,
            b,
            n,
            bp,
        };
        Ok(value)
    }
}

impl DecodeInner for Dstu4145EcBinary {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for Dstu4145EcBinary {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self.f.encoded_len(rules)
            + self.a.encoded_len(rules)
            + self.b.encoded_len(rules)
            + self.n.encoded_len(rules)
            + self.bp.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.version {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.f.encode(rules, &mut out[at..])?;
        at += self.a.encode(rules, &mut out[at..])?;
        at += self.b.encode(rules, &mut out[at..])?;
        at += self.n.encode(rules, &mut out[at..])?;
        at += self.bp.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for Dstu4145EcBinary {}

impl Tagged for Dstu4145EcBinary {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Dstu4145EcBinary {}

impl Encode for Dstu4145EcBinary {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
