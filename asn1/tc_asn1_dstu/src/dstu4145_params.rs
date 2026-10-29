//! DSTU 4145 public key parameters.
//!
//! ```text
//! DSTU4145Params ::= SEQUENCE {
//!     definition CHOICE {
//!         ecbinary   ECBinary,
//!         namedCurve OBJECT IDENTIFIER },
//!     dke OCTET STRING OPTIONAL }
//! ```
//!
//! An absent `dke` means [`Dstu4145Params::DEFAULT_DKE`]. Bouncy Castle drops a
//! written default `dke` when it re-encodes; this type keeps what it read.

use tc_asn1::{
    Asn1Error, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::Dstu4145Curve;

/// The curve and the S-box of the GOST 28147-89 hash used with it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Dstu4145Params {
    curve: Dstu4145Curve,
    dke: Option<Asn1OctetString>,
}

impl Dstu4145Params {
    /// The S-box an absent `dke` stands for.
    pub const DEFAULT_DKE: [u8; 64] = [
        0xa9, 0xd6, 0xeb, 0x45, 0xf1, 0x3c, 0x70, 0x82, 0x80, 0xc4, 0x96, 0x7b, 0x23, 0x1f, 0x5e,
        0xad, 0xf6, 0x58, 0xeb, 0xa4, 0xc0, 0x37, 0x29, 0x1d, 0x38, 0xd9, 0x6b, 0xf0, 0x25, 0xca,
        0x4e, 0x17, 0xf8, 0xe9, 0x72, 0x0d, 0xc6, 0x15, 0xb4, 0x3a, 0x28, 0x97, 0x5f, 0x0b, 0xc1,
        0xde, 0xa3, 0x64, 0x38, 0xb5, 0x64, 0xea, 0x2c, 0x17, 0x9f, 0xd0, 0x12, 0x3e, 0x6d, 0xb8,
        0xfa, 0xc5, 0x79, 0x04,
    ];

    /// The curve, with the default S-box.
    /// Variable time: branches only on the encoding structure.
    pub fn new(curve: Dstu4145Curve) -> Self {
        Self { curve, dke: None }
    }

    /// Sets the S-box; other than 64 octets is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn with_dke(mut self, dke: Asn1OctetString) -> Result<Self, Asn1Error> {
        self.dke = Some(dke_of_64(dke)?);
        Ok(self)
    }

    /// Returns the curve.
    /// Variable time: branches only on the encoding structure.
    pub fn curve(&self) -> &Dstu4145Curve {
        &self.curve
    }

    /// Returns the S-box as written, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn dke(&self) -> Option<&Asn1OctetString> {
        self.dke.as_ref()
    }
}

/// `MalformedValue` unless the S-box is 64 octets.
fn dke_of_64(dke: Asn1OctetString) -> Result<Asn1OctetString, Asn1Error> {
    if dke.as_bytes().len() == Dstu4145Params::DEFAULT_DKE.len() {
        Ok(dke)
    } else {
        Err(Asn1Error::MalformedValue)
    }
}

impl DecodeContent for Dstu4145Params {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let curve = fields.get()?;
        let dke = fields.get_opt()?.map(dke_of_64).transpose()?;
        fields.end()?;
        let value = Self { curve, dke };
        Ok(value)
    }
}

impl DecodeInner for Dstu4145Params {
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

impl EncodeContent for Dstu4145Params {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.curve.encoded_len(rules) + self.dke.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.curve.encode(rules, out)?;
        if let Some(v) = &self.dke {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Dstu4145Params {}

impl Tagged for Dstu4145Params {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Dstu4145Params {}

impl Encode for Dstu4145Params {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
