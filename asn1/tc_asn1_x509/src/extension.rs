use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1OctetString, Asn1Oid, Asn1Ref, Decode, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, tag,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extension {
    extn_id: Asn1Oid,
    critical: Asn1Boolean,
    extn_value: Asn1OctetString,
}

impl Extension {
    pub fn new(extn_id: Asn1Oid, critical: bool, extn_value: &[u8]) -> Self {
        Self {
            extn_id,
            critical: critical.into(),
            extn_value: Asn1OctetString::new(extn_value),
        }
    }

    pub fn extn_id(&self) -> &Asn1Oid {
        &self.extn_id
    }

    pub fn critical(&self) -> bool {
        self.critical.is_true()
    }

    pub fn extn_value(&self) -> &[u8] {
        self.extn_value.as_bytes()
    }

    /// Decodes `extnValue` as `T`. RFC 5280 §4.1 requires the inner value to be
    /// DER, so the DER decoder is used and the value must fill the octets exactly.
    /// Variable time: branches only on the encoding structure.
    pub fn extn_value_as<T: DecodeInner>(
        &self,
        context: &mut DecodingContext,
    ) -> Result<T, Asn1Error> {
        let bytes = self.extn_value.as_bytes();
        let mut der = context.enter_der();
        let (used, value) = T::decode_inner(bytes, der.context())?;
        if used != bytes.len() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(value)
    }
}

impl DecodeInner for Extension {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // let element = Asn1Ref::parse_der(buff, context)?.assert_tag(tag::SEQUENCE)?;
        // let mut children = element.children(context)?;
        // let extn_id = children.get_oid()?;
        // let critical = children.get_bool_opt()?;
        // let extn_value = children.get_octet()?;
        // children.end()?;

        let element = Asn1Ref::parse(buff, context)?;
        if element.tag() != tag::SEQUENCE {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut children = element.children(context)?;
        let extn_id = children
            .next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<Asn1Oid>(children.context())?;

        let mut r = children.next().ok_or(Asn1Error::Truncated)??;

        let critical = if r.tag() == tag::BOOLEAN {
            let flag = r.decode_as::<Asn1Boolean>(children.context())?;
            // X.690 §11.5: DER never writes a DEFAULT value.
            if flag.is_false() && children.context().is_der() {
                return Err(Asn1Error::NotDer);
            }
            r = children.next().ok_or(Asn1Error::Truncated)??;
            flag
        } else {
            false.into()
        };

        let extn_value = r.decode_as::<Asn1OctetString>(children.context())?;
        if children.next().is_some() {
            return Err(Asn1Error::TrailingData);
        }

        Ok((
            element.total_len(),
            Self {
                extn_id,
                critical,
                extn_value,
            },
        ))
    }
}

impl Decode for Extension {}

impl EncodeContent for Extension {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = self.extn_id.encoded_len(rules);
        len += if self.critical.is_true() {
            self.critical.encoded_len(rules)
        } else {
            0
        };
        len += self.extn_value.encoded_len(rules);
        len
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.extn_id.encode(rules, out)?;
        if self.critical.is_true() {
            at += self.critical.encode(rules, &mut out[at..])?;
        }
        at += self.extn_value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl EncodeTagged for Extension {}

impl Encode for Extension {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(tag::SEQUENCE, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(tag::SEQUENCE, rules, out)
    }
}
