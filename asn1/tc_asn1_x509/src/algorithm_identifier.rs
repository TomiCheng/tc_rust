use tc_asn1::{
    Asn1Error, Asn1Null, Asn1Object, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AlgorithmIdentifier {
    algorithm: Asn1Oid,
    parameters: Option<Asn1Object>,
}

impl AlgorithmIdentifier {
    pub fn new(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: None,
        }
    }

    pub fn with_null(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: Some(Asn1Null.into()),
        }
    }

    pub fn with_parameters(algorithm: Asn1Oid, parameters: impl Into<Asn1Object>) -> Self {
        Self {
            algorithm,
            parameters: Some(parameters.into()),
        }
    }

    pub fn algorithm(&self) -> &Asn1Oid {
        &self.algorithm
    }

    pub fn parameters(&self) -> Option<&Asn1Object> {
        self.parameters.as_ref()
    }
}

impl EncodeContent for AlgorithmIdentifier {
    /// The fields' TLVs back to back. Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.algorithm.encoded_len(rules)
            + self.parameters.as_ref().map_or(0, |p| p.encoded_len(rules))
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.algorithm.encode(rules, out)?;
        if let Some(parameters) = &self.parameters {
            at += parameters.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for AlgorithmIdentifier {}

impl Encode for AlgorithmIdentifier {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(tag::SEQUENCE, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(tag::SEQUENCE, rules, out)
    }
}

impl DecodeInner for AlgorithmIdentifier {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let algorithm: Asn1Oid = children.get()?;
        let parameters = children.get_any_opt()?;
        children.end()?;

        Ok((
            element.total_len(),
            Self {
                algorithm,
                parameters,
            },
        ))
    }
}

impl Decode for AlgorithmIdentifier {}
impl Tagged for AlgorithmIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}
