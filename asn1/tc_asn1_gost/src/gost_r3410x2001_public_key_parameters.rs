//! RFC 4491 §2.3.2 `GostR3410-2001-PublicKeyParameters`.
//!
//! ```text
//! GostR3410-2001-PublicKeyParameters ::= SEQUENCE {
//!     publicKeyParamSet  OBJECT IDENTIFIER,
//!     digestParamSet     OBJECT IDENTIFIER,
//!     encryptionParamSet OBJECT IDENTIFIER DEFAULT id-Gost28147-89-CryptoPro-A-ParamSet }
//! ```
//!
//! A written default is accepted under BER and rejected under DER; encoding
//! omits it.

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CryptoProId;

/// The curve, the hash, and the S-box parameter set of a GOST R 34.10-2001 key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GostR3410x2001PublicKeyParameters {
    public_key_param_set: Asn1Oid,
    digest_param_set: Asn1Oid,
    encryption_param_set: Asn1Oid,
}

impl GostR3410x2001PublicKeyParameters {
    /// The curve and hash, with the default S-box parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn new(public_key_param_set: Asn1Oid, digest_param_set: Asn1Oid) -> Self {
        Self {
            public_key_param_set,
            digest_param_set,
            encryption_param_set: CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.oid(),
        }
    }

    /// Sets the S-box parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn with_encryption_param_set(mut self, encryption_param_set: Asn1Oid) -> Self {
        self.encryption_param_set = encryption_param_set;
        self
    }

    /// Returns the curve.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key_param_set(&self) -> &Asn1Oid {
        &self.public_key_param_set
    }

    /// Returns the hash parameter set.
    /// Variable time: branches only on the encoding structure.
    pub fn digest_param_set(&self) -> &Asn1Oid {
        &self.digest_param_set
    }

    /// Returns the S-box parameter set, CryptoPro-A when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn encryption_param_set(&self) -> &Asn1Oid {
        &self.encryption_param_set
    }
}

impl DecodeContent for GostR3410x2001PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let public_key_param_set = fields.get()?;
        let digest_param_set = fields.get()?;
        let encryption_param_set =
            fields.get_default(CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.oid())?;
        fields.end()?;
        let value = Self {
            public_key_param_set,
            digest_param_set,
            encryption_param_set,
        };
        Ok(value)
    }
}

impl DecodeInner for GostR3410x2001PublicKeyParameters {
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

impl EncodeContent for GostR3410x2001PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.public_key_param_set.encoded_len(rules)
            + self.digest_param_set.encoded_len(rules)
            + (if self.encryption_param_set
                != CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.oid()
            {
                self.encryption_param_set.encoded_len(rules)
            } else {
                0
            })
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.public_key_param_set.encode(rules, out)?;
        at += self.digest_param_set.encode(rules, &mut out[at..])?;
        if self.encryption_param_set != CryptoProId::GOST28147_89_CRYPTO_PRO_A_PARAM_SET.oid() {
            at += self.encryption_param_set.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for GostR3410x2001PublicKeyParameters {}

impl Tagged for GostR3410x2001PublicKeyParameters {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for GostR3410x2001PublicKeyParameters {}

impl Encode for GostR3410x2001PublicKeyParameters {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
