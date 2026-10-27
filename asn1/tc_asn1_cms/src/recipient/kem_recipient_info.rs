//! RFC 9629 `KEMRecipientInfo`, a recipient whose key-encryption key comes from
//! a key-encapsulation mechanism such as ML-KEM. It travels as the value of an
//! `OtherRecipientInfo` of type [`OtherRecipientInfo::ID_ORI_KEM`].
//!
//! ```text
//! KEMRecipientInfo ::= SEQUENCE {
//!     version CMSVersion,  -- always set to 0
//!     rid RecipientIdentifier,
//!     kem KEMAlgorithmIdentifier,
//!     kemct OCTET STRING,
//!     kdf KeyDerivationAlgorithmIdentifier,
//!     kekLength INTEGER (1..65535),
//!     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
//!     wrap KeyEncryptionAlgorithmIdentifier,
//!     encryptedKey EncryptedKey }
//! ```
//!
//! [`OtherRecipientInfo::ID_ORI_KEM`]: crate::recipient::OtherRecipientInfo::ID_ORI_KEM

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1OctetString, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::recipient::RecipientIdentifier;

/// A KEM recipient: the ciphertext it decapsulates, how the key-encryption key
/// is derived from the shared secret, and the wrapped content-encryption key.
///
/// The KEK length is held as a `u16`, so the upper bound holds by construction;
/// zero is `MalformedValue`, as is any decoded value outside 1-65535.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KemRecipientInfo {
    version: Option<Asn1Integer>,
    rid: RecipientIdentifier,
    kem: AlgorithmIdentifier,
    kemct: Asn1OctetString,
    kdf: AlgorithmIdentifier,
    kek_length: u16,
    ukm: Option<Asn1OctetString>,
    wrap: AlgorithmIdentifier,
    encrypted_key: Asn1OctetString,
}

impl KemRecipientInfo {
    /// A KEM recipient without user keying material. A zero `kek_length` is
    /// `MalformedValue`. Variable time: branches only on the encoding structure.
    #[allow(clippy::too_many_arguments)] // The seven mandatory fields are distinct.
    pub fn new(
        rid: RecipientIdentifier,
        kem: AlgorithmIdentifier,
        kemct: Asn1OctetString,
        kdf: AlgorithmIdentifier,
        kek_length: u16,
        wrap: AlgorithmIdentifier,
        encrypted_key: Asn1OctetString,
    ) -> Result<Self, Asn1Error> {
        if kek_length == 0 {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            version: None,
            rid,
            kem,
            kemct,
            kdf,
            kek_length,
            ukm: None,
            wrap,
            encrypted_key,
        })
    }

    /// Adds the user keying material the KDF takes.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ukm(mut self, ukm: Asn1OctetString) -> Self {
        self.ukm = Some(ukm);
        self
    }

    /// Returns the decoded version, or 0, which RFC 9629 always sets.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version.clone().unwrap_or_else(|| 0.into())
    }

    /// Returns the recipient identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn rid(&self) -> &RecipientIdentifier {
        &self.rid
    }

    /// Returns the KEM algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn kem(&self) -> &AlgorithmIdentifier {
        &self.kem
    }

    /// Returns the KEM ciphertext.
    /// Variable time: branches only on the encoding structure.
    pub fn kemct(&self) -> &Asn1OctetString {
        &self.kemct
    }

    /// Returns the key-derivation algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn kdf(&self) -> &AlgorithmIdentifier {
        &self.kdf
    }

    /// Returns the key-encryption key length in octets.
    /// Variable time: branches only on the encoding structure.
    pub fn kek_length(&self) -> u16 {
        self.kek_length
    }

    /// Returns the user keying material, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ukm(&self) -> Option<&Asn1OctetString> {
        self.ukm.as_ref()
    }

    /// Returns the key-wrap algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn wrap(&self) -> &AlgorithmIdentifier {
        &self.wrap
    }

    /// Returns the wrapped content-encryption key.
    /// Variable time: branches only on the encoding structure.
    pub fn encrypted_key(&self) -> &Asn1OctetString {
        &self.encrypted_key
    }
}

impl DecodeContent for KemRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let rid = fields.get()?;
        let kem = fields.get()?;
        let kemct = fields.get()?;
        let kdf = fields.get()?;
        let kek_length: Asn1Integer = fields.get()?;
        let ukm = fields.get_explicit_opt::<Asn1OctetString>([0xa0])?;
        let wrap = fields.get()?;
        let encrypted_key = fields.get()?;
        fields.end()?;
        let kek_length = u16::try_from(&kek_length).map_err(|_| Asn1Error::MalformedValue)?;
        let mut info = Self::new(rid, kem, kemct, kdf, kek_length, wrap, encrypted_key)?;
        info.ukm = ukm;
        if version != info.version() {
            info.version = Some(version);
        }
        Ok(info)
    }
}

impl DecodeInner for KemRecipientInfo {
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

impl EncodeContent for KemRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.rid.encoded_len(rules)
            + self.kem.encoded_len(rules)
            + self.kemct.encoded_len(rules)
            + self.kdf.encoded_len(rules)
            + Asn1Integer::from(self.kek_length).encoded_len(rules)
            + self
                .ukm
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self.wrap.encoded_len(rules)
            + self.encrypted_key.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.rid.encode(rules, &mut out[at..])?;
        at += self.kem.encode(rules, &mut out[at..])?;
        at += self.kemct.encode(rules, &mut out[at..])?;
        at += self.kdf.encode(rules, &mut out[at..])?;
        at += Asn1Integer::from(self.kek_length).encode(rules, &mut out[at..])?;
        if let Some(v) = &self.ukm {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.wrap.encode(rules, &mut out[at..])?;
        at += self.encrypted_key.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for KemRecipientInfo {}

impl Tagged for KemRecipientInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for KemRecipientInfo {}

impl Encode for KemRecipientInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use tc_asn1::{
        Asn1Error, Asn1Integer, Asn1OctetString, Decode, DecodingOptions, Encode, EncodingOptions,
    };

    use super::KemRecipientInfo;
    use crate::fixtures::{alg, by_issuer_rid};

    fn kem(kek_length: u16) -> Result<KemRecipientInfo, Asn1Error> {
        KemRecipientInfo::new(
            by_issuer_rid(),
            alg("2.16.840.1.101.3.4.4.2"), // ML-KEM-768
            Asn1OctetString::new(&[0x33; 1088]),
            alg("1.2.840.113549.1.9.16.3.28"), // HKDF with SHA-256
            kek_length,
            alg("2.16.840.1.101.3.4.1.5"), // AES-128 key wrap
            Asn1OctetString::new(&[0x44; 24]),
        )
    }

    #[test]
    fn a_kem_recipient_round_trips_with_and_without_ukm() {
        for value in [
            kem(16).unwrap(),
            kem(16)
                .unwrap()
                .with_ukm(Asn1OctetString::new(b"user keying material")),
        ] {
            assert_eq!(value.version(), 0.into());
            for rules in [EncodingOptions::BER, EncodingOptions::DER] {
                let wire = value.encode_to_vec(&rules).unwrap();
                assert_eq!(
                    KemRecipientInfo::decode(&wire, &DecodingOptions::default())
                        .unwrap()
                        .1,
                    value
                );
            }
        }
    }

    #[test]
    fn kek_lengths_outside_1_to_65535_are_rejected() {
        assert_eq!(kem(0), Err(Asn1Error::MalformedValue));
        let value = kem(16).unwrap();
        let der = |v: &dyn Encode| v.encode_to_vec(&EncodingOptions::DER).unwrap();
        for bad in [
            Asn1Integer::from(0),
            Asn1Integer::from(65536),
            Asn1Integer::from(-1),
        ] {
            let body: Vec<u8> = [
                der(&value.version()),
                der(value.rid()),
                der(value.kem()),
                der(value.kemct()),
                der(value.kdf()),
                der(&bad),
                der(value.wrap()),
                der(value.encrypted_key()),
            ]
            .concat();
            let mut wire = alloc::vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
            wire.extend_from_slice(&body);
            assert_eq!(
                KemRecipientInfo::decode(&wire, &DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }
}
