//! PKCS#1（RFC 8017 §9.2）的 `DigestInfo`。
//!
//! ```text
//! DigestInfo ::= SEQUENCE {
//!     digestAlgorithm AlgorithmIdentifier,
//!     digest          OCTET STRING
//! }
//! ```
//!
//! RSA PKCS#1 v1.5 簽章蓋的就是它的 DER 編碼（再加 padding）。各雜湊演算法的
//! 表頭是固定的位元組，實作常直接寫死 —— 例如 SHA-256 是
//! `30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20` 接 32 個位元組。

use tc_asn1::{
    Asn1Error, Asn1OctetString, DecodeContent, DecodingOptions, Encode, EncodingOptions, Fields,
    SequenceFields,
};

use crate::AlgorithmIdentifier;

/// 雜湊演算法加上雜湊值。
///
/// # 範例
///
/// ```
/// use tc_asn1::{Asn1Null, DecodingOptions, Encode, EncodingOptions, Decode};
/// use tc_asn1_x509::{AlgorithmIdentifier, DigestInfo};
///
/// let digest = [0xAB_u8; 32];
/// let info = DigestInfo::new(
///     AlgorithmIdentifier::with_parameters("2.16.840.1.101.3.4.2.1".parse()?, Asn1Null), // sha256
///     &digest,
/// );
///
/// let mut out = vec![0_u8; info.encoded_len(EncodingOptions::Der)];
/// info.encode(EncodingOptions::Der, &mut out)?;
///
/// // 前 19 個位元組就是大家寫死的那個 SHA-256 表頭
/// assert_eq!(
///     &out[..19],
///     &[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
/// );
/// assert_eq!(&out[19..], &digest);
///
/// let (used, decoded) = DigestInfo::try_decode(&out, DecodingOptions::default())?;
/// assert_eq!(used, out.len());
/// assert_eq!(decoded.digest(), &digest);
/// assert_eq!(decoded.digest_algorithm().algorithm().to_string(), "2.16.840.1.101.3.4.2.1");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
///
/// # 時間性質
///
/// 變動時間。分支只依編碼結構；雜湊值是公開的（簽章驗證時任何人都算得出來）。
#[derive(Debug)]
pub struct DigestInfo {
    digest_algorithm: AlgorithmIdentifier,
    digest: Asn1OctetString,
}

impl DigestInfo {
    pub fn new(digest_algorithm: AlgorithmIdentifier, digest: &[u8]) -> Self {
        Self {
            digest_algorithm,
            digest: Asn1OctetString::new(digest),
        }
    }

    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    pub fn digest(&self) -> &[u8] {
        self.digest.as_bytes()
    }
}

impl<'a> tc_asn1::Decode<'a> for DigestInfo {
    fn try_decode(
        buff: &'a [u8],
        options: tc_asn1::DecodingOptions,
    ) -> Result<(usize, Self), tc_asn1::Asn1Error> {
        let element = tc_asn1::Asn1Ref::parse(buff, options)?;
        if !element.is_constructed() {
            return Err(tc_asn1::Asn1Error::UnexpectedTag);
        }
        let value =
            <Self as tc_asn1::DecodeContent<'a>>::try_decode_content(element.value(), options)?;
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for DigestInfo {
    /// 變動時間：分支只依編碼結構。剛好兩個欄位，多的回
    /// [`Asn1Error::TrailingData`]，少的回 [`Asn1Error::Truncated`]。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        let mut fields = Fields::new(value, options)?;
        let digest_algorithm = fields.required(tc_asn1::tag::SEQUENCE)?;
        let value_tag = fields.peek()?.ok_or(Asn1Error::Truncated)?.tag();
        if value_tag != tc_asn1::tag::OCTET_STRING
            && value_tag != tc_asn1::tag::CONSTRUCTED_OCTET_STRING
        {
            return Err(Asn1Error::UnexpectedTag);
        }
        let digest = fields.required(value_tag)?;
        fields.finish()?;
        Ok(Self {
            digest_algorithm,
            digest,
        })
    }
}

impl SequenceFields for DigestInfo {
    /// 變動時間：分支只依編碼結構。
    fn fields(&self, _: EncodingOptions, sink: &mut dyn FnMut(&dyn Encode)) {
        sink(&self.digest_algorithm);
        sink(&self.digest);
    }
}

tc_asn1::impl_sequence_encode!(DigestInfo);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use tc_asn1::{Asn1Null, Decode};

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(tc_asn1::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn sha256_digest_info_round_trips_through_cer_without_changing_der() {
        let value = DigestInfo::new(
            AlgorithmIdentifier::with_parameters(
                "2.16.840.1.101.3.4.2.1".parse().unwrap(),
                Asn1Null,
            ),
            &[0xab; 32],
        );
        let mut cer = alloc::vec![
            0x30, 0x80, 0x30, 0x80, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0, 0, 0, 4, 32
        ];
        cer.extend_from_slice(&[0xab; 32]);
        cer.extend_from_slice(&[0, 0]);
        assert_eq!(cer.len(), 55);
        assert_eq!(value.encoded_len(EncodingOptions::Cer), 55);
        assert_eq!(value.encode_to_vec(EncodingOptions::Cer).unwrap(), cer);
        let ber = EncodingOptions::Ber(tc_asn1::LengthForm::Indefinite);
        assert_eq!(value.encoded_len(ber), cer.len());
        assert_eq!(value.encode_to_vec(ber).unwrap(), cer);
        let decoded = DigestInfo::try_decode(&cer, OPTIONS)
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(decoded.digest(), value.digest());
        assert_eq!(
            decoded
                .digest_algorithm()
                .encode_to_vec(EncodingOptions::Der)
                .unwrap(),
            value
                .digest_algorithm()
                .encode_to_vec(EncodingOptions::Der)
                .unwrap()
        );
        assert_eq!(decoded.encode_to_vec(EncodingOptions::Cer).unwrap(), cer);
        assert!(matches!(
            {
                let input: &[u8] = &cer;
                DigestInfo::try_decode(input, OPTIONS).and_then(|(used, value)| {
                    if used != input.len() {
                        Err(tc_asn1::Asn1Error::TrailingData)
                    } else if value.encode_to_vec(tc_asn1::EncodingOptions::Der)? != input {
                        Err(tc_asn1::Asn1Error::NotDer)
                    } else {
                        Ok(value)
                    }
                })
            },
            Err(Asn1Error::NotDer)
        ));
        let mut der = alloc::vec![
            0x30, 0x31, 0x30, 0x0d, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1, 5, 0, 4, 32
        ];
        der.extend_from_slice(&[0xab; 32]);
        assert_eq!(value.encode_to_vec(EncodingOptions::Der).unwrap(), der);
        assert_eq!(decoded.encode_to_vec(EncodingOptions::Der).unwrap(), der);
    }

    /// RFC 8017 §9.2 note 1 列的 SHA-1 表頭。
    const SHA1_PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    ];

    fn encode(info: &DigestInfo) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; info.encoded_len(EncodingOptions::Der)];
        info.encode(EncodingOptions::Der, &mut out).unwrap();
        out
    }

    #[test]
    fn the_sha1_form_matches_the_rfc_prefix() {
        let digest = [0x5A_u8; 20];
        let info = DigestInfo::new(
            AlgorithmIdentifier::with_parameters("1.3.14.3.2.26".parse().unwrap(), Asn1Null),
            &digest,
        );
        let out = encode(&info);

        assert_eq!(&out[..SHA1_PREFIX.len()], SHA1_PREFIX);
        assert_eq!(&out[SHA1_PREFIX.len()..], &digest);
    }

    #[test]
    fn a_digest_info_round_trips() {
        let mut input = SHA1_PREFIX.to_vec();
        input.extend_from_slice(&[0x11; 20]);

        let (used, info) = DigestInfo::try_decode(&input, OPTIONS).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(
            info.digest_algorithm().algorithm().to_string(),
            "1.3.14.3.2.26"
        );
        assert_eq!(info.digest(), &[0x11; 20]);
        assert_eq!(encode(&info), input);
    }

    #[test]
    fn a_missing_digest_is_truncated() {
        // 只有 AlgorithmIdentifier，沒有 OCTET STRING
        let input = [
            0x30, 0x0B, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
        ];
        assert_eq!(
            DigestInfo::try_decode(&input, OPTIONS).err(),
            Some(Asn1Error::Truncated)
        );
    }

    #[test]
    fn a_digest_that_is_not_an_octet_string_is_unexpected() {
        // 第二個欄位是 INTEGER
        let mut input = SHA1_PREFIX[..13].to_vec(); // 到 AlgorithmIdentifier 結束
        input.extend_from_slice(&[0x02, 0x01, 0x05]);
        input[1] = (input.len() - 2) as u8;
        assert_eq!(
            DigestInfo::try_decode(&input, OPTIONS).err(),
            Some(Asn1Error::UnexpectedTag)
        );
    }
}
