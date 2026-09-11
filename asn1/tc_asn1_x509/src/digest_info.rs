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

use tc_asn1::tag::SEQUENCE as TAG;
use tc_asn1::{
    Asn1Error, Asn1OctetString, Children, Depth, Encode, EncodingType, TryDecodeContent,
};

use crate::AlgorithmIdentifier;

/// 雜湊演算法加上雜湊值。
///
/// # 範例
///
/// ```
/// use tc_asn1::{Asn1Null, Depth, Encode, EncodingType, TryDecode};
/// use tc_asn1_x509::{AlgorithmIdentifier, DigestInfo};
///
/// let digest = [0xAB_u8; 32];
/// let info = DigestInfo::new(
///     AlgorithmIdentifier::with_parameters("2.16.840.1.101.3.4.2.1".parse()?, Asn1Null), // sha256
///     &digest,
/// );
///
/// let mut out = vec![0_u8; info.encoded_len(EncodingType::Der)];
/// info.encode(EncodingType::Der, &mut out)?;
///
/// // 前 19 個位元組就是大家寫死的那個 SHA-256 表頭
/// assert_eq!(
///     &out[..19],
///     &[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
/// );
/// assert_eq!(&out[19..], &digest);
///
/// let (used, decoded) = DigestInfo::try_decode(&out, Depth::DEFAULT)?;
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

impl<'a> TryDecodeContent<'a> for DigestInfo {
    const TAG: &'static [u8] = TAG;

    /// 變動時間：分支只依編碼結構。剛好兩個欄位，多的回
    /// [`Asn1Error::TrailingData`]，少的回 [`Asn1Error::Truncated`]。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let mut fields = Children::new(value, depth);

        let digest_algorithm = fields
            .next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<AlgorithmIdentifier>(depth)?;
        let digest = fields
            .next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<Asn1OctetString>(depth)?;

        if fields.next().is_some() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self {
            digest_algorithm,
            digest,
        })
    }
}

impl Encode for DigestInfo {
    fn tag(&self) -> &[u8] {
        TAG
    }

    fn content_len(&self, rules: EncodingType) -> usize {
        self.digest_algorithm.encoded_len(rules) + self.digest.encoded_len(rules)
    }

    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.digest_algorithm.encode(rules, out)?;
        at += self.digest.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use tc_asn1::{Asn1Null, TryDecode};

    const DEPTH: Depth = Depth::DEFAULT;

    /// RFC 8017 §9.2 note 1 列的 SHA-1 表頭。
    const SHA1_PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
    ];

    fn encode(info: &DigestInfo) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; info.encoded_len(EncodingType::Der)];
        info.encode(EncodingType::Der, &mut out).unwrap();
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

        let (used, info) = DigestInfo::try_decode(&input, DEPTH).unwrap();
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
            DigestInfo::try_decode(&input, DEPTH).err(),
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
            DigestInfo::try_decode(&input, DEPTH).err(),
            Some(Asn1Error::UnexpectedTag)
        );
    }
}
