//! RFC 5280 的 `AlgorithmIdentifier`。
//!
//! ```text
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  ANY DEFINED BY algorithm OPTIONAL
//! }
//! ```
//!
//! `parameters` 是 `ANY DEFINED BY`：型別由 `algorithm` 的值決定。rsaEncryption
//! 配 NULL，ecPublicKey 配曲線的 OID，Ed25519 什麼都沒有。所以解碼時不解讀它，
//! 留給知道演算法的呼叫端；建構時則直接放型別化的值。

use alloc::boxed::Box;
use core::fmt;

use tc_asn1::tag::{NULL, SEQUENCE as TAG};
use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Null, Asn1Oid, Children, Depth, Encode, EncodingType, TryDecodeContent,
};

/// `parameters` 的型別由 `algorithm` 決定，所以兩個方向的表示不同。
///
/// 解碼永遠得到 [`Decoded`](Self::Decoded)；建構永遠是 [`Built`](Self::Built)。
/// 兩者不合併成一個 `Box<dyn Encode>`，因為 `dyn Encode` 只能寫不能讀 ——
/// 解進來的參數要留著 [`Asn1Any`] 才能之後 `decode_as`。
pub enum AlgorithmParameters {
    /// 沒有參數。
    Absent,
    /// `NULL`。光看 tag 就認得，不必查演算法，所以解碼時直接是它。
    Null,
    /// 自己造的：型別知道，只需要寫出去。
    Built(Box<dyn Encode>),
    /// 解進來的、不是 NULL 的：型別待查，用的時候照 `algorithm` 去 `decode_as`。
    Decoded(Asn1Any),
}

impl fmt::Debug for AlgorithmParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Null => f.write_str("Null"),
            Self::Built(_) => f.write_str("Built(..)"),
            Self::Decoded(any) => f.debug_tuple("Decoded").field(any).finish(),
        }
    }
}

/// 演算法的 OID 加上它的參數。
///
/// # 範例
///
/// 要不要帶參數由演算法規定：rsaEncryption **必須**帶 NULL（RFC 3279 §2.2.1），
/// Ed25519 與 ecdsa-with-SHA256 **必須**省略。少了 rsaEncryption 的 `05 00`
/// 是常見的互通錯誤。
///
/// 建構時參數直接放型別化的值；解碼時參數不解讀，要用時照 `algorithm` 決定型別：
///
/// ```
/// use tc_asn1::{Depth, Encode, EncodingType, TryDecode};
/// use tc_asn1_x509::{AlgorithmIdentifier, AlgorithmParameters};
///
/// let alg = AlgorithmIdentifier::with_null("1.2.840.113549.1.1.1".parse()?); // rsaEncryption
///
/// // 先問要多大，再配剛好的緩衝
/// let mut out = vec![0_u8; alg.encoded_len(EncodingType::Der)];
/// alg.encode(EncodingType::Der, &mut out)?;
/// assert_eq!(
///     out,
///     [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00],
/// );
///
/// // 解回來：消耗整個緩衝
/// let (used, decoded) = AlgorithmIdentifier::try_decode(&out, Depth::DEFAULT)?;
/// assert_eq!(used, out.len());
/// assert_eq!(decoded.algorithm().to_string(), "1.2.840.113549.1.1.1");
///
/// // NULL 光看 tag 就認得，解碼直接給變體
/// assert!(matches!(decoded.parameters(), AlgorithmParameters::Null));
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
///
/// # 時間性質
///
/// 變動時間。分支只依編碼結構；`algorithm` 與 `parameters` 都是公開值。
#[derive(Debug)]
pub struct AlgorithmIdentifier {
    algorithm: Asn1Oid,
    parameters: AlgorithmParameters,
}

impl AlgorithmIdentifier {
    /// 沒有參數，例如 Ed25519。
    pub fn new(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: AlgorithmParameters::Absent,
        }
    }

    /// 參數是 NULL：rsaEncryption 和所有 `*WithRSAEncryption` 的簽章演算法。
    pub fn with_null(algorithm: Asn1Oid) -> Self {
        Self {
            algorithm,
            parameters: AlgorithmParameters::Null,
        }
    }

    /// 帶其他參數，例如 ecPublicKey 配曲線的 OID。
    pub fn with_parameters(algorithm: Asn1Oid, parameters: impl Encode + 'static) -> Self {
        Self {
            algorithm,
            parameters: AlgorithmParameters::Built(Box::new(parameters)),
        }
    }

    /// 演算法的 OID。
    pub fn algorithm(&self) -> &Asn1Oid {
        &self.algorithm
    }

    /// 參數，三種狀態見 [`AlgorithmParameters`]。
    pub fn parameters(&self) -> &AlgorithmParameters {
        &self.parameters
    }

    /// 解進來、而且不是 NULL 的參數；其他情況回 `None`。
    pub fn decoded_parameters(&self) -> Option<&Asn1Any> {
        match &self.parameters {
            AlgorithmParameters::Decoded(any) => Some(any),
            _ => None,
        }
    }
}

impl<'a> TryDecodeContent<'a> for AlgorithmIdentifier {
    const TAG: &'static [u8] = TAG;

    /// 變動時間：分支只依編碼結構。
    ///
    /// 剛好兩個以內的欄位；第三個回 [`Asn1Error::TrailingData`]，
    /// 少了 `algorithm` 回 [`Asn1Error::Truncated`]。
    fn try_decode_content(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let mut fields = Children::new(value, depth);

        let algorithm = fields
            .next()
            .ok_or(Asn1Error::Truncated)??
            .decode_as::<Asn1Oid>(depth)?;

        let parameters = match fields.next().transpose()? {
            None => AlgorithmParameters::Absent,
            Some(field) if field.tag() == NULL => {
                field.decode_as::<Asn1Null>(depth)?; // 驗內容是空的
                AlgorithmParameters::Null
            }
            Some(field) => AlgorithmParameters::Decoded(Asn1Any::from(&field)),
        };

        if fields.next().is_some() {
            return Err(Asn1Error::TrailingData);
        }
        Ok(Self {
            algorithm,
            parameters,
        })
    }
}

impl Encode for AlgorithmIdentifier {
    fn tag(&self) -> &[u8] {
        TAG
    }

    fn content_len(&self, rules: EncodingType) -> usize {
        let parameters = match &self.parameters {
            AlgorithmParameters::Absent => 0,
            AlgorithmParameters::Null => Asn1Null.encoded_len(rules),
            AlgorithmParameters::Built(p) => p.encoded_len(rules),
            AlgorithmParameters::Decoded(p) => p.encoded_len(rules),
        };
        self.algorithm.encoded_len(rules) + parameters
    }

    fn encode_content(&self, rules: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.algorithm.encode(rules, out)?;
        at += match &self.parameters {
            AlgorithmParameters::Absent => 0,
            AlgorithmParameters::Null => Asn1Null.encode(rules, &mut out[at..])?,
            AlgorithmParameters::Built(p) => p.encode(rules, &mut out[at..])?,
            AlgorithmParameters::Decoded(p) => p.encode(rules, &mut out[at..])?,
        };
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use tc_asn1::TryDecode;

    const DEPTH: Depth = Depth::DEFAULT;

    /// rsaEncryption，參數是 NULL —— RSA 憑證裡最常見的那個。
    const RSA: &[u8] = &[
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];

    /// ecPublicKey，參數是 named curve 的 OID（prime256v1）。
    const EC_P256: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    ];

    /// Ed25519，沒有參數。
    const ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];

    fn encode(alg: &AlgorithmIdentifier) -> Vec<u8> {
        let mut out = alloc::vec![0_u8; alg.encoded_len(EncodingType::Der)];
        alg.encode(EncodingType::Der, &mut out).unwrap();
        out
    }

    #[test]
    fn rsa_with_null_parameters_decodes_and_re_encodes_identically() {
        let (used, alg) = AlgorithmIdentifier::try_decode(RSA, DEPTH).unwrap();

        assert_eq!(used, RSA.len());
        assert_eq!(alg.algorithm().to_string(), "1.2.840.113549.1.1.1");

        assert!(matches!(alg.parameters(), AlgorithmParameters::Null));
        assert!(alg.decoded_parameters().is_none(), "NULL 不算 Decoded");

        assert_eq!(encode(&alg), RSA);
    }

    #[test]
    fn ec_parameters_are_read_as_an_oid_when_the_caller_knows_the_algorithm() {
        let (_, alg) = AlgorithmIdentifier::try_decode(EC_P256, DEPTH).unwrap();
        assert_eq!(alg.algorithm().to_string(), "1.2.840.10045.2.1");

        let curve = alg
            .decoded_parameters()
            .unwrap()
            .as_ref()
            .decode_as::<Asn1Oid>(DEPTH)
            .unwrap();
        assert_eq!(curve.to_string(), "1.2.840.10045.3.1.7");
    }

    #[test]
    fn absent_parameters_decode_as_absent_and_encode_as_nothing() {
        let (used, alg) = AlgorithmIdentifier::try_decode(ED25519, DEPTH).unwrap();

        assert_eq!(used, ED25519.len());
        assert!(matches!(alg.parameters(), AlgorithmParameters::Absent));
        assert_eq!(encode(&alg), ED25519);
    }

    #[test]
    fn a_built_value_encodes_to_the_known_bytes() {
        // NULL 有專屬的建構子，不用 Box
        let alg = AlgorithmIdentifier::with_null("1.2.840.113549.1.1.1".parse().unwrap());
        assert_eq!(encode(&alg), RSA);

        let alg = AlgorithmIdentifier::with_parameters(
            "1.2.840.10045.2.1".parse().unwrap(),
            "1.2.840.10045.3.1.7".parse::<Asn1Oid>().unwrap(),
        );
        assert_eq!(encode(&alg), EC_P256);

        let alg = AlgorithmIdentifier::new("1.3.101.112".parse().unwrap());
        assert_eq!(encode(&alg), ED25519);
    }

    #[test]
    fn a_null_carrying_contents_is_malformed_not_decoded() {
        // 05 01 00 有 NULL 的 tag 但內容不空：是壞資料，不該掉進 Decoded
        let input = [
            0x30, 0x0E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05,
            0x01, 0x00,
        ];
        assert_eq!(
            AlgorithmIdentifier::try_decode(&input, DEPTH).err(),
            Some(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn a_third_field_is_trailing_data() {
        let mut input = RSA.to_vec();
        input[1] += 2;
        input.extend_from_slice(&[0x05, 0x00]);

        assert_eq!(
            AlgorithmIdentifier::try_decode(&input, DEPTH).err(),
            Some(Asn1Error::TrailingData)
        );
    }

    #[test]
    fn a_missing_algorithm_is_truncated_and_a_wrong_type_is_unexpected() {
        assert_eq!(
            AlgorithmIdentifier::try_decode(&[0x30, 0x00], DEPTH).err(),
            Some(Asn1Error::Truncated)
        );
        assert_eq!(
            AlgorithmIdentifier::try_decode(&[0x30, 0x02, 0x05, 0x00], DEPTH).err(),
            Some(Asn1Error::UnexpectedTag)
        );
    }
}
