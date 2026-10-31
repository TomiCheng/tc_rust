use crate::{Dsa, DsaDigestSignerError, DsaEncoding, DsaInit, StandardDsaEncoding};
use alloc::vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_signer::{Signer, SignerInit};

/// BC 的 `DsaDigestSigner`：把只簽雜湊的 [`Dsa`] 接成 `tc_signer` 的 [`Signer`]。訊息以
/// `D` 雜湊，交給 `A` 簽成 (r, s)，再以 `N` 編碼，預設是 DER 的 [`StandardDsaEncoding`]。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dsa::{DsaDigestSigner, HMacDsaKCalculator};
/// use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
/// use tc_ecdsa_v2::EcdsaSigner;
/// use tc_fp_curve::FpCtCurve;
/// use tc_fp_curve::named_curves::SECP256R1;
/// use tc_sha::Sha256Digest;
/// use tc_signer::{Signer, SignerInit};
///
/// let field = SECP256R1.field();
/// let curve = SECP256R1.ct_curve(&field);
/// let g = SECP256R1.ct_generator(&curve);
/// let mut rng = rand::rng();
/// let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>>::new();
/// generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// // 以 RFC 6979 的確定性 k 做 ECDSA，簽章編成 DER。
/// let ecdsa = || EcdsaSigner::new(HMacDsaKCalculator::new(Sha256Digest::new()));
/// let mut signer = DsaDigestSigner::new(ecdsa(), Sha256Digest::new());
/// signer.init(&private_key)?;
/// signer.update(b"hello")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// let mut verifier = DsaDigestSigner::new(ecdsa(), Sha256Digest::new());
/// verifier.init(&public_key)?;
/// verifier.update(b"hello")?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DsaDigestSigner<A, D, N = StandardDsaEncoding> {
    dsa: A,
    digest: D,
    encoding: N,
    signing: Option<bool>,
}

impl<A, D> DsaDigestSigner<A, D> {
    /// BC 的 `DsaDigestSigner(dsa, digest)`：簽章編成 DER。常數時間。
    pub fn new(dsa: A, digest: D) -> Self {
        Self::with_encoding(dsa, digest, StandardDsaEncoding)
    }
}

impl<A, D, N> DsaDigestSigner<A, D, N> {
    /// BC 的 `DsaDigestSigner(dsa, digest, encoding)`，例如
    /// [`PlainDsaEncoding`](crate::PlainDsaEncoding)。常數時間。
    pub fn with_encoding(dsa: A, digest: D, encoding: N) -> Self {
        Self {
            dsa,
            digest,
            encoding,
            signing: None,
        }
    }
}

impl<A, D, N, P> SignerInit<P> for DsaDigestSigner<A, D, N>
where
    A: DsaInit<P>,
    D: Digest,
    P: AsymmetricKeyParams + ?Sized,
{
    type Error = DsaDigestSignerError<<A as DsaInit<P>>::Error>;

    /// BC 的 `Init`：私鑰簽章、公鑰驗證，開始新的訊息，再初始化底層 DSA；失敗時維持未
    /// 初始化。常數時間程度同底層 DSA 的 `init`。
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.signing = None;
        self.digest.reset();
        self.dsa.init(params).map_err(DsaDigestSignerError::Dsa)?;
        self.signing = Some(params.is_private_key());
        Ok(())
    }
}

impl<A, D, N> Signer for DsaDigestSigner<A, D, N>
where
    A: Dsa<Integer = PaddedBigUint>,
    D: Digest,
    N: DsaEncoding,
{
    type Error = DsaDigestSignerError<A::Error>;

    /// 編碼依群的階最多佔的位元組數。`init` 之前呼叫會 panic。變動時間：只能用於公開值，
    /// 階是公開的。
    fn max_signature_size(&self) -> usize {
        self.encoding.max_encoding_size(self.dsa.order())
    }

    /// 把 `input` 加進訊息雜湊。`init` 之前回傳錯誤。常數時間程度同雜湊。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.signing.ok_or(DsaDigestSignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// BC 的 `GenerateSignature`：雜湊收尾，交給底層 DSA 簽章，再編碼進 `output`。以公鑰
    /// 初始化時回傳錯誤。常數時間程度同底層 DSA；編碼只處理公開的 (r, s)。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForSigning);
        }
        let mut hash = vec![0u8; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        let (r, s) = self
            .dsa
            .generate_signature(&hash)
            .map_err(DsaDigestSignerError::Dsa)?;
        self.encoding
            .encode(self.dsa.order(), &r, &s, output)
            .map_err(DsaDigestSignerError::Encoding)
    }

    /// BC 的 `VerifySignature`：解出 (r, s) 交給底層 DSA 驗證；解不出或 DSA 失敗時視為不符，
    /// 同 BC。以私鑰初始化時回傳錯誤。變動時間：只能用於公開值，簽章與訊息都是公開的。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        if self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForVerifying);
        }
        let mut hash = vec![0u8; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        let Ok((r, s)) = self.encoding.decode(self.dsa.order(), signature) else {
            return Ok(false);
        };
        Ok(self.dsa.verify_signature(&hash, &r, &s).unwrap_or(false))
    }

    /// 丟掉訊息，保留金鑰。常數時間。
    fn reset(&mut self) {
        self.digest.reset();
    }
}
