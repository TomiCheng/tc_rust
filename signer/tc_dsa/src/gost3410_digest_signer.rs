use crate::{Dsa, DsaDigestSignerError, DsaEncodingError, DsaInit};
use alloc::vec;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_signer::{Signer, SignerInit};

/// BC 的 `Gost3410DigestSigner`：GOST 系列簽章（GOST R 34.10-94、34.10-2001／2012）共用的
/// [`Signer`]。訊息以 `D` 雜湊，雜湊原樣交給 `A`（GOST 的 DSA 把它讀成小端序整數），簽章是
/// s ‖ r，各為雜湊長度的大端序，與 [`DsaDigestSigner`](crate::DsaDigestSigner) 的編碼
/// 不同。錯誤型別沿用 [`DsaDigestSignerError`]。
pub struct Gost3410DigestSigner<A, D> {
    dsa: A,
    digest: D,
    signing: Option<bool>,
}

impl<A, D> Gost3410DigestSigner<A, D> {
    /// BC 的 `Gost3410DigestSigner(signer, digest)`。常數時間。
    pub fn new(dsa: A, digest: D) -> Self {
        Self {
            dsa,
            digest,
            signing: None,
        }
    }
}

impl<A, D, P> SignerInit<P> for Gost3410DigestSigner<A, D>
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

impl<A, D> Signer for Gost3410DigestSigner<A, D>
where
    A: Dsa<Integer = PaddedBigUint>,
    D: Digest,
{
    type Error = DsaDigestSignerError<A::Error>;

    /// BC 的 `GetMaxSignatureSize`：雜湊長度的兩倍。常數時間。
    fn max_signature_size(&self) -> usize {
        self.digest.digest_size() * 2
    }

    /// 把 `input` 加進訊息雜湊。`init` 之前回傳錯誤。常數時間程度同雜湊。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.signing.ok_or(DsaDigestSignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// BC 的 `GenerateSignature`：雜湊收尾交給底層 DSA，寫出 s ‖ r。r 或 s 放不進雜湊長度
    /// 時回傳 `ValueOutOfRange`，`output` 太短時回傳 `OutputTooShort`。以公鑰初始化時回傳
    /// 錯誤。常數時間程度同底層 DSA；排列只處理公開的 (r, s)。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForSigning);
        }
        let half = self.digest.digest_size();
        let mut hash = vec![0u8; half];
        self.digest.do_final(&mut hash);
        let (r, s) = self
            .dsa
            .generate_signature(&hash)
            .map_err(DsaDigestSignerError::Dsa)?;
        let output = output
            .get_mut(..half * 2)
            .ok_or(DsaDigestSignerError::Encoding(
                DsaEncodingError::OutputTooShort,
            ))?;
        let (first, second) = output.split_at_mut(half);
        write_be(&s, first)?;
        write_be(&r, second)?;
        Ok(half * 2)
    }

    /// BC 的 `VerifySignature`：簽章後半是 r、前半是 s，交給底層 DSA 驗證。長度不是雜湊的
    /// 兩倍、或 DSA 失敗時視為不符；BC 對太短的簽章丟出例外、對太長的忽略多餘位元組。以
    /// 私鑰初始化時回傳錯誤。變動時間：只能用於公開值，簽章與訊息都是公開的。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        if self.signing.ok_or(DsaDigestSignerError::NotInitialized)? {
            return Err(DsaDigestSignerError::NotForVerifying);
        }
        let half = self.digest.digest_size();
        let mut hash = vec![0u8; half];
        self.digest.do_final(&mut hash);
        if signature.len() != half * 2 {
            return Ok(false);
        }
        let Ok(s) = PaddedBigUint::from_be(&signature[..half]);
        let Ok(r) = PaddedBigUint::from_be(&signature[half..]);
        Ok(self.dsa.verify_signature(&hash, &r, &s).unwrap_or(false))
    }

    /// 丟掉訊息，保留金鑰。常數時間。
    fn reset(&mut self) {
        self.digest.reset();
    }
}

/// `value` 以大端序寫滿 `output`，前面補零；放不下時回傳 `ValueOutOfRange`，同 BC 的
/// `AsUnsignedByteArray`。變動時間：只能用於公開值，用於公開的簽章。
fn write_be<E>(value: &PaddedBigUint, output: &mut [u8]) -> Result<(), DsaDigestSignerError<E>> {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    let magnitude = &bytes[start..];
    if magnitude.len() > output.len() {
        return Err(DsaDigestSignerError::Encoding(
            DsaEncodingError::ValueOutOfRange,
        ));
    }
    output.fill(0);
    let offset = output.len() - magnitude.len();
    output[offset..].copy_from_slice(magnitude);
    Ok(())
}
