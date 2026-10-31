use crate::X931SignerError;
use crate::iso_trailers::{self, TRAILER_IMPLICIT};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Display;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_rsa::RsaKeyParams;
use tc_signer::{Signer, SignerInit};
use tc_zeroize::Zeroizing;

/// BC 的 `X931Signer`：ANSI X9.31-1998 的 RSA 簽章。訊息以 `D` 雜湊成 H，簽章區塊
/// EB = 0x6B ‖ 0xBB… ‖ 0xBA ‖ H ‖ 結尾，與模數等長，交給 RSA 引擎 `E`；簽章取結果與
/// n 減去它兩者中較小的。結尾是雜湊的 ISO/IEC 10118 代號，或隱含的 0xBC。
///
/// X9.31 的模數位元數是 8 的倍數；否則 EB 大於模數，引擎拒絕簽章。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
/// use tc_rsa_signer::X931Signer;
/// use tc_sha::Sha256Digest;
/// use tc_signer::{Signer, SignerInit};
///
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// // 結尾標明 SHA-256 的代號 0x34CC。
/// let mut signer = X931Signer::new(RsaEngine::new(), Sha256Digest::default());
/// signer.init(&private_key)?;
/// signer.update(b"hello")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// let mut verifier = X931Signer::new(RsaEngine::new(), Sha256Digest::default());
/// verifier.init(&public_key)?;
/// verifier.update(b"hello")?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct X931Signer<E, D> {
    engine: E,
    digest: D,
    trailer: Option<u16>,
    state: Option<State>,
}

/// `init` 定下的方向與模數。
struct State {
    signing: bool,
    modulus: BigUint,
    length: usize,
}

impl<E, D: Display> X931Signer<E, D> {
    /// BC 的 `X931Signer(cipher, digest)`：結尾標明雜湊的代號，依雜湊的名稱查
    /// [`iso_trailers::trailer`]；查不到時 `init` 回傳 `NoTrailer`。變動時間：只能用於
    /// 公開值，名稱是公開的。
    pub fn new(engine: E, digest: D) -> Self {
        let trailer = iso_trailers::trailer(&digest.to_string());
        Self {
            engine,
            digest,
            trailer,
            state: None,
        }
    }
}

impl<E, D> X931Signer<E, D> {
    /// BC 的 `X931Signer(cipher, digest, true)`：隱含結尾 0xBC，不標明雜湊。常數時間。
    pub fn implicit(engine: E, digest: D) -> Self {
        Self {
            engine,
            digest,
            trailer: Some(TRAILER_IMPLICIT),
            state: None,
        }
    }
}

impl<E, D: Digest> X931Signer<E, D> {
    /// BC 的 `CreateSignatureBlock`：把訊息雜湊收尾，排成 EB。常數時間程度同雜湊：只依
    /// 長度分支。
    fn signature_block(&mut self, length: usize, trailer: u16) -> Zeroizing<Vec<u8>> {
        let mut block = Zeroizing::new(vec![0u8; length]);
        let digest_size = self.digest.digest_size();
        let delta = if trailer == TRAILER_IMPLICIT {
            block[length - 1] = TRAILER_IMPLICIT as u8;
            length - digest_size - 1
        } else {
            block[length - 2..].copy_from_slice(&trailer.to_be_bytes());
            length - digest_size - 2
        };
        self.digest.do_final(&mut block[delta..delta + digest_size]);
        block[0] = 0x6b;
        block[1..delta - 1].fill(0xbb);
        block[delta - 1] = 0xba;
        block
    }
}

impl<E, D, P> SignerInit<P> for X931Signer<E, D>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    D: Digest,
    P: RsaKeyParams<PaddedBigUint> + ?Sized,
{
    type Error = X931SignerError<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// BC 的 `Init`：私鑰簽章、公鑰驗證，開始新的訊息；雜湊沒有代號時回傳 `NoTrailer`，
    /// 模數放不下 EB 的固定部分時回傳 `KeyTooSmall`。失敗時維持未初始化。變動時間：只依
    /// 公開的模數分支；引擎的 `init` 另計。
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.state = None;
        self.digest.reset();
        let trailer = self.trailer.ok_or(X931SignerError::NoTrailer)?;
        let signing = params.is_private_key();
        let direction = if signing {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, params)
            .map_err(X931SignerError::Cipher)?;
        let modulus = BigUint::from(params.modulus().clone());
        let length = (modulus.bits() as usize).div_ceil(8);
        let trailer_length = if trailer == TRAILER_IMPLICIT { 1 } else { 2 };
        if length < self.digest.digest_size() + trailer_length + 2 {
            return Err(X931SignerError::KeyTooSmall);
        }
        self.state = Some(State {
            signing,
            modulus,
            length,
        });
        Ok(())
    }
}

impl<E, D> Signer for X931Signer<E, D>
where
    E: AsymmetricBlockCipher,
    D: Digest,
{
    type Error = X931SignerError<E::Error>;

    /// 模數的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn max_signature_size(&self) -> usize {
        self.state
            .as_ref()
            .expect("the signer is initialized")
            .length
    }

    /// 把 `input` 加進訊息雜湊。`init` 之前回傳錯誤。常數時間程度同雜湊。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.state.as_ref().ok_or(X931SignerError::NotInitialized)?;
        self.digest.update(input);
        Ok(())
    }

    /// BC 的 `GenerateSignature`：以私鑰運算 EB 得到 t，簽章是 min(t, n − t)，寫成模數
    /// 的位元組數。以公鑰初始化時回傳錯誤。常數時間程度同引擎；取較小值只處理公開的簽章。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let (signing, length) = match &self.state {
            Some(state) => (state.signing, state.length),
            None => return Err(X931SignerError::NotInitialized),
        };
        if !signing {
            return Err(X931SignerError::NotForSigning);
        }
        let trailer = self.trailer.expect("init checked the trailer");
        let block = self.signature_block(length, trailer);
        let mut raw = vec![0u8; self.engine.output_block_size()];
        let written = self
            .engine
            .process_block(&block, &mut raw)
            .map_err(X931SignerError::Cipher)?;
        let modulus = &self.state.as_ref().expect("checked above").modulus;
        let Ok(t) = BigUint::from_be(&raw[..written]);
        let complement = modulus - &t;
        let signature = if complement < t { complement } else { t };
        Ok(write_be(&signature, length, output))
    }

    /// BC 的 `VerifySignature`：以公鑰還原 t，t 或 n − t 的低 4 位元要是 12，再與重算的
    /// EB 比較；引擎拒絕的簽章視為不符。以私鑰初始化時回傳錯誤。變動時間：只能用於
    /// 公開值，簽章與訊息都是公開的；EB 的比較不會提早結束。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        let (signing, length) = match &self.state {
            Some(state) => (state.signing, state.length),
            None => return Err(X931SignerError::NotInitialized),
        };
        if signing {
            return Err(X931SignerError::NotForVerifying);
        }
        let trailer = self.trailer.expect("init checked the trailer");
        let mut raw = vec![0u8; self.engine.output_block_size()];
        let Ok(written) = self.engine.process_block(signature, &mut raw) else {
            return Ok(false);
        };
        let modulus = &self.state.as_ref().expect("checked above").modulus;
        let Ok(t) = BigUint::from_be(&raw[..written]);
        let low_nibble = |value: &BigUint| {
            ArrayEncoding::<u8>::to_be(value)
                .last()
                .map_or(0, |byte| byte & 15)
        };
        let f = if low_nibble(&t) == 12 {
            t
        } else {
            let complement = modulus - &t;
            if low_nibble(&complement) != 12 {
                return Ok(false);
            }
            complement
        };
        let expected = self.signature_block(length, trailer);
        let mut actual = vec![0u8; length];
        write_be(&f, length, &mut actual);
        Ok(fixed_time_eq(&expected, &actual))
    }

    /// 丟掉訊息，保留金鑰。常數時間。
    fn reset(&mut self) {
        self.digest.reset();
    }
}

/// `value` 以大端序寫成 `length` 位元組，前面補零，回傳 `length`。變動時間：只能用於
/// 公開值，用於公開的簽章與 EB。
fn write_be(value: &BigUint, length: usize, output: &mut [u8]) -> usize {
    let bytes = ArrayEncoding::<u8>::to_be(value);
    let bytes = &bytes[bytes.len().saturating_sub(length)..];
    output[..length].fill(0);
    output[length - bytes.len()..length].copy_from_slice(bytes);
    length
}
