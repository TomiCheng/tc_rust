use crate::{MaskGenerator, Mgf1, PssSignerError};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Display;
use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::PaddedBigUint;
use tc_constant_time::fixed_time_eq;
use tc_digest::util::Prehash;
use tc_digest::{Digest, TryDigest};
use tc_rsa::RsaKeyParams;
use tc_signer::{Signer, SignerInit};
use tc_zeroize::Zeroizing;

/// PSS 預設的結尾位元組，BC 的 `TrailerImplicit`。
pub const TRAILER_IMPLICIT: u8 = 0xBC;

/// BC 的 `PssSigner`：RFC 8017 8.1 的 RSASSA-PSS。訊息以 `C` 雜湊（通常與 `D` 相同；
/// [`raw`](PssSigner::raw) 時是呼叫端算好的雜湊），M' = 0x00 × 8 ‖ mHash ‖ salt 以 `D`
/// 雜湊，遮罩由 `M` 產生，salt 由 `R` 抽取，再交給 RSA 引擎 `E`。
///
/// 預設 salt 長度等於雜湊長度、MGF1 用同一種雜湊、結尾位元組為 0xBC。驗證時引擎拒絕的
/// 簽章一律視為不符，而 BC 會丟出例外。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
/// use tc_rsa_signer::PssSigner;
/// use tc_sha::Sha256Digest;
/// use tc_signer::{Signer, SignerInit};
///
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// // 以私鑰簽章；每次抽一個新的 salt，所以同一則訊息的簽章每次都不同。
/// let mut signer = PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng());
/// signer.init(&private_key)?;
/// signer.update(b"hello")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// // 以公鑰驗證。
/// let mut verifier = PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng());
/// verifier.init(&public_key)?;
/// verifier.update(b"hello")?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct PssSigner<E, D, M, R, C = D> {
    engine: E,
    content: C,
    digest: D,
    mask: M,
    rng: R,
    salt_length: usize,
    salt: Option<Vec<u8>>,
    trailer: u8,
    state: Option<State>,
}

/// `init` 定下的方向與 EM 的位元數、位元組數。
#[derive(Clone, Copy)]
struct State {
    signing: bool,
    em_bits: usize,
    em_len: usize,
}

impl<E, D: Digest + Clone, R> PssSigner<E, D, Mgf1<D>, R> {
    /// BC 的 `PssSigner(cipher, digest)`：salt 與雜湊等長，MGF1 用同一種雜湊。常數時間。
    pub fn new(engine: E, digest: D, rng: R) -> Self {
        Self {
            engine,
            content: digest.clone(),
            mask: Mgf1::new(digest.clone()),
            salt_length: digest.digest_size(),
            digest,
            rng,
            salt: None,
            trailer: TRAILER_IMPLICIT,
            state: None,
        }
    }
}

impl<E, D: Digest + Clone + Display, R> PssSigner<E, D, Mgf1<D>, R, Prehash> {
    /// BC 的 `CreateRawSigner(cipher, digest)`：`update` 收的是呼叫端以 `digest` 算好的
    /// 雜湊，而不是訊息，長度不對時 `generate_signature` 與 `verify_signature` 回傳
    /// `Digest` 錯誤。其餘同 [`new`](PssSigner::new)。常數時間。
    pub fn raw(engine: E, digest: D, rng: R) -> Self {
        Self {
            engine,
            content: Prehash::for_digest(&digest),
            mask: Mgf1::new(digest.clone()),
            salt_length: digest.digest_size(),
            digest,
            rng,
            salt: None,
            trailer: TRAILER_IMPLICIT,
            state: None,
        }
    }
}

impl<E, D, M, R, C> PssSigner<E, D, M, R, C> {
    /// 換掉遮罩產生函式，例如另一種雜湊的 [`Mgf1`] 或 [`XofMgf`](crate::XofMgf)。常數時間。
    pub fn with_mask<N>(self, mask: N) -> PssSigner<E, D, N, R, C> {
        PssSigner {
            engine: self.engine,
            content: self.content,
            digest: self.digest,
            mask,
            rng: self.rng,
            salt_length: self.salt_length,
            salt: self.salt,
            trailer: self.trailer,
            state: None,
        }
    }

    /// 改用 `salt_length` 位元組的隨機 salt；金鑰放不下時 `init` 回傳 `KeyTooSmall`。
    /// 常數時間。
    pub fn with_salt_length(mut self, salt_length: usize) -> Self {
        self.salt_length = salt_length;
        self.salt = None;
        self
    }

    /// 改用固定的 salt，不再抽取；驗證時也以它重算 M'。常數時間。
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt_length = salt.len();
        self.salt = Some(salt);
        self
    }

    /// 改用 `trailer` 為結尾位元組。常數時間。
    pub fn with_trailer(mut self, trailer: u8) -> Self {
        self.trailer = trailer;
        self
    }
}

impl<E, D, M, R, C, P> SignerInit<P> for PssSigner<E, D, M, R, C>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    D: Digest,
    C: TryDigest,
    P: RsaKeyParams<PaddedBigUint> + ?Sized,
{
    type Error = PssSignerError<<E as AsymmetricBlockCipherInit<P>>::Error, C::Error>;

    /// BC 的 `Init`：私鑰簽章、公鑰驗證，開始新的訊息；emBits = 模數位元數 − 1 要放得下
    /// 8·hLen + 8·sLen + 9 位元，否則回傳 `KeyTooSmall`。失敗時維持未初始化。變動時間：
    /// 只依公開的模數長度分支；引擎的 `init` 另計。
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.state = None;
        self.content.try_reset().map_err(PssSignerError::Digest)?;
        let signing = params.is_private_key();
        let direction = if signing {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, params)
            .map_err(PssSignerError::Cipher)?;
        let em_bits = (params.modulus().bits() as usize).saturating_sub(1);
        let needed = self
            .digest
            .digest_size()
            .checked_add(self.salt_length)
            .and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bits| bits.checked_add(9));
        if needed.is_none_or(|needed| em_bits < needed) {
            return Err(PssSignerError::KeyTooSmall);
        }
        self.state = Some(State {
            signing,
            em_bits,
            em_len: em_bits.div_ceil(8),
        });
        Ok(())
    }
}

impl<E, D, M, R, C> Signer for PssSigner<E, D, M, R, C>
where
    E: AsymmetricBlockCipher,
    D: Digest,
    M: MaskGenerator,
    R: CryptoRng,
    C: TryDigest,
{
    type Error = PssSignerError<E::Error, C::Error>;

    /// 模數的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn max_signature_size(&self) -> usize {
        self.state.expect("the signer is initialized");
        self.engine.output_block_size()
    }

    /// 把 `input` 加進訊息雜湊。`init` 之前回傳錯誤。常數時間程度同雜湊。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.state.ok_or(PssSignerError::NotInitialized)?;
        self.content
            .try_update(input)
            .map_err(PssSignerError::Digest)
    }

    /// BC 的 `GenerateSignature`：EM = maskedDB ‖ H ‖ trailer，DB = PS ‖ 0x01 ‖ salt，
    /// 交給引擎以私鑰運算，簽章與模數等長。以公鑰初始化時回傳錯誤。常數時間程度同引擎：
    /// 編碼只處理公開的雜湊與 salt，且只依長度分支。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let state = self.state.ok_or(PssSignerError::NotInitialized)?;
        if !state.signing {
            return Err(PssSignerError::NotForSigning);
        }
        let h_len = self.digest.digest_size();
        let s_len = self.salt_length;
        let mut m_dash = vec![0u8; 8 + h_len + s_len];
        self.content
            .try_do_final(&mut m_dash[8..8 + h_len])
            .map_err(PssSignerError::Digest)?;
        match &self.salt {
            Some(salt) => m_dash[8 + h_len..].copy_from_slice(salt),
            None => self.rng.fill_bytes(&mut m_dash[8 + h_len..]),
        }
        let mut h = vec![0u8; h_len];
        self.digest.update(&m_dash);
        self.digest.do_final(&mut h);

        let em_len = state.em_len;
        let db_len = em_len - h_len - 1;
        let mut block = Zeroizing::new(vec![0u8; em_len]);
        block[db_len - s_len - 1] = 0x01;
        block[db_len - s_len..db_len].copy_from_slice(&m_dash[8 + h_len..]);
        let mut mask = vec![0u8; db_len];
        self.mask.generate(&h, &mut mask);
        for (byte, mask) in block.iter_mut().zip(&mask) {
            *byte ^= mask;
        }
        block[db_len..em_len - 1].copy_from_slice(&h);
        block[0] &= 0xFF >> (8 * em_len - state.em_bits);
        block[em_len - 1] = self.trailer;
        self.engine
            .process_block(&block, output)
            .map_err(PssSignerError::Cipher)
    }

    /// BC 的 `VerifySignature`：以公鑰還原 EM，檢查結尾位元組、最高的多餘位元、PS 與
    /// 0x01，再以 salt 重算 H 比較；引擎拒絕的簽章視為不符。以私鑰初始化時回傳錯誤。
    /// 變動時間：只能用於公開值，簽章與訊息都是公開的；H 的比較不會提早結束。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        let state = self.state.ok_or(PssSignerError::NotInitialized)?;
        if state.signing {
            return Err(PssSignerError::NotForVerifying);
        }
        let h_len = self.digest.digest_size();
        let s_len = self.salt_length;
        let mut m_dash = vec![0u8; 8 + h_len + s_len];
        self.content
            .try_do_final(&mut m_dash[8..8 + h_len])
            .map_err(PssSignerError::Digest)?;

        let mut decrypted = vec![0u8; self.engine.output_block_size()];
        let Ok(length) = self.engine.process_block(signature, &mut decrypted) else {
            return Ok(false);
        };
        let decrypted = &decrypted[..length];
        // EM 是 emLen 位元組；引擎輸出的前導位元組超出時必須是零。
        let em_len = state.em_len;
        let mut block = vec![0u8; em_len];
        if length > em_len {
            let (extra, em) = decrypted.split_at(length - em_len);
            if extra.iter().any(|&byte| byte != 0) {
                return Ok(false);
            }
            block.copy_from_slice(em);
        } else {
            block[em_len - length..].copy_from_slice(decrypted);
        }

        let first_mask = 0xFFu8 >> (8 * em_len - state.em_bits);
        if block[0] & !first_mask != 0 || block[em_len - 1] != self.trailer {
            return Ok(false);
        }
        let db_len = em_len - h_len - 1;
        let mut mask = vec![0u8; db_len];
        self.mask.generate(&block[db_len..em_len - 1], &mut mask);
        for (byte, mask) in block.iter_mut().zip(&mask) {
            *byte ^= mask;
        }
        block[0] &= first_mask;
        let separator = db_len - s_len - 1;
        if block[..separator].iter().any(|&byte| byte != 0) || block[separator] != 0x01 {
            return Ok(false);
        }
        match &self.salt {
            Some(salt) => m_dash[8 + h_len..].copy_from_slice(salt),
            None => m_dash[8 + h_len..].copy_from_slice(&block[db_len - s_len..db_len]),
        }
        let mut h = vec![0u8; h_len];
        self.digest.update(&m_dash);
        self.digest.do_final(&mut h);
        Ok(fixed_time_eq(&h, &block[db_len..em_len - 1]))
    }

    /// 丟掉訊息，保留金鑰。常數時間。
    fn reset(&mut self) {
        let _ = self.content.try_reset();
    }
}
