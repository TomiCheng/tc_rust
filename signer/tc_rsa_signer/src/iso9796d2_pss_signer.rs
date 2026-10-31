use crate::iso_trailers::{self, TRAILER_IMPLICIT, trailer_length};
use crate::{Iso9796d2Error, MaskGenerator, Mgf1};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Display;
use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::PaddedBigUint;
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_rsa::RsaKeyParams;
use tc_signer::{Signer, SignerInit, SignerWithRecovery};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `Iso9796d2PssSigner`：ISO/IEC 9796-2 方案 2 與 3，加 salt 的可還原訊息 RSA 簽章。
/// 訊息前段 M1 放進區塊，其餘 M2 只取雜湊：H = Hash(len(M1) ‖ M1 ‖ Hash(M2) ‖ salt)，
/// 區塊是 MGF1(H) 遮住的 0x00… ‖ 0x01 ‖ M1 ‖ salt，後接 H 與結尾。salt 長度 0 即方案 3。
///
/// 和 BC 不同：驗證時拿輸入的 M1 與還原的比對。BC 在比對前把還原的 M1 寫進輸入的緩衝區，
/// 使 M1 被換掉也照樣通過。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
/// use tc_rsa_signer::Iso9796d2PssSigner;
/// use tc_sha::Sha256Digest;
/// use tc_signer::{Signer, SignerInit, SignerWithRecovery};
///
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// let mut signer = Iso9796d2PssSigner::new(RsaEngine::new(), Sha256Digest::default(), 20, rand::rng());
/// signer.init(&private_key)?;
/// signer.update(b"challenge")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// let mut verifier = Iso9796d2PssSigner::new(RsaEngine::new(), Sha256Digest::default(), 20, rand::rng());
/// verifier.init(&public_key)?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// assert_eq!(verifier.recovered_message(), Some(&b"challenge"[..]));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Iso9796d2PssSigner<E, D, R> {
    engine: E,
    digest: D,
    mask: Mgf1<D>,
    rng: R,
    salt_length: usize,
    salt: Option<Vec<u8>>,
    trailer: Option<u16>,
    digest_trailer: Option<u16>,
    state: Option<State>,
    buffer: Zeroizing<Vec<u8>>,
    message_length: usize,
    full_message: bool,
    recovered: Option<Vec<u8>>,
    pre: Option<Pre>,
}

/// `init` 定下的方向與區塊長度。
#[derive(Clone, Copy)]
struct State {
    signing: bool,
    block_length: usize,
}

/// `update_with_recovered_message` 解出的簽章與區塊、訊息起點與結尾長度。
struct Pre {
    signature: Vec<u8>,
    block: Zeroizing<Vec<u8>>,
    start: usize,
    trailer_length: usize,
}

impl<E, D: Digest + Clone + Display, R> Iso9796d2PssSigner<E, D, R> {
    /// BC 的 `Iso9796d2PssSigner(cipher, digest, saltLength)`：結尾標明雜湊的代號，依名稱
    /// 查；查不到時 `init` 回傳 `NoTrailer`。salt 由 `rng` 抽取。變動時間：只能用於公開值，
    /// 名稱是公開的。
    pub fn new(engine: E, digest: D, salt_length: usize, rng: R) -> Self {
        let digest_trailer = iso_trailers::trailer(&digest.to_string());
        Self::with_trailer(
            engine,
            digest,
            salt_length,
            rng,
            digest_trailer,
            digest_trailer,
        )
    }

    /// BC 的 `Iso9796d2PssSigner(cipher, digest, saltLength, true)`：隱含結尾 0xBC。驗證時
    /// 仍接受標明這個雜湊代號的簽章，同 BC。變動時間：只能用於公開值，名稱是公開的。
    pub fn implicit(engine: E, digest: D, salt_length: usize, rng: R) -> Self {
        let digest_trailer = iso_trailers::trailer(&digest.to_string());
        Self::with_trailer(
            engine,
            digest,
            salt_length,
            rng,
            Some(TRAILER_IMPLICIT),
            digest_trailer,
        )
    }

    /// 以簽章用的結尾與雜湊的代號建構；MGF1 用同一種雜湊。常數時間。
    fn with_trailer(
        engine: E,
        digest: D,
        salt_length: usize,
        rng: R,
        trailer: Option<u16>,
        digest_trailer: Option<u16>,
    ) -> Self {
        Self {
            engine,
            mask: Mgf1::new(digest.clone()),
            digest,
            rng,
            salt_length,
            salt: None,
            trailer,
            digest_trailer,
            state: None,
            buffer: Zeroizing::new(Vec::new()),
            message_length: 0,
            full_message: false,
            recovered: None,
            pre: None,
        }
    }
}

impl<E, D, R> Iso9796d2PssSigner<E, D, R> {
    /// BC 以 `ParametersWithSalt` 給的固定 salt：簽章時用它，不再抽取；salt 長度隨之改變。
    /// 驗證一律用區塊裡的 salt。常數時間。
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt_length = salt.len();
        self.salt = Some(salt);
        self
    }
}

impl<E: AsymmetricBlockCipher, D: Digest, R> Iso9796d2PssSigner<E, D, R> {
    /// 一則訊息結束：清掉訊息與雜湊。常數時間。
    fn end_message(&mut self) {
        self.digest.reset();
        self.message_length = 0;
        self.buffer.zeroize();
    }

    /// 回傳已初始化為驗證的狀態。常數時間。
    fn verifying(&self) -> Result<State, Iso9796d2Error<E::Error>> {
        let state = self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        if state.signing {
            return Err(Iso9796d2Error::NotForVerifying);
        }
        Ok(state)
    }

    /// BC 的 `UpdateWithRecoveredMessage` 本體：解出區塊、去掉遮罩，找出 0x01 之後的 M1。
    /// 引擎拒絕的簽章回傳引擎的錯誤，格式不對時回傳 `MalformedSignature`。和 BC 不同，
    /// 不把 M1 寫進輸入的緩衝區。變動時間：只能用於公開值，簽章是公開的。
    fn recover(&mut self, state: State, signature: &[u8]) -> Result<(), Iso9796d2Error<E::Error>> {
        let mut raw = Zeroizing::new(vec![0u8; self.engine.output_block_size()]);
        let written = self
            .engine
            .process_block(signature, &mut raw)
            .map_err(Iso9796d2Error::Cipher)?;
        let length = state.block_length;
        if written > length && raw[..written - length].iter().any(|&byte| byte != 0) {
            return Err(Iso9796d2Error::MalformedSignature);
        }
        let mut block = Zeroizing::new(vec![0u8; length]);
        let kept = written.min(length);
        block[length - kept..].copy_from_slice(&raw[written - kept..written]);

        let trailer_length = trailer_length(&block, self.digest_trailer)?;
        let digest_size = self.digest.digest_size();
        let mask_length = length
            .checked_sub(digest_size + trailer_length)
            .ok_or(Iso9796d2Error::MalformedSignature)?;
        let mut mask = vec![0u8; mask_length];
        self.mask
            .generate(&block[mask_length..mask_length + digest_size], &mut mask);
        for (byte, mask) in block.iter_mut().zip(&mask) {
            *byte ^= mask;
        }
        block[0] &= 0x7F;
        let start = block
            .iter()
            .position(|&byte| byte == 0x01)
            .map_or(length, |index| index + 1);
        let recovered_length = mask_length
            .checked_sub(start + self.salt_length)
            .filter(|_| start < length)
            .ok_or(Iso9796d2Error::MalformedSignature)?;
        self.full_message = start > 1;
        self.recovered = Some(block[start..start + recovered_length].to_vec());
        self.pre = Some(Pre {
            signature: signature.to_vec(),
            block,
            start,
            trailer_length,
        });
        Ok(())
    }
}

impl<E, D, R, P> SignerInit<P> for Iso9796d2PssSigner<E, D, R>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    D: Digest,
    P: RsaKeyParams<PaddedBigUint> + ?Sized,
{
    type Error = Iso9796d2Error<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// BC 的 `Init`：私鑰簽章、公鑰驗證，丟掉先前的訊息；雜湊沒有代號時回傳 `NoTrailer`，
    /// 模數放不下雜湊、salt 與結尾時回傳 `KeyTooSmall`。失敗時維持未初始化。變動時間：只依
    /// 公開的模數分支；引擎的 `init` 另計。
    fn init(&mut self, params: &P) -> Result<(), Self::Error> {
        self.state = None;
        let trailer = self.trailer.ok_or(Iso9796d2Error::NoTrailer)?;
        let signing = params.is_private_key();
        let direction = if signing {
            CipherDirection::Encrypt
        } else {
            CipherDirection::Decrypt
        };
        self.engine
            .init(direction, params)
            .map_err(Iso9796d2Error::Cipher)?;
        let block_length = (params.modulus().bits() as usize).div_ceil(8);
        let trailer_length = if trailer == TRAILER_IMPLICIT { 1 } else { 2 };
        let buffer_length = self
            .digest
            .digest_size()
            .checked_add(self.salt_length)
            .and_then(|fixed| fixed.checked_add(1 + trailer_length))
            .and_then(|fixed| block_length.checked_sub(fixed))
            .ok_or(Iso9796d2Error::KeyTooSmall)?;
        self.buffer = Zeroizing::new(vec![0; buffer_length]);
        self.digest.reset();
        self.message_length = 0;
        self.recovered = None;
        self.full_message = false;
        self.pre = None;
        self.state = Some(State {
            signing,
            block_length,
        });
        Ok(())
    }
}

impl<E, D, R> Signer for Iso9796d2PssSigner<E, D, R>
where
    E: AsymmetricBlockCipher,
    D: Digest,
    R: CryptoRng,
{
    type Error = Iso9796d2Error<E::Error>;

    /// 模數的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn max_signature_size(&self) -> usize {
        self.state.expect("the signer is initialized");
        self.engine.output_block_size()
    }

    /// 放得下的前段存為 M1，其餘加進 M2 的雜湊；`update_with_recovered_message` 之後全部
    /// 加進雜湊。`init` 之前回傳錯誤。常數時間程度同雜湊：只依長度分支與複製。
    fn update(&mut self, mut input: &[u8]) -> Result<(), Self::Error> {
        self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        if self.pre.is_none() {
            let stored = (self.buffer.len() - self.message_length).min(input.len());
            self.buffer[self.message_length..self.message_length + stored]
                .copy_from_slice(&input[..stored]);
            self.message_length += stored;
            input = &input[stored..];
        }
        self.digest.update(input);
        Ok(())
    }

    /// BC 的 `GenerateSignature`：抽取 salt（或用固定的），算出 H，排好區塊並以 MGF1(H)
    /// 遮住，以私鑰運算。以公鑰初始化時回傳錯誤。常數時間程度同引擎：編碼只處理隨簽章公開
    /// 的值，且只依長度分支。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let state = self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        if !state.signing {
            return Err(Iso9796d2Error::NotForSigning);
        }
        let trailer = self.trailer.expect("init checked the trailer");
        let mut salt = vec![0u8; self.salt_length];
        match &self.salt {
            Some(fixed) => salt.copy_from_slice(fixed),
            None => self.rng.fill_bytes(&mut salt),
        }
        let digest_size = self.digest.digest_size();
        let message_length = self.message_length;
        let mut hash = vec![0u8; digest_size];
        self.digest.do_final(&mut hash);
        self.digest
            .update(&((message_length as u64) * 8).to_be_bytes());
        self.digest.update(&self.buffer[..message_length]);
        self.digest.update(&hash);
        self.digest.update(&salt);
        self.digest.do_final(&mut hash);

        let length = state.block_length;
        let trailer_length = if trailer == TRAILER_IMPLICIT { 1 } else { 2 };
        let mut block = Zeroizing::new(vec![0u8; length]);
        let offset = length - message_length - salt.len() - digest_size - trailer_length - 1;
        block[offset] = 0x01;
        block[offset + 1..offset + 1 + message_length]
            .copy_from_slice(&self.buffer[..message_length]);
        block[offset + 1 + message_length..offset + 1 + message_length + salt.len()]
            .copy_from_slice(&salt);
        let mask_length = length - digest_size - trailer_length;
        let mut mask = vec![0u8; mask_length];
        self.mask.generate(&hash, &mut mask);
        for (byte, mask) in block.iter_mut().zip(&mask) {
            *byte ^= mask;
        }
        block[mask_length..mask_length + digest_size].copy_from_slice(&hash);
        if trailer == TRAILER_IMPLICIT {
            block[length - 1] = TRAILER_IMPLICIT as u8;
        } else {
            block[length - 2..].copy_from_slice(&trailer.to_be_bytes());
        }
        block[0] &= 0x7F;
        let result = self
            .engine
            .process_block(&block, output)
            .map_err(Iso9796d2Error::Cipher);
        self.end_message();
        result
    }

    /// BC 的 `VerifySignature`：取得 Hash(M2)，以公鑰解出區塊（或用
    /// `update_with_recovered_message` 解出的），以還原的 M1 與區塊裡的 salt 重算 H 比較，
    /// 再比對輸入的 M1；引擎拒絕或格式不對的簽章視為不符。結尾標明另一種雜湊時同樣視為
    /// 不符，同 BC。變動時間：只能用於公開值，簽章與訊息都是公開的；H 與 M1 的比較不會提早
    /// 結束。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        let state = self.verifying()?;
        let digest_size = self.digest.digest_size();
        let mut m2_hash = vec![0u8; digest_size];
        self.digest.do_final(&mut m2_hash);
        match &self.pre {
            None => {
                if self.recover(state, signature).is_err() {
                    self.end_message();
                    return Ok(false);
                }
            }
            Some(pre) if pre.signature != signature => {
                return Err(Iso9796d2Error::DifferentSignature);
            }
            Some(_) => {}
        }
        let Pre {
            block,
            start,
            trailer_length,
            ..
        } = self.pre.take().expect("recovered above");
        let recovered = self.recovered.take().expect("recovered with the block");
        self.digest
            .update(&((recovered.len() as u64) * 8).to_be_bytes());
        self.digest.update(&recovered);
        self.digest.update(&m2_hash);
        let salt_start = start + recovered.len();
        self.digest
            .update(&block[salt_start..salt_start + self.salt_length]);
        let mut hash = vec![0u8; digest_size];
        self.digest.do_final(&mut hash);
        let hash_start = block.len() - trailer_length - digest_size;
        if !fixed_time_eq(&hash, &block[hash_start..hash_start + digest_size]) {
            self.full_message = false;
            self.end_message();
            return Ok(false);
        }
        let same = self.message_length == 0
            || (self.message_length == recovered.len()
                && fixed_time_eq(&self.buffer[..self.message_length], &recovered));
        self.recovered = Some(recovered);
        self.end_message();
        Ok(same)
    }

    /// 丟掉訊息、還原結果與待驗證的簽章，保留金鑰。常數時間。
    fn reset(&mut self) {
        self.end_message();
        self.recovered = None;
        self.full_message = false;
        self.pre = None;
    }
}

impl<E, D, R> SignerWithRecovery for Iso9796d2PssSigner<E, D, R>
where
    E: AsymmetricBlockCipher,
    D: Digest,
    R: CryptoRng,
{
    /// 上次驗證是否還原出整則訊息。常數時間。
    fn has_full_message(&self) -> bool {
        self.full_message
    }

    /// 上次驗證或 `update_with_recovered_message` 還原的 M1。常數時間。
    fn recovered_message(&self) -> Option<&[u8]> {
        self.recovered.as_deref()
    }

    /// BC 的 `UpdateWithRecoveredMessage`：解出 M1，之後的 `update` 只給 M2。引擎拒絕的
    /// 簽章回傳引擎的錯誤，格式不對時回傳 `MalformedSignature`。變動時間：只能用於公開值，
    /// 簽章是公開的。
    fn update_with_recovered_message(&mut self, signature: &[u8]) -> Result<(), Self::Error> {
        let state = self.verifying()?;
        self.recover(state, signature)
    }
}
