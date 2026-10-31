use crate::Iso9796d2Error;
use crate::iso_trailers::{self, TRAILER_IMPLICIT, trailer_length};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Display;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::PaddedBigUint;
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_rsa::RsaKeyParams;
use tc_signer::{Signer, SignerInit, SignerWithRecovery};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `Iso9796d2Signer`：ISO/IEC 9796-2 方案 1，可還原訊息的 RSA 簽章。訊息的前段
/// 放進簽章區塊，驗證時還原出來；訊息短得放得下時整則還原。區塊是
/// 標頭 ‖ 0xBB… ‖ 0xBA ‖ 可還原的訊息 ‖ H(訊息) ‖ 結尾，結尾是雜湊的 ISO/IEC 10118 代號
/// 或隱含的 0xBC。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};
/// use tc_rsa_signer::Iso9796d2Signer;
/// use tc_sha::Sha256Digest;
/// use tc_signer::{Signer, SignerInit, SignerWithRecovery};
///
/// let mut generator = RsaKeyGenerator::new();
/// generator.init(RsaKeyGenerationParamsOwned::new(rand::rng()))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// // 短訊息整則放進簽章。
/// let mut signer = Iso9796d2Signer::new(RsaEngine::new(), Sha256Digest::default());
/// signer.init(&private_key)?;
/// signer.update(b"a short message")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// // 驗證端不必有訊息，從簽章還原。
/// let mut verifier = Iso9796d2Signer::new(RsaEngine::new(), Sha256Digest::default());
/// verifier.init(&public_key)?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// assert!(verifier.has_full_message());
/// assert_eq!(verifier.recovered_message(), Some(&b"a short message"[..]));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Iso9796d2Signer<E, D> {
    engine: E,
    digest: D,
    trailer: Option<u16>,
    digest_trailer: Option<u16>,
    state: Option<State>,
    buffer: Zeroizing<Vec<u8>>,
    message_length: usize,
    full_message: bool,
    recovered: Option<Vec<u8>>,
    pre: Option<Pre>,
}

/// `init` 定下的方向、模數位元數與區塊長度。
#[derive(Clone, Copy)]
struct State {
    signing: bool,
    key_bits: usize,
    block_length: usize,
}

/// 區塊裡可還原訊息的起訖位置，以及是否為整則訊息。
#[derive(Clone, Copy)]
struct Recoverable {
    start: usize,
    end: usize,
    full: bool,
}

/// `update_with_recovered_message` 解出的簽章與區塊，留給 `verify_signature`。
struct Pre {
    signature: Vec<u8>,
    block: Zeroizing<Vec<u8>>,
}

impl<E, D: Display> Iso9796d2Signer<E, D> {
    /// BC 的 `Iso9796d2Signer(cipher, digest)`：結尾標明雜湊的代號，依雜湊的名稱查；查不到
    /// 時 `init` 回傳 `NoTrailer`。變動時間：只能用於公開值，名稱是公開的。
    pub fn new(engine: E, digest: D) -> Self {
        let digest_trailer = iso_trailers::trailer(&digest.to_string());
        Self::with_trailer(engine, digest, digest_trailer, digest_trailer)
    }

    /// BC 的 `Iso9796d2Signer(cipher, digest, true)`：隱含結尾 0xBC。驗證時仍接受標明這個
    /// 雜湊代號的簽章，同 BC。變動時間：只能用於公開值，名稱是公開的。
    pub fn implicit(engine: E, digest: D) -> Self {
        let digest_trailer = iso_trailers::trailer(&digest.to_string());
        Self::with_trailer(engine, digest, Some(TRAILER_IMPLICIT), digest_trailer)
    }

    /// 以簽章用的結尾與雜湊的代號建構。常數時間。
    fn with_trailer(
        engine: E,
        digest: D,
        trailer: Option<u16>,
        digest_trailer: Option<u16>,
    ) -> Self {
        Self {
            engine,
            digest,
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

impl<E: AsymmetricBlockCipher, D: Digest> Iso9796d2Signer<E, D> {
    /// 丟掉訊息、還原結果與待驗證的簽章。常數時間。
    fn clear(&mut self) {
        self.digest.reset();
        self.message_length = 0;
        self.buffer.zeroize();
        self.recovered = None;
        self.full_message = false;
        self.pre = None;
    }

    /// 一則訊息驗證完：清掉訊息與雜湊。常數時間。
    fn end_message(&mut self) {
        self.digest.reset();
        self.message_length = 0;
        self.buffer.zeroize();
    }

    /// 驗證失敗時結束這則訊息並回傳 `false`。常數時間。
    fn fail(&mut self) -> bool {
        self.end_message();
        false
    }

    /// 解析區塊：檢查標頭與結尾，回傳可還原訊息的起訖位置與是否為整則訊息；格式不對時
    /// 回傳 `None`。變動時間：只能用於公開值，區塊來自公開的簽章。
    fn parse(&self, block: &[u8]) -> Result<Option<Recoverable>, Iso9796d2Error<E::Error>> {
        let length = block.len();
        if length < 2 || block[0] & 0xC0 != 0x40 || block[length - 1] & 0x0F != 0x0C {
            return Ok(None);
        }
        let delta = trailer_length(block, self.digest_trailer)?;
        let start = block
            .iter()
            .position(|byte| byte & 0x0F == 0x0A)
            .unwrap_or(length)
            + 1;
        let end = length as isize - delta as isize - self.digest.digest_size() as isize;
        if end - start as isize <= 0 {
            return Ok(None);
        }
        Ok(Some(Recoverable {
            start,
            end: end as usize,
            full: block[0] & 0x20 == 0,
        }))
    }

    /// BC 的 `IsSameAs`：輸入的訊息前段與還原的訊息是否相同；比較不會提早結束。變動時間：
    /// 只能用於公開值，長度是公開的。
    fn is_same_as(&self, recovered: &[u8]) -> bool {
        let length = if self.message_length > self.buffer.len() {
            if self.buffer.len() > recovered.len() {
                return false;
            }
            self.buffer.len()
        } else {
            if self.message_length != recovered.len() {
                return false;
            }
            recovered.len()
        };
        fixed_time_eq(&self.buffer[..length], &recovered[..length])
    }

    /// 回傳已初始化為驗證的狀態。常數時間。
    fn verifying(&self) -> Result<State, Iso9796d2Error<E::Error>> {
        let state = self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        if state.signing {
            return Err(Iso9796d2Error::NotForVerifying);
        }
        Ok(state)
    }
}

impl<E, D, P> SignerInit<P> for Iso9796d2Signer<E, D>
where
    E: AsymmetricBlockCipher + AsymmetricBlockCipherInit<P>,
    D: Digest,
    P: RsaKeyParams<PaddedBigUint> + ?Sized,
{
    type Error = Iso9796d2Error<<E as AsymmetricBlockCipherInit<P>>::Error>;

    /// BC 的 `Init`：私鑰簽章、公鑰驗證，丟掉先前的訊息；雜湊沒有代號時回傳 `NoTrailer`，
    /// 模數放不下雜湊與結尾時回傳 `KeyTooSmall`。失敗時維持未初始化。變動時間：只依公開
    /// 的模數分支；引擎的 `init` 另計。
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
        let key_bits = params.modulus().bits() as usize;
        let block_length = key_bits.div_ceil(8);
        let trailer_length = if trailer == TRAILER_IMPLICIT { 1 } else { 2 };
        let buffer_length = block_length
            .checked_sub(self.digest.digest_size() + 1 + trailer_length)
            .ok_or(Iso9796d2Error::KeyTooSmall)?;
        self.buffer = Zeroizing::new(vec![0; buffer_length]);
        self.digest.reset();
        self.message_length = 0;
        self.recovered = None;
        self.full_message = false;
        self.pre = None;
        self.state = Some(State {
            signing,
            key_bits,
            block_length,
        });
        Ok(())
    }
}

impl<E, D> Signer for Iso9796d2Signer<E, D>
where
    E: AsymmetricBlockCipher,
    D: Digest,
{
    type Error = Iso9796d2Error<E::Error>;

    /// 模數的位元組數。`init` 之前呼叫會 panic。常數時間。
    fn max_signature_size(&self) -> usize {
        self.state.expect("the signer is initialized");
        self.engine.output_block_size()
    }

    /// 把 `input` 加進雜湊，放得下的前段另存起來放進簽章。`init` 之前回傳錯誤。常數時間
    /// 程度同雜湊：只依長度分支與複製。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        self.digest.update(input);
        let start = self.message_length.min(self.buffer.len());
        let stored = (self.buffer.len() - start).min(input.len());
        self.buffer[start..start + stored].copy_from_slice(&input[..stored]);
        self.message_length += input.len();
        Ok(())
    }

    /// BC 的 `GenerateSignature`：訊息放得下時整則放進區塊（標頭 0x40），否則放前段
    /// （標頭 0x60），以私鑰運算。以公鑰初始化時回傳錯誤。常數時間程度同引擎：編碼只依
    /// 長度分支與複製。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let state = self.state.ok_or(Iso9796d2Error::NotInitialized)?;
        if !state.signing {
            return Err(Iso9796d2Error::NotForSigning);
        }
        let trailer = self.trailer.expect("init checked the trailer");
        let digest_size = self.digest.digest_size();
        let length = state.block_length;
        let mut block = Zeroizing::new(vec![0u8; length]);
        let (trailer_bits, mut delta) = if trailer == TRAILER_IMPLICIT {
            block[length - 1] = TRAILER_IMPLICIT as u8;
            (8, length - digest_size - 1)
        } else {
            block[length - 2..].copy_from_slice(&trailer.to_be_bytes());
            (16, length - digest_size - 2)
        };
        self.digest.do_final(&mut block[delta..delta + digest_size]);

        let message_length = self.message_length;
        let excess = ((digest_size + message_length) * 8 + trailer_bits + 4) as isize
            - state.key_bits as isize;
        let header = if excess > 0 {
            let recoverable = message_length
                .checked_sub((excess as usize).div_ceil(8))
                .ok_or(Iso9796d2Error::KeyTooSmall)?;
            delta -= recoverable;
            block[delta..delta + recoverable].copy_from_slice(&self.buffer[..recoverable]);
            0x60
        } else {
            delta -= message_length;
            block[delta..delta + message_length].copy_from_slice(&self.buffer[..message_length]);
            0x40
        };
        if delta > 1 {
            block[1..delta - 1].fill(0xbb);
            block[delta - 1] = 0xba;
            block[0] = 0x0b | header;
        } else {
            block[0] = 0x0a | header;
        }
        let result = self
            .engine
            .process_block(&block, output)
            .map_err(Iso9796d2Error::Cipher);
        self.message_length = 0;
        self.buffer.zeroize();
        result
    }

    /// BC 的 `VerifySignature`：以公鑰還原區塊（或用 `update_with_recovered_message` 解出
    /// 的），檢查標頭、結尾與雜湊，再比對輸入的訊息前段；引擎拒絕或格式不對的簽章視為
    /// 不符。結尾標明另一種雜湊時回傳錯誤，同 BC。變動時間：只能用於公開值，簽章與訊息都是
    /// 公開的；雜湊的比較不會提早結束。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        self.verifying()?;
        if self
            .pre
            .as_ref()
            .is_some_and(|pre| pre.signature != signature)
        {
            return Err(Iso9796d2Error::DifferentSignature);
        }
        let block = match self.pre.take() {
            Some(pre) => pre.block,
            None => {
                let mut raw = Zeroizing::new(vec![0u8; self.engine.output_block_size()]);
                let Ok(written) = self.engine.process_block(signature, &mut raw) else {
                    return Ok(self.fail());
                };
                raw.truncate(written);
                raw
            }
        };
        let Some(Recoverable { start, end, full }) = self.parse(&block)? else {
            return Ok(self.fail());
        };
        self.full_message = full;
        let digest_size = self.digest.digest_size();
        let mut hash = vec![0u8; digest_size];
        if full {
            if self.message_length > end - start {
                return Ok(self.fail());
            }
            self.digest.reset();
            self.digest.update(&block[start..end]);
        }
        self.digest.do_final(&mut hash);
        if !fixed_time_eq(&hash, &block[end..end + digest_size]) {
            return Ok(self.fail());
        }
        let recovered = block[start..end].to_vec();
        let same = self.message_length == 0 || self.is_same_as(&recovered);
        self.recovered = Some(recovered);
        if !same {
            return Ok(self.fail());
        }
        self.end_message();
        Ok(true)
    }

    /// 丟掉訊息、還原結果與待驗證的簽章，保留金鑰。常數時間。
    fn reset(&mut self) {
        self.clear();
    }
}

impl<E, D> SignerWithRecovery for Iso9796d2Signer<E, D>
where
    E: AsymmetricBlockCipher,
    D: Digest,
{
    /// 上次驗證是否還原出整則訊息。常數時間。
    fn has_full_message(&self) -> bool {
        self.full_message
    }

    /// 上次驗證或 `update_with_recovered_message` 還原的訊息。常數時間。
    fn recovered_message(&self) -> Option<&[u8]> {
        self.recovered.as_deref()
    }

    /// BC 的 `UpdateWithRecoveredMessage`：以公鑰解出區塊，把可還原的訊息加進雜湊，之後的
    /// `update` 只需給其餘的訊息。引擎拒絕的簽章回傳引擎的錯誤，格式不對時回傳
    /// `MalformedSignature`。變動時間：只能用於公開值，簽章是公開的。
    fn update_with_recovered_message(&mut self, signature: &[u8]) -> Result<(), Self::Error> {
        self.verifying()?;
        let mut block = Zeroizing::new(vec![0u8; self.engine.output_block_size()]);
        let written = self
            .engine
            .process_block(signature, &mut block)
            .map_err(Iso9796d2Error::Cipher)?;
        block.truncate(written);
        let Recoverable { start, end, full } = self
            .parse(&block)?
            .ok_or(Iso9796d2Error::MalformedSignature)?;
        let recovered = block[start..end].to_vec();
        self.digest.update(&recovered);
        self.message_length = recovered.len();
        let stored = recovered.len().min(self.buffer.len());
        self.buffer[..stored].copy_from_slice(&recovered[..stored]);
        self.full_message = full;
        self.recovered = Some(recovered);
        self.pre = Some(Pre {
            signature: signature.to_vec(),
            block,
        });
        Ok(())
    }
}
