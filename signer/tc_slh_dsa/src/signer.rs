use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use rand_core::CryptoRng;
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;
use tc_sha::{Sha256Digest, Sha512Digest};
use tc_signer::{Signer, SignerInit};
use tc_zeroize::Zeroize;

use crate::params::Family;
use crate::{SlhDsaError, SlhDsaParameters, SlhDsaPrivateKey, SlhDsaPublicKey, engine};

/// 不取亂數的確定性簽章，BC 的 `deterministic = true`：opt_rand 是 PK.seed。
#[derive(Clone, Copy, Debug, Default)]
pub struct Deterministic;

mod sealed {
    pub trait Randomness {
        fn fill(&mut self, opt_rand: &mut [u8]) -> bool;
    }
}

use sealed::Randomness;

impl<R: CryptoRng> Randomness for R {
    fn fill(&mut self, opt_rand: &mut [u8]) -> bool {
        self.fill_bytes(opt_rand);
        true
    }
}

impl Randomness for Deterministic {
    fn fill(&mut self, _: &mut [u8]) -> bool {
        false
    }
}

enum Key {
    Private(Box<SlhDsaPrivateKey>),
    Public(SlhDsaPublicKey),
}

impl Key {
    fn params(&self) -> SlhDsaParameters {
        match self {
            Self::Private(key) => key.params(),
            Self::Public(key) => key.params(),
        }
    }
}

/// 兩種 signer 共用的部分：參數組、亂數、情境字串、金鑰與 M′。SLH-DSA 要讀兩次訊息，所以整個
/// 留在記憶體裡，同 BC。
struct Core<R> {
    params: SlhDsaParameters,
    rng: R,
    context: Vec<u8>,
    key: Option<Key>,
    buffer: Vec<u8>,
    prefix: usize,
}

impl<R: Randomness> Core<R> {
    fn new(params: SlhDsaParameters, rng: R) -> Self {
        Self {
            params,
            rng,
            context: Vec::new(),
            key: None,
            buffer: Vec::new(),
            prefix: 0,
        }
    }

    fn set_context(&mut self, context: &[u8]) -> Result<(), SlhDsaError> {
        if context.len() > 255 {
            return Err(SlhDsaError::ContextTooLong);
        }
        self.context = context.to_vec();
        Ok(())
    }

    // M′ starts with domain ‖ |ctx| ‖ ctx, and an OID for HashSLH-DSA
    fn init(&mut self, key: Key, domain: u8, oid: &[u8]) -> Result<(), SlhDsaError> {
        self.key = None;
        self.buffer.clear();
        if key.params() != self.params {
            return Err(SlhDsaError::ParameterMismatch);
        }
        self.key = Some(key);
        self.buffer.push(domain);
        self.buffer.push(self.context.len() as u8);
        self.buffer.extend_from_slice(&self.context);
        self.buffer.extend_from_slice(oid);
        self.prefix = self.buffer.len();
        Ok(())
    }

    fn reset(&mut self) {
        self.buffer[self.prefix..].zeroize();
        self.buffer.truncate(self.prefix);
    }

    fn sign(&mut self, output: &mut [u8]) -> Result<usize, SlhDsaError> {
        let key = match &self.key {
            None => return Err(SlhDsaError::NotInitialized),
            Some(Key::Public(_)) => return Err(SlhDsaError::NotForSigning),
            Some(Key::Private(key)) => key,
        };
        let length = self.params.signature_length();
        let output = output
            .get_mut(..length)
            .ok_or(SlhDsaError::OutputTooShort)?;
        let n = self.params.n();
        let mut opt_rand = [0u8; 32];
        if !self.rng.fill(&mut opt_rand[..n]) {
            opt_rand[..n].copy_from_slice(&key.public_key().encoding()[..n]);
        }
        engine::sign(key, &self.buffer, &opt_rand[..n], output);
        opt_rand.zeroize();
        self.reset();
        Ok(length)
    }

    fn verify(&mut self, signature: &[u8]) -> Result<bool, SlhDsaError> {
        let key = match &self.key {
            None => return Err(SlhDsaError::NotInitialized),
            Some(Key::Private(_)) => return Err(SlhDsaError::NotForVerification),
            Some(Key::Public(key)) => key,
        };
        let result = engine::verify(key, &self.buffer, signature);
        self.reset();
        Ok(result)
    }
}

/// BC 的 `SlhDsaSigner`：純 SLH-DSA（FIPS 205 的 slh_sign 與 slh_verify）。私鑰簽章、公鑰驗章；
/// `R` 是對沖簽章用的亂數來源，或 [`Deterministic`]。
///
/// 簽章對 SK.seed 與 SK.prf 是常數時間：只用雜湊，走訪的樹節點由公開的訊息摘要決定。驗章是
/// 變動時間，只處理公開值。
pub struct SlhDsaSigner<R> {
    core: Core<R>,
}

impl<R: CryptoRng> SlhDsaSigner<R> {
    /// 以 `rng` 取每個簽章的 opt_rand，BC 的 `deterministic = false`。常數時間。
    pub fn new(params: SlhDsaParameters, rng: R) -> Self {
        Self {
            core: Core::new(params, rng),
        }
    }
}

impl SlhDsaSigner<Deterministic> {
    /// opt_rand 用 PK.seed，BC 的 `deterministic = true`。常數時間。
    pub fn deterministic(params: SlhDsaParameters) -> Self {
        Self {
            core: Core::new(params, Deterministic),
        }
    }
}

impl<R: Randomness> SlhDsaSigner<R> {
    /// 情境字串，最長 255 bytes，BC 的 `ParametersWithContext`；在 `init` 之前設定。常數時間。
    pub fn set_context(&mut self, context: &[u8]) -> Result<(), SlhDsaError> {
        self.core.set_context(context)
    }
}

impl<R: Randomness> SignerInit<SlhDsaPrivateKey> for SlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 以私鑰準備簽章。參數組不同時是 `ParameterMismatch`。常數時間。
    fn init(&mut self, key: &SlhDsaPrivateKey) -> Result<(), SlhDsaError> {
        self.core.init(Key::Private(Box::new(key.clone())), 0, &[])
    }
}

impl<R: Randomness> SignerInit<SlhDsaPublicKey> for SlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 以公鑰準備驗章。參數組不同時是 `ParameterMismatch`。常數時間。
    fn init(&mut self, key: &SlhDsaPublicKey) -> Result<(), SlhDsaError> {
        self.core.init(Key::Public(key.clone()), 0, &[])
    }
}

impl<R: Randomness> Signer for SlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 簽章的位元組數。常數時間。
    fn max_signature_size(&self) -> usize {
        self.core.params.signature_length()
    }

    /// 把訊息接在 M′ 後面。常數時間。
    fn update(&mut self, input: &[u8]) -> Result<(), SlhDsaError> {
        if self.core.key.is_none() {
            return Err(SlhDsaError::NotInitialized);
        }
        self.core.buffer.extend_from_slice(input);
        Ok(())
    }

    /// 簽章並重新開始。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, SlhDsaError> {
        self.core.sign(output)
    }

    /// 驗章並重新開始。變動時間：只能用於公開值。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, SlhDsaError> {
        self.core.verify(signature)
    }

    /// 捨棄訊息、保留金鑰。常數時間。
    fn reset(&mut self) {
        if self.core.key.is_some() {
            self.core.reset();
        }
    }
}

// The DER of the OIDs under 2.16.840.1.101.3.4.2
fn hash_oid(last: u8) -> [u8; 11] {
    [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last,
    ]
}

#[derive(Clone)]
enum PreHash {
    Sha256(Sha256Digest),
    Sha512(Sha512Digest),
    Shake128(ShakeDigest),
    Shake256(ShakeDigest),
}

impl PreHash {
    // As BC pairs them: SHA-256 or SHAKE128 for n = 16, SHA-512 or SHAKE256 above
    fn for_params(params: SlhDsaParameters) -> Self {
        match (params.family(), params.n() == 16) {
            (Family::Sha2, true) => Self::Sha256(Sha256Digest::new()),
            (Family::Sha2, false) => Self::Sha512(Sha512Digest::new()),
            (Family::Shake, true) => Self::Shake128(ShakeDigest::new(128)),
            (Family::Shake, false) => Self::Shake256(ShakeDigest::new(256)),
        }
    }

    fn oid(&self) -> [u8; 11] {
        hash_oid(match self {
            Self::Sha256(_) => 0x01,
            Self::Sha512(_) => 0x03,
            Self::Shake128(_) => 0x0b,
            Self::Shake256(_) => 0x0c,
        })
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Sha256(_) => "SHA256",
            Self::Sha512(_) => "SHA512",
            Self::Shake128(_) => "SHAKE128",
            Self::Shake256(_) => "SHAKE256",
        }
    }

    fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha256(digest) => digest.update(input),
            Self::Sha512(digest) => digest.update(input),
            Self::Shake128(digest) | Self::Shake256(digest) => digest.update(input),
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Sha256(digest) => digest.reset(),
            Self::Sha512(digest) => digest.reset(),
            Self::Shake128(digest) | Self::Shake256(digest) => digest.reset(),
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        match self {
            Self::Sha256(digest) => {
                let mut out = vec![0u8; 32];
                digest.do_final(&mut out);
                out
            }
            Self::Sha512(digest) => {
                let mut out = vec![0u8; 64];
                digest.do_final(&mut out);
                out
            }
            Self::Shake128(digest) => {
                let mut out = vec![0u8; 32];
                digest.output_final(&mut out);
                out
            }
            Self::Shake256(digest) => {
                let mut out = vec![0u8; 64];
                digest.output_final(&mut out);
                out
            }
        }
    }
}

/// BC 的 `HashSlhDsaSigner`：HashSLH-DSA，訊息先雜湊，雜湊依 BC 的配對：SHA2 的 128 位元參數組
/// 用 SHA-256、其他用 SHA-512，SHAKE 的 128 位元參數組用 SHAKE128、其他用 SHAKE256。時間性質同
/// [`SlhDsaSigner`]。
pub struct HashSlhDsaSigner<R> {
    core: Core<R>,
    pre_hash: PreHash,
}

impl<R: CryptoRng> HashSlhDsaSigner<R> {
    /// 以 `rng` 取每個簽章的 opt_rand。常數時間。
    pub fn new(params: SlhDsaParameters, rng: R) -> Self {
        Self {
            core: Core::new(params, rng),
            pre_hash: PreHash::for_params(params),
        }
    }
}

impl HashSlhDsaSigner<Deterministic> {
    /// opt_rand 用 PK.seed。常數時間。
    pub fn deterministic(params: SlhDsaParameters) -> Self {
        Self {
            core: Core::new(params, Deterministic),
            pre_hash: PreHash::for_params(params),
        }
    }
}

impl<R: Randomness> HashSlhDsaSigner<R> {
    /// 情境字串，最長 255 bytes；在 `init` 之前設定。常數時間。
    pub fn set_context(&mut self, context: &[u8]) -> Result<(), SlhDsaError> {
        self.core.set_context(context)
    }

    /// BC 的名稱，例如 "SLH-DSA-SHA2-128s-WITH-SHA256"。常數時間。
    pub fn name(&self) -> alloc::string::String {
        alloc::format!("{}-WITH-{}", self.core.params.name(), self.pre_hash.name())
    }

    fn init_with(&mut self, key: Key) -> Result<(), SlhDsaError> {
        self.pre_hash.reset();
        let oid = self.pre_hash.oid();
        self.core.init(key, 1, &oid)
    }

    fn finish(&mut self) -> Result<(), SlhDsaError> {
        if self.core.key.is_none() {
            return Err(SlhDsaError::NotInitialized);
        }
        let hash = self.pre_hash.finish();
        self.core.buffer.truncate(self.core.prefix);
        self.core.buffer.extend_from_slice(&hash);
        Ok(())
    }
}

impl<R: Randomness> SignerInit<SlhDsaPrivateKey> for HashSlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 以私鑰準備簽章。常數時間。
    fn init(&mut self, key: &SlhDsaPrivateKey) -> Result<(), SlhDsaError> {
        self.init_with(Key::Private(Box::new(key.clone())))
    }
}

impl<R: Randomness> SignerInit<SlhDsaPublicKey> for HashSlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 以公鑰準備驗章。常數時間。
    fn init(&mut self, key: &SlhDsaPublicKey) -> Result<(), SlhDsaError> {
        self.init_with(Key::Public(key.clone()))
    }
}

impl<R: Randomness> Signer for HashSlhDsaSigner<R> {
    type Error = SlhDsaError;

    /// 簽章的位元組數。常數時間。
    fn max_signature_size(&self) -> usize {
        self.core.params.signature_length()
    }

    /// 加入訊息。常數時間。
    fn update(&mut self, input: &[u8]) -> Result<(), SlhDsaError> {
        if self.core.key.is_none() {
            return Err(SlhDsaError::NotInitialized);
        }
        self.pre_hash.update(input);
        Ok(())
    }

    /// 簽章並重新開始。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, SlhDsaError> {
        self.finish()?;
        self.core.sign(output)
    }

    /// 驗章並重新開始。變動時間：只能用於公開值。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, SlhDsaError> {
        self.finish()?;
        self.core.verify(signature)
    }

    /// 捨棄訊息、保留金鑰。常數時間。
    fn reset(&mut self) {
        self.pre_hash.reset();
    }
}
