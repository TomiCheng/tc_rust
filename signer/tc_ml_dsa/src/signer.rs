use alloc::vec::Vec;

use rand_core::CryptoRng;
use tc_digest::Digest;
use tc_keccak::ShakeDigest;
use tc_sha::Sha512Digest;
use tc_signer::{Signer, SignerInit};
use tc_zeroize::Zeroize;

use crate::engine;
use crate::{MlDsaError, MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey};

// DER of id-sha512, 2.16.840.1.101.3.4.2.3
const SHA512_OID: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];

/// 不取亂數的確定性簽章，BC 的 `deterministic = true`：rnd 固定為 32 個零。
#[derive(Clone, Copy, Debug, Default)]
pub struct Deterministic;

mod sealed {
    pub trait Randomness {
        fn fill(&mut self, rnd: &mut [u8; 32]);
    }
}

use sealed::Randomness;

impl<R: CryptoRng> Randomness for R {
    fn fill(&mut self, rnd: &mut [u8; 32]) {
        self.fill_bytes(rnd);
    }
}

impl Randomness for Deterministic {
    fn fill(&mut self, rnd: &mut [u8; 32]) {
        rnd.fill(0);
    }
}

enum Key {
    Private(alloc::boxed::Box<MlDsaPrivateKey>),
    Public(MlDsaPublicKey),
}

impl Key {
    fn params(&self) -> MlDsaParameters {
        match self {
            Self::Private(key) => key.params(),
            Self::Public(key) => key.params(),
        }
    }

    fn tr(&self) -> [u8; 64] {
        match self {
            Self::Private(key) => key.material().tr,
            Self::Public(key) => key.hash(),
        }
    }
}

/// 兩種 signer 共用的部分：參數組、亂數、情境字串與金鑰。
struct Core<R> {
    params: MlDsaParameters,
    rng: R,
    context: Vec<u8>,
    key: Option<Key>,
}

impl<R: Randomness> Core<R> {
    fn new(params: MlDsaParameters, rng: R) -> Self {
        Self {
            params,
            rng,
            context: Vec::new(),
            key: None,
        }
    }

    fn set_context(&mut self, context: &[u8]) -> Result<(), MlDsaError> {
        if context.len() > 255 {
            return Err(MlDsaError::ContextTooLong);
        }
        self.context = context.to_vec();
        Ok(())
    }

    fn init(&mut self, key: Key) -> Result<(), MlDsaError> {
        self.key = None;
        if key.params() != self.params {
            return Err(MlDsaError::ParameterMismatch);
        }
        self.key = Some(key);
        Ok(())
    }

    // tr ‖ domain ‖ |ctx| ‖ ctx
    fn begin(&self, domain: u8) -> Result<ShakeDigest, MlDsaError> {
        let key = self.key.as_ref().ok_or(MlDsaError::NotInitialized)?;
        let mut digest = ShakeDigest::new(256);
        digest.update(&key.tr());
        digest.update(&[domain, self.context.len() as u8]);
        digest.update(&self.context);
        Ok(digest)
    }

    fn sign(&mut self, digest: ShakeDigest, output: &mut [u8]) -> Result<usize, MlDsaError> {
        let Some(Key::Private(key)) = &self.key else {
            return Err(match self.key {
                None => MlDsaError::NotInitialized,
                Some(_) => MlDsaError::NotForSigning,
            });
        };
        let length = self.params.signature_length();
        let output = output.get_mut(..length).ok_or(MlDsaError::OutputTooShort)?;
        let mut rnd = [0u8; 32];
        self.rng.fill(&mut rnd);
        let result = engine::sign(&self.params, digest, key.material(), &rnd, output);
        rnd.zeroize();
        result.map(|()| length)
    }

    fn verify(&self, digest: ShakeDigest, signature: &[u8]) -> Result<bool, MlDsaError> {
        let Some(Key::Public(key)) = &self.key else {
            return Err(match self.key {
                None => MlDsaError::NotInitialized,
                Some(_) => MlDsaError::NotForVerification,
            });
        };
        Ok(engine::verify(
            &self.params,
            digest,
            key.rho(),
            key.t1(),
            signature,
        ))
    }
}

/// BC 的 `MLDsaSigner`：純 ML-DSA（FIPS 204 的 ML-DSA.Sign 與 ML-DSA.Verify）。私鑰簽章、公鑰
/// 驗章；`R` 是對沖簽章用的亂數來源，或 [`Deterministic`]。
///
/// 簽章的拒絕取樣圈數依秘密而定，FIPS 204 本身如此；其餘對秘密是常數時間。驗章是變動時間，
/// 只處理公開值。
pub struct MlDsaSigner<R> {
    core: Core<R>,
    digest: Option<ShakeDigest>,
}

impl<R: CryptoRng> MlDsaSigner<R> {
    /// 以 `rng` 取每個簽章的 rnd，BC 的 `deterministic = false`。常數時間。
    pub fn new(params: MlDsaParameters, rng: R) -> Self {
        Self {
            core: Core::new(params, rng),
            digest: None,
        }
    }
}

impl MlDsaSigner<Deterministic> {
    /// rnd 固定為零，BC 的 `deterministic = true`。常數時間。
    pub fn deterministic(params: MlDsaParameters) -> Self {
        Self {
            core: Core::new(params, Deterministic),
            digest: None,
        }
    }
}

impl<R: Randomness> MlDsaSigner<R> {
    /// 情境字串，最長 255 bytes，BC 的 `ParametersWithContext`；在 `init` 之前設定。常數時間。
    pub fn set_context(&mut self, context: &[u8]) -> Result<(), MlDsaError> {
        self.core.set_context(context)
    }

    fn start(&mut self) -> Result<(), MlDsaError> {
        self.digest = Some(self.core.begin(0)?);
        Ok(())
    }
}

impl<R: Randomness> SignerInit<MlDsaPrivateKey> for MlDsaSigner<R> {
    type Error = MlDsaError;

    /// 以私鑰準備簽章。參數組不同時是 `ParameterMismatch`。常數時間。
    fn init(&mut self, key: &MlDsaPrivateKey) -> Result<(), MlDsaError> {
        self.digest = None;
        self.core
            .init(Key::Private(alloc::boxed::Box::new(key.clone())))?;
        self.start()
    }
}

impl<R: Randomness> SignerInit<MlDsaPublicKey> for MlDsaSigner<R> {
    type Error = MlDsaError;

    /// 以公鑰準備驗章。參數組不同時是 `ParameterMismatch`。常數時間。
    fn init(&mut self, key: &MlDsaPublicKey) -> Result<(), MlDsaError> {
        self.digest = None;
        self.core.init(Key::Public(key.clone()))?;
        self.start()
    }
}

impl<R: Randomness> Signer for MlDsaSigner<R> {
    type Error = MlDsaError;

    /// 簽章的位元組數。常數時間。
    fn max_signature_size(&self) -> usize {
        self.core.params.signature_length()
    }

    /// 加入訊息。常數時間。
    fn update(&mut self, input: &[u8]) -> Result<(), MlDsaError> {
        self.digest
            .as_mut()
            .ok_or(MlDsaError::NotInitialized)?
            .update(input);
        Ok(())
    }

    /// 簽章並重新開始。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, MlDsaError> {
        let digest = self.digest.take().ok_or(MlDsaError::NotInitialized)?;
        let result = self.core.sign(digest, output);
        self.start()?;
        result
    }

    /// 驗章並重新開始。變動時間：只能用於公開值。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, MlDsaError> {
        let digest = self.digest.take().ok_or(MlDsaError::NotInitialized)?;
        let result = self.core.verify(digest, signature);
        self.start()?;
        result
    }

    /// 捨棄訊息、保留金鑰。常數時間。
    fn reset(&mut self) {
        let _ = self.start();
    }
}

/// BC 的 `HashMLDsaSigner`：HashML-DSA，訊息先以 SHA-512 雜湊（FIPS 204 的 HashML-DSA.Sign 與
/// HashML-DSA.Verify），名稱如 "ML-DSA-44-WITH-SHA512"。時間性質同 [`MlDsaSigner`]。
pub struct HashMlDsaSigner<R> {
    core: Core<R>,
    pre_hash: Sha512Digest,
}

impl<R: CryptoRng> HashMlDsaSigner<R> {
    /// 以 `rng` 取每個簽章的 rnd。常數時間。
    pub fn new(params: MlDsaParameters, rng: R) -> Self {
        Self {
            core: Core::new(params, rng),
            pre_hash: Sha512Digest::new(),
        }
    }
}

impl HashMlDsaSigner<Deterministic> {
    /// rnd 固定為零。常數時間。
    pub fn deterministic(params: MlDsaParameters) -> Self {
        Self {
            core: Core::new(params, Deterministic),
            pre_hash: Sha512Digest::new(),
        }
    }
}

impl<R: Randomness> HashMlDsaSigner<R> {
    /// 情境字串，最長 255 bytes；在 `init` 之前設定。常數時間。
    pub fn set_context(&mut self, context: &[u8]) -> Result<(), MlDsaError> {
        self.core.set_context(context)
    }

    /// BC 的名稱，例如 "ML-DSA-65-WITH-SHA512"。常數時間。
    pub fn name(&self) -> alloc::string::String {
        alloc::format!("{}-WITH-SHA512", self.core.params.name())
    }

    // tr ‖ 1 ‖ |ctx| ‖ ctx ‖ OID ‖ SHA-512(M)
    fn finish(&mut self) -> Result<ShakeDigest, MlDsaError> {
        let mut digest = self.core.begin(1)?;
        digest.update(&SHA512_OID);
        let mut hash = [0u8; 64];
        self.pre_hash.do_final(&mut hash);
        digest.update(&hash);
        Ok(digest)
    }
}

impl<R: Randomness> SignerInit<MlDsaPrivateKey> for HashMlDsaSigner<R> {
    type Error = MlDsaError;

    /// 以私鑰準備簽章。常數時間。
    fn init(&mut self, key: &MlDsaPrivateKey) -> Result<(), MlDsaError> {
        self.pre_hash.reset();
        self.core
            .init(Key::Private(alloc::boxed::Box::new(key.clone())))
    }
}

impl<R: Randomness> SignerInit<MlDsaPublicKey> for HashMlDsaSigner<R> {
    type Error = MlDsaError;

    /// 以公鑰準備驗章。常數時間。
    fn init(&mut self, key: &MlDsaPublicKey) -> Result<(), MlDsaError> {
        self.pre_hash.reset();
        self.core.init(Key::Public(key.clone()))
    }
}

impl<R: Randomness> Signer for HashMlDsaSigner<R> {
    type Error = MlDsaError;

    /// 簽章的位元組數。常數時間。
    fn max_signature_size(&self) -> usize {
        self.core.params.signature_length()
    }

    /// 加入訊息。常數時間。
    fn update(&mut self, input: &[u8]) -> Result<(), MlDsaError> {
        if self.core.key.is_none() {
            return Err(MlDsaError::NotInitialized);
        }
        self.pre_hash.update(input);
        Ok(())
    }

    /// 簽章並重新開始。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, MlDsaError> {
        let digest = self.finish()?;
        self.core.sign(digest, output)
    }

    /// 驗章並重新開始。變動時間：只能用於公開值。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, MlDsaError> {
        let digest = self.finish()?;
        self.core.verify(digest, signature)
    }

    /// 捨棄訊息、保留金鑰。常數時間。
    fn reset(&mut self) {
        self.pre_hash.reset();
    }
}
