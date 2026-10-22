use tc_signer::{Signer, SignerInit};

use crate::params::AnyParams;
use crate::{AnyError, SecurityError};

// 錯誤已經換成 AnyError、參數換成 AnyParams，合成一個 trait 才能放進同一個 dyn
trait InnerAnySigner: Signer<Error = AnyError> + SignerInit<AnyParams, Error = AnyError> {}

impl<T> InnerAnySigner for T where
    T: Signer<Error = AnyError> + SignerInit<AnyParams, Error = AnyError>
{
}

type KeyOf<K> = fn(&AnyParams) -> Option<&K>;

/// 包住具體的簽章器：金鑰從 `AnyParams` 取出具體型別，錯誤換成 `AnyError`。
/// 簽章與驗章的金鑰型別可以不同（Ed25519 的私鑰與公鑰），也可以相同（RSA 由金鑰本身分辨）。
#[allow(dead_code, reason = "所有 signer 的 feature 都關掉時，沒有 signer")]
struct SignerWrapper<T, S, V> {
    signer: T,
    signing_key: KeyOf<S>,
    verifying_key: KeyOf<V>,
}

impl<T, S, V> SignerInit<AnyParams> for SignerWrapper<T, S, V>
where
    T: SignerInit<S> + SignerInit<V>,
    <T as SignerInit<S>>::Error: Send + Sync + 'static,
    <T as SignerInit<V>>::Error: Send + Sync + 'static,
{
    type Error = AnyError;

    fn init(&mut self, params: &AnyParams) -> Result<(), AnyError> {
        if let Some(key) = (self.signing_key)(params) {
            return SignerInit::<S>::init(&mut self.signer, key).map_err(AnyError::new);
        }
        let key = (self.verifying_key)(params)
            .ok_or_else(|| AnyError::new(SecurityError::WrongParams))?;
        SignerInit::<V>::init(&mut self.signer, key).map_err(AnyError::new)
    }
}

impl<T, S, V> Signer for SignerWrapper<T, S, V>
where
    T: Signer,
    <T as Signer>::Error: Send + Sync + 'static,
{
    type Error = AnyError;

    fn max_signature_size(&self) -> usize {
        self.signer.max_signature_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AnyError> {
        self.signer.update(input).map_err(AnyError::new)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AnyError> {
        self.signer
            .generate_signature(output)
            .map_err(AnyError::new)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AnyError> {
        self.signer
            .verify_signature(signature)
            .map_err(AnyError::new)
    }

    fn reset(&mut self) {
        self.signer.reset();
    }
}

/// 執行時才決定的簽章器；私鑰（簽章）與公鑰（驗章）都用 [`AnyParams`] 傳。
pub struct AnySigner(Box<dyn InnerAnySigner>);

impl AnySigner {
    // 給表用：簽章與驗章的金鑰各給一個從 AnyParams 取出具體型別的函式，種類不對時回傳 None
    #[allow(dead_code, reason = "所有 signer 的 feature 都關掉時，沒有 signer")]
    pub(super) fn new<T, S, V>(signer: T, signing_key: KeyOf<S>, verifying_key: KeyOf<V>) -> Self
    where
        T: Signer + SignerInit<S> + SignerInit<V> + 'static,
        S: 'static,
        V: 'static,
        <T as Signer>::Error: Send + Sync + 'static,
        <T as SignerInit<S>>::Error: Send + Sync + 'static,
        <T as SignerInit<V>>::Error: Send + Sync + 'static,
    {
        Self(Box::new(SignerWrapper {
            signer,
            signing_key,
            verifying_key,
        }))
    }
}

impl SignerInit<AnyParams> for AnySigner {
    type Error = AnyError;

    fn init(&mut self, params: &AnyParams) -> Result<(), AnyError> {
        self.0.init(params)
    }
}

impl Signer for AnySigner {
    type Error = AnyError;

    fn max_signature_size(&self) -> usize {
        self.0.max_signature_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), AnyError> {
        self.0.update(input)
    }

    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, AnyError> {
        self.0.generate_signature(output)
    }

    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, AnyError> {
        self.0.verify_signature(signature)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}
