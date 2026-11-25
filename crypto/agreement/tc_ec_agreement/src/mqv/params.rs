use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};

/// BC 的 `MqvPrivateParameters`：自己的長期私鑰、這次的臨時私鑰，以及可省略的臨時公鑰。
/// 只是容器：網域在 `init` 才檢查，省略的臨時公鑰也在那時算出；BC 在建構時做。
#[derive(Clone)]
pub struct MqvPrivateParams<C: Curve<Scalar = PaddedBigUint>> {
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    ephemeral_public_key: Option<EcPublicKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> MqvPrivateParams<C> {
    /// 臨時公鑰省略、由 `init` 算出的參數。常數時間。
    pub fn new(static_key: EcPrivateKey<C>, ephemeral_key: EcPrivateKey<C>) -> Self {
        Self {
            static_key,
            ephemeral_key,
            ephemeral_public_key: None,
        }
    }

    /// 提供已算好的臨時公鑰，省下一次乘點；不檢查它是否對應臨時私鑰，同 BC。常數時間。
    pub fn with_ephemeral_public_key(mut self, key: EcPublicKey<C>) -> Self {
        self.ephemeral_public_key = Some(key);
        self
    }

    /// 長期私鑰。常數時間。
    pub fn static_key(&self) -> &EcPrivateKey<C> {
        &self.static_key
    }

    /// 臨時私鑰。常數時間。
    pub fn ephemeral_key(&self) -> &EcPrivateKey<C> {
        &self.ephemeral_key
    }

    /// 提供的臨時公鑰；省略時為 `None`。常數時間。
    pub fn ephemeral_public_key(&self) -> Option<&EcPublicKey<C>> {
        self.ephemeral_public_key.as_ref()
    }
}

/// BC 的 `MqvPublicParameters`：對方的長期公鑰與臨時公鑰。只是容器，網域在協商時才
/// 檢查；BC 在建構時做。
#[derive(Clone)]
pub struct MqvPublicParams<C: Curve> {
    static_key: EcPublicKey<C>,
    ephemeral_key: EcPublicKey<C>,
}

impl<C: Curve> MqvPublicParams<C> {
    /// 對方的兩把公鑰。常數時間。
    pub fn new(static_key: EcPublicKey<C>, ephemeral_key: EcPublicKey<C>) -> Self {
        Self {
            static_key,
            ephemeral_key,
        }
    }

    /// 對方的長期公鑰。常數時間。
    pub fn static_key(&self) -> &EcPublicKey<C> {
        &self.static_key
    }

    /// 對方的臨時公鑰。常數時間。
    pub fn ephemeral_key(&self) -> &EcPublicKey<C> {
        &self.ephemeral_key
    }
}
