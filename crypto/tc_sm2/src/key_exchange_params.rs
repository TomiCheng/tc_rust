use crate::Sm2Curve;
use alloc::vec::Vec;
use tc_ec_key::{EcPrivateKey, EcPublicKey};

/// BC 的 `SM2KeyExchangePrivateParameters`，加上 `ParametersWithID` 的使用者 ID：是否為
/// 發起方、自己的長期私鑰與這次的臨時私鑰。只是容器，`Sm2KeyExchange::init` 才檢查；
/// BC 在建構時算出兩把公鑰點，這裡在 `init` 時算。
#[derive(Clone)]
pub struct Sm2KeyExchangePrivateParams<C: Sm2Curve> {
    initiator: bool,
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    user_id: Vec<u8>,
}

impl<C: Sm2Curve> Sm2KeyExchangePrivateParams<C> {
    /// 使用者 ID 為空的參數，同 BC 不包 `ParametersWithID` 時。常數時間。
    pub fn new(
        initiator: bool,
        static_key: EcPrivateKey<C>,
        ephemeral_key: EcPrivateKey<C>,
    ) -> Self {
        Self {
            initiator,
            static_key,
            ephemeral_key,
            user_id: Vec::new(),
        }
    }

    /// 設定自己的使用者 ID。常數時間。
    pub fn with_user_id(mut self, user_id: Vec<u8>) -> Self {
        self.user_id = user_id;
        self
    }

    /// 是否為發起方。常數時間。
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }

    /// 長期私鑰。常數時間。
    pub fn static_key(&self) -> &EcPrivateKey<C> {
        &self.static_key
    }

    /// 臨時私鑰。常數時間。
    pub fn ephemeral_key(&self) -> &EcPrivateKey<C> {
        &self.ephemeral_key
    }

    /// 自己的使用者 ID。常數時間。
    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }
}

/// BC 的 `SM2KeyExchangePublicParameters`，加上 `ParametersWithID` 的使用者 ID：對方的長期
/// 公鑰與臨時公鑰。只是容器，計算時才檢查。
#[derive(Clone)]
pub struct Sm2KeyExchangePublicParams<C: Sm2Curve> {
    static_key: EcPublicKey<C>,
    ephemeral_key: EcPublicKey<C>,
    user_id: Vec<u8>,
}

impl<C: Sm2Curve> Sm2KeyExchangePublicParams<C> {
    /// 使用者 ID 為空的參數。常數時間。
    pub fn new(static_key: EcPublicKey<C>, ephemeral_key: EcPublicKey<C>) -> Self {
        Self {
            static_key,
            ephemeral_key,
            user_id: Vec::new(),
        }
    }

    /// 設定對方的使用者 ID。常數時間。
    pub fn with_user_id(mut self, user_id: Vec<u8>) -> Self {
        self.user_id = user_id;
        self
    }

    /// 對方的長期公鑰。常數時間。
    pub fn static_key(&self) -> &EcPublicKey<C> {
        &self.static_key
    }

    /// 對方的臨時公鑰。常數時間。
    pub fn ephemeral_key(&self) -> &EcPublicKey<C> {
        &self.ephemeral_key
    }

    /// 對方的使用者 ID。常數時間。
    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }
}
