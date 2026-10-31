use crate::user_id::DEFAULT_USER_ID;
use alloc::vec::Vec;

/// BC 包在 `ParametersWithID` 裡的 EC 金鑰：私鑰簽章、公鑰驗證，加上算 Z 用的使用者 ID。
/// 只是容器，`Sm2Signer::init` 才檢查。
#[derive(Clone)]
pub struct Sm2SignerParams<K> {
    key: K,
    user_id: Vec<u8>,
}

impl<K> Sm2SignerParams<K> {
    /// 使用者 ID 為 BC 預設的 "1234567812345678"。常數時間。
    pub fn new(key: K) -> Self {
        Self {
            key,
            user_id: DEFAULT_USER_ID.to_vec(),
        }
    }

    /// 設定使用者 ID。常數時間。
    pub fn with_user_id(mut self, user_id: Vec<u8>) -> Self {
        self.user_id = user_id;
        self
    }

    /// 金鑰。常數時間。
    pub fn key(&self) -> &K {
        &self.key
    }

    /// 使用者 ID。常數時間。
    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }
}
