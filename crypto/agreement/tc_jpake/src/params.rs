use crate::JPakePrimeOrderGroup;
use crate::standard_groups::nist_3072;
use alloc::string::String;
use alloc::vec::Vec;
use tc_zeroize::Zeroize;

/// BC `JPakeParticipant` 建構子的參數：參與者 ID、密碼與群組。
///
/// 只是容器，`JPakeParticipant::init` 才檢查；drop 時清除密碼。沒有 `Debug` 與
/// `PartialEq`，以免印出或以變動時間比較密碼。
#[derive(Clone)]
pub struct JPakeParams {
    participant_id: String,
    password: Vec<u8>,
    group: JPakePrimeOrderGroup,
}

impl JPakeParams {
    /// 參與者 ID 與密碼的複本，群組用 BC 預設的 NIST 3072 位元群組。BC 的密碼是字元陣列，
    /// 以 UTF-8 編碼；這裡直接收位元組。對密碼是常數時間：只依長度複製。
    pub fn new(participant_id: &str, password: &[u8]) -> Self {
        Self {
            participant_id: participant_id.into(),
            password: password.to_vec(),
            group: nist_3072(),
        }
    }

    /// 改用 `group`。常數時間。
    pub fn with_group(mut self, group: JPakePrimeOrderGroup) -> Self {
        self.group = group;
        self
    }

    /// 參與者 ID：交換的雙方必須不同。常數時間。
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// 密碼。常數時間。
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// 群組。常數時間。
    pub fn group(&self) -> &JPakePrimeOrderGroup {
        &self.group
    }
}

impl Drop for JPakeParams {
    /// 清除密碼。常數時間。
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
