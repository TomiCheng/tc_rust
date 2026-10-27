use alloc::vec::Vec;

use tc_zeroize::Zeroizing;

use crate::{PbeError, PbeParams};

/// 產生器在 init 時複製的參數；密碼與 salt 在替換與 drop 時清除（scrypt 拿秘密當 salt）。
pub(crate) struct PbeState {
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) salt: Zeroizing<Vec<u8>>,
    pub(crate) iteration_count: usize,
}

impl PbeState {
    /// 複製 `params`；迭代次數 0 在複製之前就拒絕。對密碼與 salt 的內容是常數時間。
    pub(crate) fn copy<P: PbeParams + ?Sized>(params: &P) -> Result<Self, PbeError> {
        let iteration_count = params.iteration_count();
        if iteration_count == 0 {
            return Err(PbeError::InvalidIterationCount(0));
        }
        Ok(Self {
            password: Zeroizing::new(params.password().to_vec()),
            salt: Zeroizing::new(params.salt().to_vec()),
            iteration_count,
        })
    }
}
