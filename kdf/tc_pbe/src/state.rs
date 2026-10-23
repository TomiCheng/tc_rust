use alloc::vec::Vec;

use tc_zeroize::Zeroizing;

use crate::{PbeError, PbeParams};

/// 產生器在 init 時複製的參數；密碼在替換與 drop 時清除，salt 與次數不是秘密。
pub(crate) struct PbeState {
    pub(crate) password: Zeroizing<Vec<u8>>,
    pub(crate) salt: Vec<u8>,
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
            salt: params.salt().to_vec(),
            iteration_count,
        })
    }
}
