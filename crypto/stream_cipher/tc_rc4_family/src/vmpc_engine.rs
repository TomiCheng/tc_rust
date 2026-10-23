use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::vmpc_state::{self, VmpcState};

/// VMPC（Żółtak, 2004），同 BC 的 `VmpcEngine`：RC4 的變形，金鑰與 IV 都是 16 到 64 bytes。
///
/// **變動時間（cache-timing）：** 以置換表的值當索引多層取值與交換，查表位置依秘密狀態而定；只為
/// 相容保留。置換表、金鑰與 IV 在 drop 時清除。
pub struct VmpcEngine {
    state: VmpcState,
}

impl VmpcEngine {
    /// 最短的金鑰長度（bytes）。
    pub const MIN_KEY_BYTES: usize = vmpc_state::MIN_KEY_BYTES;
    /// 最長的金鑰長度（bytes）。
    pub const MAX_KEY_BYTES: usize = vmpc_state::MAX_KEY_BYTES;
    /// 最短的 IV 長度（bytes）。
    pub const MIN_IV_BYTES: usize = vmpc_state::MIN_IV_BYTES;
    /// 最長的 IV 長度（bytes）。
    pub const MAX_IV_BYTES: usize = vmpc_state::MAX_IV_BYTES;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            state: VmpcState::new(false),
        }
    }
}

impl Default for VmpcEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VmpcEngine {
    /// 寫出 `VMPC`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VMPC")
    }
}

impl StreamCipher for VmpcEngine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`。變動時間（查表）。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
    /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，兩者都不改變位置。變動時間
    /// （查表）。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// 回到目前金鑰與 IV 的 keystream 開頭。變動時間（重排置換表）。
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for VmpcEngine {
    type Error = InitError;

    /// 裝入 16 到 64 bytes 的金鑰與 IV；方向不影響，兩個方向用同一條 keystream。長度不對時保留原本
    /// 的金鑰、IV 與位置。變動時間（KSA 以金鑰、IV 與狀態當索引）。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        self.state.init(params)
    }
}
