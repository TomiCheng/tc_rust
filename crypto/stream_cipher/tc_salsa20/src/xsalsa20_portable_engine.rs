use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

use crate::salsa::{self, State};

/// XSalsa20（Bernstein, 2008）的 portable 實作，同 BC 的 `XSalsa20Engine`：32 bytes 的金鑰與 24 bytes 的 IV，以
/// HSalsa20 由金鑰與 IV 前 16 bytes 推出子金鑰，再以 IV 後 8 bytes 跑 20 回合的 Salsa20。
///
/// 同一組金鑰與 IV 最多 2^70 bytes，同 BC；超過時處理回傳 `MaxBytesExceeded`。
///
/// **常數時間：** 只有 32 位元加法、XOR 與固定旋轉，分支只看長度與 keystream 位置。狀態字組、
/// 推子金鑰的暫存與目前的 keystream 區塊在 drop 或用完時清除；呼叫端的金鑰與暫存器、堆疊上的
/// 複本不在此列。
pub struct Xsalsa20PortableEngine {
    state: State,
}

impl Xsalsa20PortableEngine {
    /// 金鑰長度（bytes）。
    pub const KEY_BYTES: usize = 32;
    /// IV 長度（bytes）。
    pub const IV_BYTES: usize = 24;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            state: State::new(salsa::DEFAULT_ROUNDS),
        }
    }
}

impl Default for Xsalsa20PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Xsalsa20PortableEngine {
    /// 寫出 `XSalsa20`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XSalsa20")
    }
}

impl StreamCipher for Xsalsa20PortableEngine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`，到上限時回傳
    /// `MaxBytesExceeded`。常數時間。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        self.state.return_byte(input)
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
    /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，會超過上限時回傳
    /// `MaxBytesExceeded`。常數時間；分支只看長度與位置。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        self.state.process_bytes(input, output)
    }

    /// 回到目前金鑰與 IV 的 keystream 開頭。常數時間。
    fn reset(&mut self) {
        self.state.reset();
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Xsalsa20PortableEngine {
    type Error = InitError;

    /// 裝入 32 bytes 的金鑰與 24 bytes 的 IV，推出子金鑰後從第 0 個區塊開始；方向不影響，兩個方向用
    /// 同一條 keystream。長度不對時保留原本的金鑰、IV 與位置。常數時間；分支只看長度。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != Self::KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }

        let words = &mut self.state.words;
        words.zeroize();
        salsa::set_key(words, key, iv);
        words[8] = u32::from_le_bytes([iv[8], iv[9], iv[10], iv[11]]);
        words[9] = u32::from_le_bytes([iv[12], iv[13], iv[14], iv[15]]);

        // HSalsa20：區塊輸出減回輸入，取對角線與中間四個字組當子金鑰
        let mut output = salsa::block(salsa::DEFAULT_ROUNDS, words);
        words[1] = output[0].wrapping_sub(words[0]);
        words[2] = output[5].wrapping_sub(words[5]);
        words[3] = output[10].wrapping_sub(words[10]);
        words[4] = output[15].wrapping_sub(words[15]);
        words[11] = output[6].wrapping_sub(words[6]);
        words[12] = output[7].wrapping_sub(words[7]);
        words[13] = output[8].wrapping_sub(words[8]);
        words[14] = output[9].wrapping_sub(words[9]);
        output.zeroize();

        words[6] = u32::from_le_bytes([iv[16], iv[17], iv[18], iv[19]]);
        words[7] = u32::from_le_bytes([iv[20], iv[21], iv[22], iv[23]]);
        self.state.finish_initialization();
        Ok(())
    }
}
