use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};

use crate::salsa::{self, State};

/// Salsa20（Bernstein, 2005），同 BC 的 `Salsa20Engine`：16 或 32 bytes 的金鑰、8 bytes 的 IV，回合數
/// 預設 20，[`with_rounds`](Self::with_rounds) 可選其他正偶數（8 與 12 是減回合版本）。
///
/// 同一組金鑰與 IV 最多 2^70 bytes，同 BC；超過時處理回傳 `MaxBytesExceeded`。
///
/// **常數時間：** 只有 32 位元加法、XOR 與固定旋轉，分支只看長度、回合數與 keystream 位置，都是
/// 公開值。狀態字組與目前的 keystream 區塊在 drop 時清除；呼叫端的金鑰與暫存器、堆疊上的複本
/// 不在此列。
pub struct Salsa20Engine {
    rounds: usize,
    state: State,
}

impl Salsa20Engine {
    /// 接受的金鑰長度（bytes）。
    pub const KEY_BYTES: [usize; 2] = [16, 32];
    /// IV 長度（bytes）。
    pub const IV_BYTES: usize = 8;
    /// 預設的回合數。
    pub const DEFAULT_ROUNDS: usize = salsa::DEFAULT_ROUNDS;

    /// 20 回合、還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self::build(salsa::DEFAULT_ROUNDS)
    }

    /// 指定正偶數回合數的引擎，不合時回傳 `InvalidRounds`。常數時間。
    pub const fn with_rounds(rounds: usize) -> Result<Self, InitError> {
        if rounds == 0 || rounds & 1 != 0 || rounds > salsa::MAX_ROUNDS {
            return Err(InitError::InvalidRounds(rounds));
        }
        Ok(Self::build(rounds))
    }

    const fn build(rounds: usize) -> Self {
        Self {
            rounds,
            state: State::new(rounds),
        }
    }
}

impl Default for Salsa20Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Salsa20Engine {
    /// 寫出 `Salsa20`，回合數不是 20 時寫成 `Salsa20/12` 這樣，同 BC；不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rounds == salsa::DEFAULT_ROUNDS {
            f.write_str("Salsa20")
        } else {
            write!(f, "Salsa20/{}", self.rounds)
        }
    }
}

impl StreamCipher for Salsa20Engine {
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

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Salsa20Engine {
    type Error = InitError;

    /// 裝入 16 或 32 bytes 的金鑰與 8 bytes 的 IV，從第 0 個區塊開始；方向不影響，兩個方向用同一條
    /// keystream。長度不對時保留原本的金鑰、IV 與位置。常數時間；分支只看長度。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !Self::KEY_BYTES.contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.state.init(key, iv);
        Ok(())
    }
}
