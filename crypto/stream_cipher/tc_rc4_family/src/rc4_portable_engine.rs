use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const STATE_BYTES: usize = 256;

/// RC4（Rivest, 1987）的 portable 實作，同 BC 的 `RC4Engine`：1 到 256 bytes 的金鑰，沒有 IV。
///
/// **變動時間（cache-timing）：** 以置換表的值當索引交換與輸出，查表位置依秘密狀態而定。RC4 的
/// keystream 有已知偏差，已被攻破；只為相容保留。置換表與金鑰在 drop 時清除。
pub struct Rc4PortableEngine {
    state: [u8; STATE_BYTES],
    x: usize,
    y: usize,
    working_key: [u8; Self::MAX_KEY_BYTES],
    key_len: usize,
    initialised: bool,
}

impl Rc4PortableEngine {
    /// 最短的金鑰長度（bytes）。
    pub const MIN_KEY_BYTES: usize = 1;
    /// 最長的金鑰長度（bytes）。
    pub const MAX_KEY_BYTES: usize = 256;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            state: [0; STATE_BYTES],
            x: 0,
            y: 0,
            working_key: [0; Self::MAX_KEY_BYTES],
            key_len: 0,
            initialised: false,
        }
    }

    fn set_key(&mut self) {
        self.x = 0;
        self.y = 0;
        for (index, state) in self.state.iter_mut().enumerate() {
            *state = index as u8;
        }

        let mut key_index = 0usize;
        let mut state_index = 0usize;
        for index in 0..STATE_BYTES {
            state_index =
                (state_index + self.working_key[key_index] as usize + self.state[index] as usize)
                    & 0xff;
            self.state.swap(index, state_index);
            key_index = (key_index + 1) % self.key_len;
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.x = (self.x + 1) & 0xff;
        self.y = (self.y + self.state[self.x] as usize) & 0xff;
        self.state.swap(self.x, self.y);
        let index = (self.state[self.x] as usize + self.state[self.y] as usize) & 0xff;
        self.state[index]
    }
}

impl Default for Rc4PortableEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Rc4PortableEngine {
    /// 寫出 `RC4`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RC4")
    }
}

impl StreamCipher for Rc4PortableEngine {
    type Error = StreamError;

    /// `input` XOR 下一個 keystream byte；`init` 之前回傳 `NotInitialised`。變動時間（查表）。
    fn return_byte(&mut self, input: u8) -> Result<u8, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        Ok(input ^ self.next_byte())
    }

    /// `input` XOR keystream 寫進 `output` 開頭，回傳 `input.len()`；`init` 之前回傳
    /// `NotInitialised`，`output` 比 `input` 短時回傳 `BufferTooShort`，兩者都不改變位置。變動時間
    /// （查表）。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, StreamError> {
        if !self.initialised {
            return Err(StreamError::NotInitialised);
        }
        if output.len() < input.len() {
            return Err(StreamError::BufferTooShort);
        }
        for (input, output) in input.iter().zip(output.iter_mut()) {
            *output = *input ^ self.next_byte();
        }
        Ok(input.len())
    }

    /// 回到目前金鑰的 keystream 開頭。變動時間（重排置換表）。
    fn reset(&mut self) {
        if self.initialised {
            self.set_key();
        }
    }
}

impl<P: KeyParams + ?Sized> StreamCipherInit<P> for Rc4PortableEngine {
    type Error = InitError;

    /// 裝入 1 到 256 bytes 的金鑰；方向不影響，兩個方向用同一條 keystream。長度不對時保留原本的
    /// 金鑰與位置。變動時間（排列置換表時以金鑰與狀態當索引）。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if !(Self::MIN_KEY_BYTES..=Self::MAX_KEY_BYTES).contains(&key.len()) {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        self.working_key.zeroize();
        self.working_key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.set_key();
        self.initialised = true;
        Ok(())
    }
}

impl Drop for Rc4PortableEngine {
    fn drop(&mut self) {
        self.state.zeroize();
        self.working_key.zeroize();
    }
}
