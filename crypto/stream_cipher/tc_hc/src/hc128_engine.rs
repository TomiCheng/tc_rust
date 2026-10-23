use core::fmt;

use tc_stream_cipher::{
    CipherDirection, InitError, IvParams, KeyParams, StreamCipher, StreamCipherInit, StreamError,
};
use tc_zeroize::Zeroize;

const TABLE_WORDS: usize = 512;
const COUNTER_MASK: usize = 1023;

/// HC-128（eSTREAM），同 BC 的 `HC128Engine`：16 bytes 的金鑰與 16 bytes 的 IV。
///
/// **變動時間（cache-timing）：** 每一步以內部狀態的位元組查 p、q 表，查表位置依秘密狀態而定，
/// 共用快取的環境下可能洩漏；HC 沒有常數時間的版本，只為相容保留。其餘只有 32 位元加法、XOR
/// 與固定旋轉，分支只看長度與位置。金鑰、IV 與兩張表在 drop 時清除。
pub struct Hc128Engine {
    p: [u32; TABLE_WORDS],
    q: [u32; TABLE_WORDS],
    counter: usize,
    key: [u8; Self::KEY_BYTES],
    iv: [u8; Self::IV_BYTES],
    word: [u8; 4],
    word_index: usize,
    initialised: bool,
}

impl Hc128Engine {
    /// 金鑰長度（bytes）。
    pub const KEY_BYTES: usize = 16;
    /// IV 長度（bytes）。
    pub const IV_BYTES: usize = 16;

    /// 還沒有金鑰的引擎；處理前要先 `init`。常數時間。
    pub const fn new() -> Self {
        Self {
            p: [0; TABLE_WORDS],
            q: [0; TABLE_WORDS],
            counter: 0,
            key: [0; Self::KEY_BYTES],
            iv: [0; Self::IV_BYTES],
            word: [0; 4],
            word_index: 0,
            initialised: false,
        }
    }

    #[inline]
    fn f1(value: u32) -> u32 {
        value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3)
    }

    #[inline]
    fn f2(value: u32) -> u32 {
        value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10)
    }

    #[inline]
    fn g1(x: u32, y: u32, z: u32) -> u32 {
        (x.rotate_right(10) ^ z.rotate_right(23)).wrapping_add(y.rotate_right(8))
    }

    #[inline]
    fn g2(x: u32, y: u32, z: u32) -> u32 {
        (x.rotate_left(10) ^ z.rotate_left(23)).wrapping_add(y.rotate_left(8))
    }

    #[inline]
    fn h1(&self, value: u32) -> u32 {
        self.q[(value & 0xff) as usize].wrapping_add(self.q[256 + ((value >> 16) & 0xff) as usize])
    }

    #[inline]
    fn h2(&self, value: u32) -> u32 {
        self.p[(value & 0xff) as usize].wrapping_add(self.p[256 + ((value >> 16) & 0xff) as usize])
    }

    #[inline]
    fn step(&mut self) -> u32 {
        let index = self.counter & 511;
        let index3 = index.wrapping_sub(3) & 511;
        let index10 = index.wrapping_sub(10) & 511;
        let index12 = index.wrapping_sub(12) & 511;
        let index511 = index.wrapping_sub(511) & 511;
        let result = if self.counter < 512 {
            self.p[index] = self.p[index].wrapping_add(Self::g1(
                self.p[index3],
                self.p[index10],
                self.p[index511],
            ));
            self.h1(self.p[index12]) ^ self.p[index]
        } else {
            self.q[index] = self.q[index].wrapping_add(Self::g2(
                self.q[index3],
                self.q[index10],
                self.q[index511],
            ));
            self.h2(self.q[index12]) ^ self.q[index]
        };
        self.counter = (self.counter + 1) & COUNTER_MASK;
        result
    }

    fn initialize_state(&mut self) {
        self.counter = 0;
        self.word_index = 0;
        self.word = [0; 4];

        let mut words = [0u32; 1280];
        for (word, bytes) in words[..4].iter_mut().zip(self.key.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        words.copy_within(0..4, 4);
        for (word, bytes) in words[8..12].iter_mut().zip(self.iv.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        words.copy_within(8..12, 12);
        for index in 16..words.len() {
            words[index] = Self::f2(words[index - 2])
                .wrapping_add(words[index - 7])
                .wrapping_add(Self::f1(words[index - 15]))
                .wrapping_add(words[index - 16])
                .wrapping_add(index as u32);
        }
        self.p.copy_from_slice(&words[256..768]);
        self.q.copy_from_slice(&words[768..1280]);
        words.zeroize();

        for index in 0..TABLE_WORDS {
            self.p[index] = self.step();
        }
        for index in 0..TABLE_WORDS {
            self.q[index] = self.step();
        }
        self.counter = 0;
    }

    #[inline]
    fn next_byte(&mut self) -> u8 {
        if self.word_index == 0 {
            self.word = self.step().to_le_bytes();
        }
        let result = self.word[self.word_index];
        self.word_index = (self.word_index + 1) & 3;
        result
    }
}

impl Default for Hc128Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Hc128Engine {
    /// 寫出 `HC-128`，不碰金鑰。常數時間。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HC-128")
    }
}

impl StreamCipher for Hc128Engine {
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

    /// 回到目前金鑰與 IV 的 keystream 開頭。變動時間（重建表時查表）。
    fn reset(&mut self) {
        if self.initialised {
            self.initialize_state();
        }
    }
}

impl<P: KeyParams + IvParams + ?Sized> StreamCipherInit<P> for Hc128Engine {
    type Error = InitError;

    /// 裝入 16 bytes 的金鑰與 16 bytes 的 IV；方向不影響，兩個方向用同一條 keystream。長度不對時
    /// 保留原本的金鑰、IV 與位置。變動時間（建表時查表）。
    fn init(&mut self, _direction: CipherDirection, params: &P) -> Result<(), InitError> {
        let key = params.key();
        if key.len() != Self::KEY_BYTES {
            return Err(InitError::InvalidKeyLength(key.len()));
        }
        let iv = params.iv();
        if iv.len() != Self::IV_BYTES {
            return Err(InitError::InvalidIvLength(iv.len()));
        }
        self.key.copy_from_slice(key);
        self.iv.copy_from_slice(iv);
        self.initialize_state();
        self.initialised = true;
        Ok(())
    }
}

impl Drop for Hc128Engine {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.word.zeroize();
    }
}
