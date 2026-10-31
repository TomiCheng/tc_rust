use crate::shared::{self, Buffers};
use crate::{Cbc, CtsChaining, Ecb};
use core::marker::PhantomData;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockModeInitError, IvParams};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_zeroize::{Zeroize, Zeroizing};

/// BC 的 `CtsBlockCipher`，區塊為 `N` 位元組、緩衝放在結構裡，不需配置器：密文與明文
/// 等長，最後一個區塊可以不完整，但訊息至少要有一個完整區塊。`M` 是串接方式，[`Ecb`] 或
/// [`Cbc`]。
///
/// 自己做 CBC 串接，直接持有 block cipher：CTS 的最後兩個區塊有一個要繞過串接、直接交給
/// block cipher。常數時間程度同 block cipher：只依長度分支與複製。緩衝區在 reset 與 drop
/// 時清除。
///
/// ```
/// use tc_aes::AesEngine;
/// use tc_block_modes::KeyWithIvRef;
/// use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};
/// use tc_cts_modes::{Cbc, FixedCtsBlockCipher};
///
/// let (key, iv) = ([0x42; 16], [0x24; 16]);
/// let params = KeyWithIvRef::new(&key, &iv);
/// let message = b"twenty-one bytes long";
///
/// // AES-CBC 加上密文竊取：21 位元組的明文得到 21 位元組的密文。
/// let mut cipher = FixedCtsBlockCipher::<_, 16, Cbc>::cbc(AesEngine::new());
/// cipher.init(CipherDirection::Encrypt, &params)?;
/// let mut sealed = vec![0; cipher.output_len(message.len())?];
/// let mut written = cipher.process_bytes(message, &mut sealed)?;
/// written += cipher.do_final(&mut sealed[written..])?;
/// assert_eq!(written, message.len());
///
/// cipher.init(CipherDirection::Decrypt, &params)?;
/// let mut opened = vec![0; cipher.output_len(written)?];
/// let mut read = cipher.process_bytes(&sealed, &mut opened)?;
/// read += cipher.do_final(&mut opened[read..])?;
/// assert_eq!(&opened[..read], message);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
pub struct FixedCtsBlockCipher<C, const N: usize, M> {
    cipher: C,
    buffer: Zeroizing<[[u8; N]; 2]>,
    chain: Zeroizing<[u8; N]>,
    next: Zeroizing<[u8; N]>,
    block: Zeroizing<[u8; N]>,
    iv: Zeroizing<[u8; N]>,
    buffered: usize,
    direction: Option<CipherDirection>,
    chaining: PhantomData<M>,
}

impl<C, const N: usize, M> FixedCtsBlockCipher<C, N, M> {
    /// 包住 `cipher`，尚未 `init`。常數時間。
    fn new(cipher: C) -> Self {
        Self {
            cipher,
            buffer: Zeroizing::new([[0; N]; 2]),
            chain: Zeroizing::new([0; N]),
            next: Zeroizing::new([0; N]),
            block: Zeroizing::new([0; N]),
            iv: Zeroizing::new([0; N]),
            buffered: 0,
            direction: None,
            chaining: PhantomData,
        }
    }

    /// 清除緩衝，串接回到 IV。常數時間。
    fn reset_state(&mut self) {
        self.buffer.zeroize();
        self.next.zeroize();
        self.block.zeroize();
        self.chain.copy_from_slice(&self.iv[..]);
        self.buffered = 0;
    }

    /// 借出共用邏輯要的緩衝區。常數時間。
    fn buffers(&mut self) -> (&mut C, Buffers<'_>) {
        (
            &mut self.cipher,
            Buffers {
                buffer: self.buffer.as_flattened_mut(),
                chain: &mut self.chain[..],
                next: &mut self.next[..],
                block: &mut self.block[..],
            },
        )
    }

    /// 檢查 block cipher 的區塊是 `N` 位元組。常數時間。
    fn check_block_size<E>(&self) -> Result<(), BlockModeInitError<E>>
    where
        C: BlockCipher,
    {
        let actual = self.cipher.block_size();
        if actual != N {
            return Err(BlockModeInitError::UnsupportedBlockSize {
                actual,
                required: N,
            });
        }
        Ok(())
    }
}

impl<C, const N: usize> FixedCtsBlockCipher<C, N, Ecb> {
    /// 不串接的 CTS，同 BC 的 `CtsBlockCipher(IBlockCipher)`。常數時間。
    pub fn ecb(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C, const N: usize> FixedCtsBlockCipher<C, N, Cbc> {
    /// CBC 串接的 CTS，同 BC 的 `CtsBlockCipher(new CbcBlockCipher(cipher))`。常數時間。
    pub fn cbc(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C, const N: usize, M> BufferedCipher for FixedCtsBlockCipher<C, N, M>
where
    C: BlockCipher,
    C::Error: core::error::Error + 'static,
    M: CtsChaining,
{
    type Error = BufferedError<C::Error>;

    /// 回傳 `N`。常數時間。
    fn block_size(&self) -> usize {
        N
    }

    /// 這次 `process_bytes` 會寫出的位元組數：留下最後一個以上、至多兩個區塊，其餘寫出。
    /// 常數時間：只讀長度。
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, N, input_len)
    }

    /// `process_bytes` 加上 `do_final` 寫出的位元組數，與輸入等長。常數時間：只讀長度。
    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::output_len(self.buffered, input_len)
    }

    /// 緩衝 `input`，寫出不再屬於最後兩個區塊的部分。常數時間程度同 block cipher。
    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BufferedError::NotInitialized)?;
        let mut buffered = self.buffered;
        let (cipher, buffers) = self.buffers();
        let result = shared::process_bytes(
            cipher,
            M::CBC,
            direction == CipherDirection::Encrypt,
            buffers,
            &mut buffered,
            input,
            output,
        );
        self.buffered = buffered;
        result
    }

    /// 以密文竊取處理最後兩個區塊；不到一個完整區塊時回傳 `IncompleteLastBlock`。不論
    /// 成敗都清除緩衝、回到 IV。常數時間程度同 block cipher。
    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        let result = match self.direction {
            Some(direction) => {
                let buffered = self.buffered;
                let (cipher, buffers) = self.buffers();
                shared::do_final(
                    cipher,
                    M::CBC,
                    direction == CipherDirection::Encrypt,
                    buffers,
                    buffered,
                    output,
                )
            }
            None => Err(BufferedError::NotInitialized),
        };
        self.reset_state();
        result
    }

    /// 丟掉緩衝的輸入並清除，串接回到 IV。常數時間。
    fn reset(&mut self) {
        self.reset_state();
    }
}

impl<C, P, const N: usize> BufferedCipherInit<P> for FixedCtsBlockCipher<C, N, Ecb>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// 檢查區塊大小，以 `params` 初始化 block cipher；失敗時維持未初始化。常數時間程度
    /// 同 block cipher 的 `init`。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.reset_state();
        self.check_block_size()?;
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}

impl<C, P, const N: usize> BufferedCipherInit<P> for FixedCtsBlockCipher<C, N, Cbc>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// 檢查區塊大小與 IV 長度（恰好 `N` 位元組），以 `params` 初始化 block cipher，裝上 IV；
    /// 失敗時維持未初始化。常數時間程度同 block cipher 的 `init`：只檢查公開的長度並複製
    /// IV。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.check_block_size()?;
        let iv = params.iv();
        if iv.len() != N {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }
        self.iv.copy_from_slice(iv);
        self.reset_state();
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        self.direction = Some(direction);
        Ok(())
    }
}
