use crate::shared::{self, Buffers};
use crate::{Cbc, CtsChaining, Ecb};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use tc_block_cipher::{BlockCipher, BlockCipherInit};
use tc_block_modes::{BlockModeInitError, IvParams};
use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, BufferedError, CipherDirection};
use tc_zeroize::{Zeroize, Zeroizing};

/// 同 [`FixedCtsBlockCipher`](crate::FixedCtsBlockCipher)，緩衝在 `init` 時依 block cipher
/// 的區塊大小配置，給執行期才知道區塊大小的呼叫端，例如工廠。需要 `alloc` feature。
///
/// 常數時間程度同 block cipher：只依長度分支與複製。緩衝區在 reset、重新配置與 drop 時
/// 清除。
pub struct CtsBlockCipher<C, M> {
    cipher: C,
    buffer: Zeroizing<Vec<u8>>,
    chain: Zeroizing<Vec<u8>>,
    next: Zeroizing<Vec<u8>>,
    block: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    buffered: usize,
    direction: Option<CipherDirection>,
    chaining: PhantomData<M>,
}

impl<C, M> CtsBlockCipher<C, M> {
    /// 包住 `cipher`，尚未 `init`，也還沒配置緩衝。常數時間。
    fn new(cipher: C) -> Self {
        Self {
            cipher,
            buffer: Zeroizing::new(Vec::new()),
            chain: Zeroizing::new(Vec::new()),
            next: Zeroizing::new(Vec::new()),
            block: Zeroizing::new(Vec::new()),
            iv: Zeroizing::new(Vec::new()),
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
        self.chain.copy_from_slice(&self.iv);
        self.buffered = 0;
    }

    /// 依區塊大小 `n` 重新配置緩衝；舊的緩衝在丟棄時清除。常數時間：只依長度。
    fn allocate(&mut self, n: usize, iv: &[u8]) {
        self.buffer = Zeroizing::new(vec![0; 2 * n]);
        self.chain = Zeroizing::new(iv.to_vec());
        self.next = Zeroizing::new(vec![0; n]);
        self.block = Zeroizing::new(vec![0; n]);
        self.iv = Zeroizing::new(iv.to_vec());
        self.buffered = 0;
    }

    /// 借出共用邏輯要的緩衝區。常數時間。
    fn buffers(&mut self) -> (&mut C, Buffers<'_>) {
        (
            &mut self.cipher,
            Buffers {
                buffer: &mut self.buffer,
                chain: &mut self.chain,
                next: &mut self.next,
                block: &mut self.block,
            },
        )
    }
}

impl<C> CtsBlockCipher<C, Ecb> {
    /// 不串接的 CTS，同 BC 的 `CtsBlockCipher(IBlockCipher)`。常數時間。
    pub fn ecb(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C> CtsBlockCipher<C, Cbc> {
    /// CBC 串接的 CTS，同 BC 的 `CtsBlockCipher(new CbcBlockCipher(cipher))`。常數時間。
    pub fn cbc(cipher: C) -> Self {
        Self::new(cipher)
    }
}

impl<C, M> BufferedCipher for CtsBlockCipher<C, M>
where
    C: BlockCipher,
    C::Error: core::error::Error + 'static,
    M: CtsChaining,
{
    type Error = BufferedError<C::Error>;

    /// block cipher 的區塊大小。常數時間。
    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// 這次 `process_bytes` 會寫出的位元組數：留下最後一個以上、至多兩個區塊，其餘寫出。
    /// 常數時間：只讀長度。
    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        shared::update_output_len(self.buffered, self.chain.len(), input_len)
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

impl<C, P> BufferedCipherInit<P> for CtsBlockCipher<C, Ecb>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// 以 `params` 初始化 block cipher，依它的區塊大小配置緩衝；失敗時維持未初始化。
    /// 常數時間程度同 block cipher 的 `init`。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        let n = self.cipher.block_size();
        self.allocate(n, &vec![0; n]);
        self.direction = Some(direction);
        Ok(())
    }
}

impl<C, P> BufferedCipherInit<P> for CtsBlockCipher<C, Cbc>
where
    C: BlockCipher + BlockCipherInit<P>,
    P: IvParams + ?Sized,
{
    type Error = BlockModeInitError<<C as BlockCipherInit<P>>::Error>;

    /// 以 `params` 初始化 block cipher，IV 要恰好一個區塊長，依區塊大小配置緩衝並裝上 IV；
    /// 失敗時維持未初始化。常數時間程度同 block cipher 的 `init`：只檢查公開的長度並複製
    /// IV。
    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), Self::Error> {
        self.direction = None;
        self.cipher
            .init(direction.into(), params)
            .map_err(BlockModeInitError::Cipher)?;
        let n = self.cipher.block_size();
        let iv = params.iv();
        if iv.len() != n {
            return Err(BlockModeInitError::InvalidIvLength(iv.len()));
        }
        self.allocate(n, iv);
        self.direction = Some(direction);
        Ok(())
    }
}
