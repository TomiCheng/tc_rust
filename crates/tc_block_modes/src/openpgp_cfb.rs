//! OpenPGP's variant of CFB, ported from Bouncy Castle's
//! `OpenPgpCfbBlockCipher`.
//!
//! OpenPGP uses full-block CFB with an extra resynchronisation step: after the
//! first block and the two-byte check that follows it, the feedback register is
//! shifted by two bytes and re-encrypted, so the third block onwards runs on a
//! register offset from the plain CFB one. See RFC 4880 §13.9.
//!
//! Only the forward direction of the cipher is used, so the underlying cipher
//! is always keyed for encryption.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use tc_cipher_core::{BlockCipher, BlockCipherInit, CipherDirection};

use crate::BlockCipherModeError;

/// Parameters for OpenPGP CFB: the cipher's key parameters plus an IV.
///
/// The IV may be shorter than one block, in which case it is left-padded with
/// zeros; `None` means an all-zero IV.
pub struct OpenPgpCfbParams<'a, E: BlockCipherInit> {
    /// The underlying block cipher's key parameters.
    key_params: E::Params<'a>,
    /// The initialisation vector; `None` means all zeros.
    iv: Option<&'a [u8]>,
}

impl<'a, E: BlockCipherInit> OpenPgpCfbParams<'a, E> {
    /// Builds parameters with an all-zero IV.
    pub fn new(key_params: E::Params<'a>) -> Self {
        Self {
            key_params,
            iv: None,
        }
    }

    /// Builds parameters with the given IV, which may be up to one block long.
    pub fn with_iv(key_params: E::Params<'a>, iv: &'a [u8]) -> Self {
        Self {
            key_params,
            iv: Some(iv),
        }
    }
}

/// OpenPGP CFB mode over the block cipher `E` (bc `OpenPgpCfbBlockCipher`).
pub struct OpenPgpCfbBlockCipher<E> {
    /// The underlying block cipher, always keyed for encryption.
    cipher: E,
    /// The composed name, built at construction and refreshed on `init`.
    name: String,
    /// The IV chosen at `init`, kept so the register can be restarted.
    iv: Vec<u8>,
    /// The feedback register (`FR` in the RFC).
    fr: Vec<u8>,
    /// The cipher's output over the register (`FRE` in the RFC).
    fre: Vec<u8>,
    /// Bytes processed so far, which selects the resynchronisation stage.
    count: usize,
    /// `None` until `init`; then the direction data is transformed in.
    direction: Option<CipherDirection>,
}

impl<E: BlockCipher> OpenPgpCfbBlockCipher<E> {
    /// Wraps the given block cipher in OpenPGP CFB mode.
    pub fn new(cipher: E) -> Self {
        let block_size = cipher.block_size();
        let mut mode = Self {
            cipher,
            name: String::new(),
            iv: vec![0u8; block_size],
            fr: vec![0u8; block_size],
            fre: vec![0u8; block_size],
            count: 0,
            direction: None,
        };
        mode.refresh_name();
        mode
    }

    /// Rebuilds the composed algorithm name.
    ///
    /// 名稱在建構與 init 後各組一次：部分 engine 要等 keying 之後才知道名稱。
    fn refresh_name(&mut self) {
        let base = self.cipher.algorithm_name();
        let mut name = String::with_capacity(base.len() + 11);
        name.push_str(base);
        name.push_str("/OpenPGPCFB");
        self.name = name;
    }

    /// Runs the cipher over the feedback register into `fre`.
    fn encrypt_register(&mut self) -> Result<(), BlockCipherModeError<E>> {
        self.cipher
            .process_block(&self.fr, &mut self.fre)
            .map_err(BlockCipherModeError::BlockCipher)?;
        Ok(())
    }

    fn encrypt_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockCipherModeError<E>> {
        let bs = self.fr.len();
        if self.count > bs {
            // 穩定狀態：回饋暫存器已偏移兩個位元組。
            self.fr[bs - 2] = self.fre[bs - 2] ^ input[0];
            output[0] = self.fr[bs - 2];
            self.fr[bs - 1] = self.fre[bs - 1] ^ input[1];
            output[1] = self.fr[bs - 1];
            self.encrypt_register()?;
            for n in 2..bs {
                self.fr[n - 2] = self.fre[n - 2] ^ input[n];
                output[n] = self.fr[n - 2];
            }
        } else if self.count == 0 {
            // 第一塊：一般的 CFB。
            self.encrypt_register()?;
            for n in 0..bs {
                self.fr[n] = self.fre[n] ^ input[n];
                output[n] = self.fr[n];
            }
            self.count += bs;
        } else {
            // 第二塊：輸出兩個位元組後重新同步，暫存器左移兩格再加密一次。
            self.encrypt_register()?;
            output[0] = self.fre[0] ^ input[0];
            output[1] = self.fre[1] ^ input[1];

            self.fr.copy_within(2.., 0);
            self.fr[bs - 2..].copy_from_slice(&output[..2]);

            self.encrypt_register()?;
            for n in 2..bs {
                self.fr[n - 2] = self.fre[n - 2] ^ input[n];
                output[n] = self.fr[n - 2];
            }
            self.count += bs;
        }
        Ok(())
    }

    fn decrypt_block(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), BlockCipherModeError<E>> {
        let bs = self.fr.len();
        if self.count > bs {
            // 解密時回饋的是密文，也就是輸入。
            self.fr[bs - 2] = input[0];
            output[0] = self.fre[bs - 2] ^ input[0];
            self.fr[bs - 1] = input[1];
            output[1] = self.fre[bs - 1] ^ input[1];
            self.encrypt_register()?;
            for n in 2..bs {
                self.fr[n - 2] = input[n];
                output[n] = self.fre[n - 2] ^ input[n];
            }
        } else if self.count == 0 {
            self.encrypt_register()?;
            for n in 0..bs {
                self.fr[n] = input[n];
                output[n] = self.fre[n] ^ input[n];
            }
            self.count += bs;
        } else {
            self.encrypt_register()?;
            let in0 = input[0];
            let in1 = input[1];
            output[0] = self.fre[0] ^ in0;
            output[1] = self.fre[1] ^ in1;

            self.fr.copy_within(2.., 0);
            self.fr[bs - 2] = in0;
            self.fr[bs - 1] = in1;

            self.encrypt_register()?;
            for n in 2..bs {
                self.fr[n - 2] = input[n];
                output[n] = self.fre[n - 2] ^ input[n];
            }
            self.count += bs;
        }
        Ok(())
    }
}

impl<E: BlockCipher> BlockCipher for OpenPgpCfbBlockCipher<E> {
    type Error = BlockCipherModeError<E>;

    fn algorithm_name(&self) -> &str {
        &self.name
    }

    fn block_size(&self) -> usize {
        self.fr.len()
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        let direction = self.direction.ok_or(BlockCipherModeError::NotInitialised)?;
        let bs = self.fr.len();
        if input.len() < bs || output.len() < bs {
            return Err(BlockCipherModeError::BufferTooShort);
        }
        match direction {
            CipherDirection::Encrypt => self.encrypt_block(input, output)?,
            CipherDirection::Decrypt => self.decrypt_block(input, output)?,
        }
        Ok(bs)
    }
}

impl<E: BlockCipherInit> BlockCipherInit for OpenPgpCfbBlockCipher<E> {
    type Params<'a> = OpenPgpCfbParams<'a, E>;

    fn init(
        &mut self,
        direction: CipherDirection,
        params: &Self::Params<'_>,
    ) -> Result<(), Self::Error> {
        let block_size = self.cipher.block_size();
        if let Some(iv) = params.iv {
            if iv.len() > block_size {
                return Err(BlockCipherModeError::InvalidIvLength {
                    actual: iv.len(),
                    block_size,
                });
            }
            // 較短的 IV 靠左補零（照 bc，依 FIPS PUB 81）。
            let offset = block_size - iv.len();
            self.iv[..offset].fill(0);
            self.iv[offset..].copy_from_slice(iv);
        } else {
            self.iv.fill(0);
        }
        self.count = 0;
        self.fr.copy_from_slice(&self.iv);

        // 只用到 cipher 的正向，故底層一律以加密方向 keying。
        self.cipher
            .init(CipherDirection::Encrypt, &params.key_params)
            .map_err(BlockCipherModeError::BlockCipher)?;
        self.direction = Some(direction);
        self.refresh_name();
        Ok(())
    }
}
