use tc_buffered_cipher::{BufferedCipher, BufferedCipherInit, CipherDirection};

use crate::AnyError;
use crate::params::AnyParams;

trait InnerAnyCipher:
    BufferedCipher<Error = AnyError> + BufferedCipherInit<AnyParams, Error = AnyError>
{
}

// 錯誤已經是 AnyError 的，自動符合
impl<T> InnerAnyCipher for T where
    T: BufferedCipher<Error = AnyError> + BufferedCipherInit<AnyParams, Error = AnyError>
{
}

/// 包住具體的 buffered cipher，每個方法轉呼叫進去，錯誤換成 `AnyError`。
/// 具體 cipher 的 `Error` 是別的 crate 定的，改不了，所以包一層自己的型別。
struct BufferedCipherWrapper<T>(T);

impl<T> BufferedCipher for BufferedCipherWrapper<T>
where
    T: BufferedCipher,
    T::Error: Send + Sync + 'static,
{
    type Error = AnyError;

    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, AnyError> {
        self.0.update_output_len(input_len).map_err(AnyError::new)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, AnyError> {
        self.0.output_len(input_len).map_err(AnyError::new)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, AnyError> {
        self.0.process_bytes(input, output).map_err(AnyError::new)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, AnyError> {
        self.0.do_final(output).map_err(AnyError::new)
    }

    fn reset(&mut self) {
        self.0.reset();
    }
}

impl<T> BufferedCipherInit<AnyParams> for BufferedCipherWrapper<T>
where
    T: BufferedCipherInit<AnyParams>,
    T::Error: Send + Sync + 'static,
{
    type Error = AnyError;

    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), AnyError> {
        self.0.init(direction, params).map_err(AnyError::new)
    }
}

pub struct AnyCipher {
    cipher: Box<dyn InnerAnyCipher>,
}

impl AnyCipher {
    // 給表用：包一層 BufferedCipherWrapper 把錯誤換成 AnyError
    pub(super) fn new<T>(cipher: T) -> Self
    where
        T: BufferedCipher + BufferedCipherInit<AnyParams> + 'static,
        <T as BufferedCipher>::Error: Send + Sync + 'static,
        <T as BufferedCipherInit<AnyParams>>::Error: Send + Sync + 'static,
    {
        Self {
            cipher: Box::new(BufferedCipherWrapper(cipher)),
        }
    }
}

impl BufferedCipherInit<AnyParams> for AnyCipher {
    type Error = AnyError;

    fn init(&mut self, direction: CipherDirection, params: &AnyParams) -> Result<(), Self::Error> {
        self.cipher.init(direction, params)
    }
}

impl BufferedCipher for AnyCipher {
    type Error = AnyError;

    fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    fn update_output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.update_output_len(input_len)
    }

    fn output_len(&self, input_len: usize) -> Result<usize, Self::Error> {
        self.cipher.output_len(input_len)
    }

    fn process_bytes(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.process_bytes(input, output)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.cipher.do_final(output)
    }

    fn reset(&mut self) {
        self.cipher.reset();
    }
}
