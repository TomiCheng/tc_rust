/// 初始化好的封裝方，BC 的 `IKemEncapsulator`：以對方的公鑰產生封裝與共享秘密。
///
/// 封裝需要的隨機值由實作自己持有的亂數來源取得；初始化由 [`KemInit`] 另外提供。時間保證
/// 由實作標明。
pub trait KemEncapsulator {
    /// 失敗的型別，例如緩衝區長度不對。
    type Error: core::error::Error;

    /// 封裝的位元組數。
    fn encapsulation_length(&self) -> usize;

    /// 共享秘密的位元組數。
    fn secret_length(&self) -> usize;

    /// 寫出封裝與共享秘密；兩個緩衝區的長度要恰好是
    /// [`encapsulation_length`](Self::encapsulation_length) 與
    /// [`secret_length`](Self::secret_length)，同 BC。
    fn encapsulate(
        &mut self,
        encapsulation: &mut [u8],
        secret: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// 初始化好的解封裝方，BC 的 `IKemDecapsulator`：以私鑰從封裝取回共享秘密。
///
/// 初始化由 [`KemInit`] 另外提供。時間保證由實作標明。
pub trait KemDecapsulator {
    /// 失敗的型別，例如緩衝區長度不對。
    type Error: core::error::Error;

    /// 封裝的位元組數。
    fn encapsulation_length(&self) -> usize;

    /// 共享秘密的位元組數。
    fn secret_length(&self) -> usize;

    /// 從 `encapsulation` 取回共享秘密寫進 `secret`；長度要恰好是
    /// [`encapsulation_length`](Self::encapsulation_length) 與
    /// [`secret_length`](Self::secret_length)，同 BC。
    fn decapsulate(&mut self, encapsulation: &[u8], secret: &mut [u8]) -> Result<(), Self::Error>;
}

/// 以型別 `P` 的參數初始化封裝方或解封裝方：封裝收公鑰，解封裝收私鑰。
pub trait KemInit<P: ?Sized> {
    /// 失敗的型別，例如金鑰不合格。
    type Error: core::error::Error;

    /// 收下金鑰。
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
