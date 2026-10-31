use core::fmt;

/// BC 的 `MLKemParameters` 與 `MLKemParameterSet`：FIPS 203 的三組參數。只是常數，沒有
/// 可變的部分。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlKemParameters {
    name: &'static str,
    k: usize,
    eta1: u8,
    poly_compressed_bytes: usize,
    poly_vec_compressed_bytes: usize,
}

impl MlKemParameters {
    /// ML-KEM-512：k = 2。
    pub const ML_KEM_512: Self = Self {
        name: "ML-KEM-512",
        k: 2,
        eta1: 3,
        poly_compressed_bytes: 128,
        poly_vec_compressed_bytes: 2 * 320,
    };

    /// ML-KEM-768：k = 3。
    pub const ML_KEM_768: Self = Self {
        name: "ML-KEM-768",
        k: 3,
        eta1: 2,
        poly_compressed_bytes: 128,
        poly_vec_compressed_bytes: 3 * 320,
    };

    /// ML-KEM-1024：k = 4。
    pub const ML_KEM_1024: Self = Self {
        name: "ML-KEM-1024",
        k: 4,
        eta1: 2,
        poly_compressed_bytes: 160,
        poly_vec_compressed_bytes: 4 * 352,
    };

    /// 名稱，例如 "ML-KEM-768"。常數時間。
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// 封裝（密文）的位元組數。常數時間。
    pub const fn encapsulation_length(&self) -> usize {
        self.poly_vec_compressed_bytes + self.poly_compressed_bytes
    }

    /// 共享秘密的位元組數，固定 32。常數時間。
    pub const fn secret_length(&self) -> usize {
        32
    }

    /// 封裝金鑰 ek 的位元組數：384·k + 32。常數時間。
    pub const fn public_key_length(&self) -> usize {
        384 * self.k + 32
    }

    /// 解封裝金鑰 dk 的位元組數：dk_PKE ‖ ek ‖ H(ek) ‖ z。常數時間。
    pub const fn private_key_length(&self) -> usize {
        384 * self.k + self.public_key_length() + 64
    }

    /// k。常數時間。
    pub(crate) const fn k(&self) -> usize {
        self.k
    }

    /// η₁。常數時間。
    pub(crate) const fn eta1(&self) -> u8 {
        self.eta1
    }

    /// u 壓縮後的位元組數。常數時間。
    pub(crate) const fn poly_vec_compressed_bytes(&self) -> usize {
        self.poly_vec_compressed_bytes
    }
}

impl fmt::Display for MlKemParameters {
    /// 寫出名稱。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}
