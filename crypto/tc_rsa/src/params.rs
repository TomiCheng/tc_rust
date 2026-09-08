//! RSA 金鑰參數。
//!
//! 這些型別只是大端序位元組的容器，建構時不做任何有效性檢查；金鑰能不能用，
//! 由 `RsaCoreEngine` 初始化時判定。

use crate::traits;

/// 公開金鑰或非 CRT 私鑰的參數。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RsaKeyRef<'a> {
    is_private: bool,
    modulus: &'a [u8],
    exponent: &'a [u8],
}

impl<'a> RsaKeyRef<'a> {
    /// 建立 RSA 金鑰參數。
    ///
    /// `exponent` 對公開金鑰是 `e`，對私鑰是 `d`。
    pub const fn new(is_private: bool, modulus: &'a [u8], exponent: &'a [u8]) -> Self {
        Self {
            is_private,
            modulus,
            exponent,
        }
    }

    /// 回傳此參數是否包含私密指數。
    pub const fn is_private(&self) -> bool {
        self.is_private
    }

    /// 回傳模數。
    pub const fn modulus(&self) -> &'a [u8] {
        self.modulus
    }

    /// 回傳公開或私密指數。
    pub const fn exponent(&self) -> &'a [u8] {
        self.exponent
    }
}

impl traits::RsaKeyParams for RsaKeyRef<'_> {
    fn is_private_key(&self) -> bool {
        self.is_private
    }

    fn modulus(&self) -> &[u8] {
        self.modulus
    }

    fn exponent(&self) -> &[u8] {
        self.exponent
    }
}

/// 含中國剩餘定理因子的 RSA 私鑰參數。
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RsaPrivateCrtKeyRef<'a> {
    modulus: &'a [u8],
    public_exponent: &'a [u8],
    private_exponent: &'a [u8],
    p: &'a [u8],
    q: &'a [u8],
    dp: &'a [u8],
    dq: &'a [u8],
    q_inv: &'a [u8],
}

impl<'a> RsaPrivateCrtKeyRef<'a> {
    /// 建立 CRT 私鑰參數。
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        modulus: &'a [u8],
        public_exponent: &'a [u8],
        private_exponent: &'a [u8],
        p: &'a [u8],
        q: &'a [u8],
        dp: &'a [u8],
        dq: &'a [u8],
        q_inv: &'a [u8],
    ) -> Self {
        Self {
            modulus,
            public_exponent,
            private_exponent,
            p,
            q,
            dp,
            dq,
            q_inv,
        }
    }

    pub const fn modulus(&self) -> &'a [u8] {
        self.modulus
    }

    pub const fn public_exponent(&self) -> &'a [u8] {
        self.public_exponent
    }

    pub const fn private_exponent(&self) -> &'a [u8] {
        self.private_exponent
    }

    pub const fn p(&self) -> &'a [u8] {
        self.p
    }

    pub const fn q(&self) -> &'a [u8] {
        self.q
    }

    pub const fn dp(&self) -> &'a [u8] {
        self.dp
    }

    pub const fn dq(&self) -> &'a [u8] {
        self.dq
    }

    pub const fn q_inv(&self) -> &'a [u8] {
        self.q_inv
    }
}

impl traits::RsaKeyParams for RsaPrivateCrtKeyRef<'_> {
    fn is_private_key(&self) -> bool {
        true
    }

    fn modulus(&self) -> &[u8] {
        self.modulus
    }

    fn exponent(&self) -> &[u8] {
        self.private_exponent
    }
}

impl traits::RsaPrivateCrtKeyParams for RsaPrivateCrtKeyRef<'_> {
    fn public_exponent(&self) -> &[u8] {
        self.public_exponent
    }

    fn p(&self) -> &[u8] {
        self.p
    }

    fn q(&self) -> &[u8] {
        self.q
    }

    fn dp(&self) -> &[u8] {
        self.dp
    }

    fn dq(&self) -> &[u8] {
        self.dq
    }

    fn q_inv(&self) -> &[u8] {
        self.q_inv
    }
}

/// 可交給 RSA 引擎的金鑰種類。
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RsaKey<'a> {
    Standard(RsaKeyRef<'a>),
    PrivateCrt(RsaPrivateCrtKeyRef<'a>),
}

impl<'a> From<RsaKeyRef<'a>> for RsaKey<'a> {
    fn from(value: RsaKeyRef<'a>) -> Self {
        Self::Standard(value)
    }
}

impl<'a> From<RsaPrivateCrtKeyRef<'a>> for RsaKey<'a> {
    fn from(value: RsaPrivateCrtKeyRef<'a>) -> Self {
        Self::PrivateCrt(value)
    }
}
