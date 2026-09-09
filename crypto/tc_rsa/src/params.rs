//! RSA 金鑰參數。
//!
//! 這些型別只是大端序位元組的容器，建構時不做任何有效性檢查；金鑰能不能用，
//! 由 `RsaCoreEngine` 初始化時判定。
//! 容器不提供相等比較：逐位元組比較不是常數時間，也不代表忽略前導零後的數值相等。

use alloc::vec::Vec;
use tc_bigint::{Zeroize, ZeroizeOnDrop};

use crate::traits;

/// 公開金鑰或非 CRT 私鑰的參數。
///
/// 借用呼叫端持有的大端序位元組，建構時不驗證，初始化時才檢查。
/// 所有權決定清除責任：此型別不修改借用資料，歸零由持有位元組的呼叫端負責。
///
/// ```
/// use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
/// use tc_rsa::{Rsa2048Core, RsaInit, RsaKeyRef};
///
/// // 小型金鑰僅供示範，不可用於實際場合。
/// let modulus = [0x0f, 0xf7];
/// let exponent = [7];
/// let key = RsaKeyRef::new(false, &modulus, &exponent);
/// let mut engine = Rsa2048Core::default();
/// engine.init(CipherDirection::Encrypt, &key)?;
/// let mut output = [0_u8; 2];
/// let len = engine.process_block(&[2], &mut output)?;
/// assert_eq!(&output[..len], &[0, 128]);
/// # Ok::<(), tc_rsa::RsaError>(())
/// ```
#[derive(Clone, Copy)]
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
///
/// 所有權決定清除責任：此型別不修改借用資料，歸零由持有位元組的呼叫端負責。
#[derive(Clone, Copy)]
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

/// 擁有位元組的公開金鑰或非 CRT 私鑰參數。
///
/// 與 [`RsaKeyRef`] 的差別只在所有權：從 DER／PKCS#8 解出來的位元組沒有更長壽
/// 的借用來源時用這個，其餘語意（大端序、允許前導零、建構不驗證）完全相同。
/// drop 時會以易失寫入清除所有位元組欄位的有效內容，再釋放配置。
/// 建構後不再增長或重新配置，因此持有期間不會新增重配置留下的舊緩衝。
/// 清除範圍不含 spare capacity，也無法追回建構前的舊配置或其他副本。
///
/// ```
/// use tc_cipher::{AsymmetricBlockCipher, CipherDirection};
/// use tc_rsa::{Rsa2048Core, RsaInit, RsaKeyOwned};
///
/// // 小型金鑰僅供示範；位元組的所有權交給參數容器。
/// let key = RsaKeyOwned::new(false, vec![0x0f, 0xf7], vec![7]);
/// let borrowed = key.as_key_ref();
/// assert_eq!(borrowed.modulus(), &[0x0f, 0xf7]);
/// let mut engine = Rsa2048Core::default();
/// engine.init(CipherDirection::Encrypt, &borrowed)?;
/// // 初始化後，核心持有自己的整數值，不借用原始容器。
/// drop(key);
/// let mut output = [0_u8; 2];
/// let len = engine.process_block(&[2], &mut output)?;
/// assert_eq!(&output[..len], &[0, 128]);
/// # Ok::<(), tc_rsa::RsaError>(())
/// ```
#[derive(Clone)]
pub struct RsaKeyOwned {
    is_private: bool,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl Drop for RsaKeyOwned {
    fn drop(&mut self) {
        self.modulus[..].zeroize();
        self.exponent[..].zeroize();
    }
}

impl ZeroizeOnDrop for RsaKeyOwned {}

impl RsaKeyOwned {
    /// 建立擁有位元組的 RSA 金鑰參數。
    ///
    /// `exponent` 對公開金鑰是 `e`，對私鑰是 `d`。
    pub const fn new(is_private: bool, modulus: Vec<u8>, exponent: Vec<u8>) -> Self {
        Self {
            is_private,
            modulus,
            exponent,
        }
    }

    /// 借出一份 [`RsaKeyRef`]。
    pub fn as_key_ref(&self) -> RsaKeyRef<'_> {
        RsaKeyRef::new(self.is_private, &self.modulus, &self.exponent)
    }
}

impl traits::RsaKeyParams for RsaKeyOwned {
    fn is_private_key(&self) -> bool {
        self.is_private
    }

    fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    fn exponent(&self) -> &[u8] {
        &self.exponent
    }
}

/// 擁有位元組的 CRT 私鑰參數。
///
/// 與 [`RsaPrivateCrtKeyRef`] 的差別只在所有權。
/// drop 時會以易失寫入清除所有位元組欄位的有效內容，再釋放配置。
/// 建構後不再增長或重新配置，因此持有期間不會新增重配置留下的舊緩衝。
/// 清除範圍不含 spare capacity，也無法追回建構前的舊配置或其他副本。
#[derive(Clone)]
pub struct RsaPrivateCrtKeyOwned {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    dp: Vec<u8>,
    dq: Vec<u8>,
    q_inv: Vec<u8>,
}

impl Drop for RsaPrivateCrtKeyOwned {
    fn drop(&mut self) {
        self.modulus[..].zeroize();
        self.public_exponent[..].zeroize();
        self.private_exponent[..].zeroize();
        self.p[..].zeroize();
        self.q[..].zeroize();
        self.dp[..].zeroize();
        self.dq[..].zeroize();
        self.q_inv[..].zeroize();
    }
}

impl ZeroizeOnDrop for RsaPrivateCrtKeyOwned {}

impl RsaPrivateCrtKeyOwned {
    /// 建立擁有位元組的 CRT 私鑰參數。
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        modulus: Vec<u8>,
        public_exponent: Vec<u8>,
        private_exponent: Vec<u8>,
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        q_inv: Vec<u8>,
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

    /// 借出一份 [`RsaPrivateCrtKeyRef`]。
    pub fn as_key_ref(&self) -> RsaPrivateCrtKeyRef<'_> {
        RsaPrivateCrtKeyRef::new(
            &self.modulus,
            &self.public_exponent,
            &self.private_exponent,
            &self.p,
            &self.q,
            &self.dp,
            &self.dq,
            &self.q_inv,
        )
    }
}

impl traits::RsaKeyParams for RsaPrivateCrtKeyOwned {
    fn is_private_key(&self) -> bool {
        true
    }

    fn modulus(&self) -> &[u8] {
        &self.modulus
    }

    fn exponent(&self) -> &[u8] {
        &self.private_exponent
    }
}

impl traits::RsaPrivateCrtKeyParams for RsaPrivateCrtKeyOwned {
    fn public_exponent(&self) -> &[u8] {
        &self.public_exponent
    }

    fn p(&self) -> &[u8] {
        &self.p
    }

    fn q(&self) -> &[u8] {
        &self.q
    }

    fn dp(&self) -> &[u8] {
        &self.dp
    }

    fn dq(&self) -> &[u8] {
        &self.dq
    }

    fn q_inv(&self) -> &[u8] {
        &self.q_inv
    }
}
