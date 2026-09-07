//! X25519 的型別安全封裝。

use core::fmt;

use rand_core::CryptoRng;

/// X25519 私鑰。
#[derive(Clone)]
pub struct PrivateKey([u8; 32]);

/// X25519 公鑰。
///
/// 公鑰與私鑰是不同型別，不能互換：
///
/// ```compile_fail
/// use tc_x25519::x25519::{PrivateKey, PublicKey};
///
/// fn needs_private_key(_: &PrivateKey) {}
///
/// let public_key = PublicKey::from_bytes([0_u8; 32]);
/// needs_private_key(&public_key);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; 32]);

/// X25519 shared secret。
///
/// 這個型別刻意不實作 `Debug` 與 `PartialEq`；只能透過
/// [`SharedSecret::into_bytes`] 明確取出內容。
pub struct SharedSecret([u8; 32]);

/// X25519 agreement 錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X25519Error {
    /// 對方公鑰產生全零輸出，代表必須拒絕的低階點。
    LowOrderPoint,
}

impl fmt::Display for X25519Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("X25519 peer public key is a low-order point")
    }
}

impl core::error::Error for X25519Error {}

impl PrivateKey {
    /// 使用呼叫端提供的密碼學安全亂數產生已夾制私鑰。
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        generate_private_key(rng)
    }

    /// 從 byte array 建立私鑰，並依 RFC 7748 夾制 scalar。
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut bytes = bytes;
        tc_rfc7748::x25519::clamp_private_key(&mut bytes);
        Self(bytes)
    }

    /// 從私鑰導出對應的 X25519 公鑰。
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        public_key(self)
    }

    /// 與對方公鑰進行 X25519 agreement。
    pub fn agree(&self, peer: &PublicKey) -> Result<SharedSecret, X25519Error> {
        agree(self, peer)
    }
}

impl PublicKey {
    /// 從 RFC 7748 編碼的 u 座標建立公鑰。
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 取出 RFC 7748 編碼的 u 座標。
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl SharedSecret {
    /// 明確取出 shared secret bytes。
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// 使用呼叫端提供的密碼學安全亂數產生已夾制私鑰。
pub fn generate_private_key<R: CryptoRng + ?Sized>(rng: &mut R) -> PrivateKey {
    PrivateKey(tc_rfc7748::x25519::generate_private_key(rng))
}

/// 從私鑰導出對應的 X25519 公鑰。
#[must_use]
pub fn public_key(private_key: &PrivateKey) -> PublicKey {
    PublicKey(tc_rfc7748::x25519::generate_public_key(&private_key.0))
}

/// 進行 X25519 agreement，並拒絕會產生全零輸出的低階點。
pub fn agree(private_key: &PrivateKey, peer: &PublicKey) -> Result<SharedSecret, X25519Error> {
    tc_rfc7748::x25519::calculate_agreement(&private_key.0, &peer.0)
        .map(SharedSecret)
        .ok_or(X25519Error::LowOrderPoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_constructor_clamps_the_stored_scalar() {
        let private_key = PrivateKey::from_bytes([0xFF; 32]);

        assert_eq!(private_key.0[0], 0xF8);
        assert_eq!(private_key.0[31], 0x7F);
    }
}
