//! 金鑰封裝機制（KEM）的介面，對應 Bouncy Castle 的 `IKemEncapsulator` 與
//! `IKemDecapsulator`：封裝方以對方的公鑰產生一份封裝與共享秘密，解封裝方以私鑰從封裝
//! 取回同一個秘密。

#![no_std]

mod traits;

pub use traits::{KemDecapsulator, KemEncapsulator, KemInit};
