#![cfg_attr(not(feature = "std"), no_std)]

// 本 crate 需要堆積配置（Vec/Box/String），但不一定需要完整 std。
// no_std 時仍透過 alloc 取得這些型別；std build 下 alloc 也可用（std 依賴 alloc）。
extern crate alloc;

pub mod big_integer;
pub mod ec;
