//! CRT 私鑰運算的後端實作。

use crate::rsa_core::limbs_for_bits;

mod fixed;

pub use fixed::FixedRsaCrtCoreEngine;

/// 模數上限 1024 位元的 CRT 核心。
pub type Rsa1024CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(1024) }, { limbs_for_bits(512) }>;

/// 模數上限 2048 位元的 CRT 核心。
pub type Rsa2048CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(2048) }, { limbs_for_bits(1024) }>;

/// 模數上限 3072 位元的 CRT 核心。
pub type Rsa3072CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(3072) }, { limbs_for_bits(1536) }>;

/// 模數上限 4096 位元的 CRT 核心。
pub type Rsa4096CrtCore = FixedRsaCrtCoreEngine<{ limbs_for_bits(4096) }, { limbs_for_bits(2048) }>;
