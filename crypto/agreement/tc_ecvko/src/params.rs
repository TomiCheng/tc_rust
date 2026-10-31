use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::EcPrivateKey;

/// BC 包在 `ParametersWithUkm` 裡的 EC 私鑰：自己的私鑰與雙方約定的 UKM（user keying
/// material，公開的隨機值）。只是容器，`init` 才使用。
#[derive(Clone)]
pub struct EcVkoParams<C: Curve<Scalar = PaddedBigUint>> {
    key: EcPrivateKey<C>,
    ukm: Vec<u8>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcVkoParams<C> {
    /// 私鑰與 UKM；UKM 以小端序解讀成整數。常數時間。
    pub fn new(key: EcPrivateKey<C>, ukm: Vec<u8>) -> Self {
        Self { key, ukm }
    }

    /// 私鑰。常數時間。
    pub fn key(&self) -> &EcPrivateKey<C> {
        &self.key
    }

    /// UKM。常數時間。
    pub fn ukm(&self) -> &[u8] {
        &self.ukm
    }
}
