use tc_macs::{Mac, MacInit};

use crate::params::AnyParams;

/// CBC-MAC 的參數沒帶 IV 時補上全零的 IV，同 BC 的 `CbcBlockCipherMac` 只收到金鑰時；帶了 IV 就照用。
#[allow(dead_code, reason = "所有 CBC-MAC 的 feature 都關掉時沒有人用")]
pub(super) struct ZeroIv<M> {
    mac: M,
    iv_size: usize,
}

#[allow(dead_code, reason = "所有 CBC-MAC 的 feature 都關掉時沒有人用")]
impl<M> ZeroIv<M> {
    pub(super) const fn new(mac: M, iv_size: usize) -> Self {
        Self { mac, iv_size }
    }
}

impl<M: Mac> Mac for ZeroIv<M> {
    type Error = M::Error;

    fn mac_size(&self) -> usize {
        self.mac.mac_size()
    }

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.mac.update(input)
    }

    fn do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        self.mac.do_final(output)
    }

    fn reset(&mut self) {
        self.mac.reset();
    }
}

impl<M: MacInit<AnyParams>> MacInit<AnyParams> for ZeroIv<M> {
    type Error = M::Error;

    fn init(&mut self, params: &AnyParams) -> Result<(), Self::Error> {
        match params {
            AnyParams::WithIv { .. } => self.mac.init(params),
            // 複製一份參數包上全零 IV；用完 drop 時清除複製的金鑰
            _ => self
                .mac
                .init(&params.clone().with_iv(vec![0; self.iv_size])),
        }
    }
}
