use alloc::{vec, vec::Vec};

use tc_digest::Digest;
use tc_hmac::HMac;
use tc_macs::{Mac, MacInit};
use tc_params::KeyRef;

use crate::scalar::bits_to_int;
use crate::{EcdsaScalar, KCalculator};

/// RFC 6979 的 HMAC 暫時純量計算器。
pub struct HMacKCalculator<D, S> {
    hmac: HMac<D>,
    k: Vec<u8>,
    v: Vec<u8>,
    n: Option<S>,
}

impl<D: Digest, S: EcdsaScalar> HMacKCalculator<D, S> {
    /// 使用指定摘要建立尚未初始化的計算器。
    pub fn new(digest: D) -> Self {
        let hmac = HMac::new(digest);
        let size = hmac.mac_size();
        Self {
            hmac,
            k: vec![0; size],
            v: vec![1; size],
            n: None,
        }
    }

    /// 以群階、私密純量與已完成的訊息雜湊初始化。
    pub fn init(&mut self, n: &S, d: &S, message_hash: &[u8]) {
        self.n = Some(*n);
        let mut m = bits_to_int(n, message_hash).expect("雜湊截斷後必定符合純量寬度");
        if m >= *n {
            m = m.sub_public(n);
        }
        let size = n.bit_length().div_ceil(8);
        let x = d.to_be_bytes_padded(size);
        let m = m.to_be_bytes_padded(size);

        self.k.fill(0);
        self.v.fill(1);

        let marker = [0_u8];
        self.k = Self::hmac(&mut self.hmac, &self.k, &[&self.v, &marker, &x, &m]);
        self.v = Self::hmac(&mut self.hmac, &self.k, &[&self.v]);

        let marker = [1_u8];
        self.k = Self::hmac(&mut self.hmac, &self.k, &[&self.v, &marker, &x, &m]);
        self.v = Self::hmac(&mut self.hmac, &self.k, &[&self.v]);
    }

    // TODO(SM2): 在第一輪 K 更新加入 RFC 6979 3.6 額外輸入的 hook。
    #[allow(dead_code)]
    fn init_additional_input_0(&mut self, _input: &[u8]) {}

    // TODO(SM2): 在第二輪 K 更新加入 RFC 6979 3.6 額外輸入的 hook。
    #[allow(dead_code)]
    fn init_additional_input_1(&mut self, _input: &[u8]) {}

    fn hmac(hmac: &mut HMac<D>, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        MacInit::init(hmac, &KeyRef::new(key)).expect("HMAC 金鑰初始化不會失敗");
        for part in parts {
            hmac.update(part).expect("HMAC 已初始化");
        }
        let mut output = vec![0; hmac.mac_size()];
        hmac.do_final(&mut output).expect("HMAC 輸出長度正確");
        output
    }
}

impl<D: Digest, S: EcdsaScalar> KCalculator<S> for HMacKCalculator<D, S> {
    fn is_deterministic(&self) -> bool {
        true
    }

    /// 產生下一個 `k`。
    ///
    /// RFC 6979 的拒絕取樣迴圈是變動時間；常用曲線遇到重試的機率極低，且與
    /// Bouncy Castle 行為一致。
    fn next_k(&mut self) -> S {
        let n = self.n.expect("HMacKCalculator 必須先初始化");
        let size = n.bit_length().div_ceil(8);
        loop {
            let mut t = Vec::with_capacity(size);
            while t.len() < size {
                self.v = Self::hmac(&mut self.hmac, &self.k, &[&self.v]);
                let remaining = size - t.len();
                t.extend_from_slice(&self.v[..remaining.min(self.v.len())]);
            }
            let candidate = bits_to_int(&n, &t).expect("候選值必定符合純量寬度");
            if !candidate.is_zero() && candidate < n {
                return candidate;
            }

            let marker = [0_u8];
            self.k = Self::hmac(&mut self.hmac, &self.k, &[&self.v, &marker]);
            self.v = Self::hmac(&mut self.hmac, &self.k, &[&self.v]);
        }
    }
}
