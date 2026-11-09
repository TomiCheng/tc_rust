/// BC 的 `MLDsaParameters` 與 `MLDsaParameterSet`：FIPS 204 的三組參數。只是常數。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlDsaParameters {
    name: &'static str,
    k: usize,
    l: usize,
    eta: i32,
    tau: usize,
    beta: i32,
    gamma1: i32,
    gamma2: i32,
    omega: usize,
    c_tilde: usize,
}

impl MlDsaParameters {
    /// ML-DSA-44：(k, l) = (4, 4)。
    pub const ML_DSA_44: Self = Self {
        name: "ML-DSA-44",
        k: 4,
        l: 4,
        eta: 2,
        tau: 39,
        beta: 78,
        gamma1: 1 << 17,
        gamma2: (crate::poly::Q - 1) / 88,
        omega: 80,
        c_tilde: 32,
    };

    /// ML-DSA-65：(k, l) = (6, 5)。
    pub const ML_DSA_65: Self = Self {
        name: "ML-DSA-65",
        k: 6,
        l: 5,
        eta: 4,
        tau: 49,
        beta: 196,
        gamma1: 1 << 19,
        gamma2: (crate::poly::Q - 1) / 32,
        omega: 55,
        c_tilde: 48,
    };

    /// ML-DSA-87：(k, l) = (8, 7)。
    pub const ML_DSA_87: Self = Self {
        name: "ML-DSA-87",
        k: 8,
        l: 7,
        eta: 2,
        tau: 60,
        beta: 120,
        gamma1: 1 << 19,
        gamma2: (crate::poly::Q - 1) / 32,
        omega: 75,
        c_tilde: 64,
    };

    /// 名稱，例如 "ML-DSA-65"。常數時間。
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// 公鑰 ρ ‖ t1 的位元組數。常數時間。
    pub const fn public_key_length(&self) -> usize {
        32 + self.k * 320
    }

    /// 私鑰 ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 的位元組數。常數時間。
    pub const fn private_key_length(&self) -> usize {
        32 + 32 + 64 + (self.l + self.k) * self.eta_packed_bytes() + self.k * 416
    }

    /// 簽章 c̃ ‖ z ‖ h 的位元組數。常數時間。
    pub const fn signature_length(&self) -> usize {
        self.c_tilde + self.l * self.z_packed_bytes() + self.omega + self.k
    }

    pub(crate) const fn k(&self) -> usize {
        self.k
    }

    pub(crate) const fn l(&self) -> usize {
        self.l
    }

    pub(crate) const fn eta(&self) -> i32 {
        self.eta
    }

    pub(crate) const fn tau(&self) -> usize {
        self.tau
    }

    pub(crate) const fn beta(&self) -> i32 {
        self.beta
    }

    pub(crate) const fn gamma1(&self) -> i32 {
        self.gamma1
    }

    pub(crate) const fn gamma2(&self) -> i32 {
        self.gamma2
    }

    pub(crate) const fn omega(&self) -> usize {
        self.omega
    }

    pub(crate) const fn c_tilde(&self) -> usize {
        self.c_tilde
    }

    pub(crate) const fn eta_packed_bytes(&self) -> usize {
        if self.eta == 2 { 96 } else { 128 }
    }

    pub(crate) const fn z_packed_bytes(&self) -> usize {
        if self.gamma1 == 1 << 17 { 576 } else { 640 }
    }

    pub(crate) const fn w1_packed_bytes(&self) -> usize {
        if self.gamma2 == (crate::poly::Q - 1) / 88 {
            192
        } else {
            128
        }
    }
}
