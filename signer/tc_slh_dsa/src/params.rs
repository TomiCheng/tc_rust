/// SLH-DSA 用的雜湊家族。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Sha2,
    Shake,
}

/// BC 的 `SlhDsaParameters` 與 `SlhDsaParameterSet`：FIPS 205 的十二組參數。只是常數。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlhDsaParameters {
    name: &'static str,
    family: Family,
    n: usize,
    d: usize,
    a: usize,
    k: usize,
    h: usize,
}

macro_rules! set {
    ($name:literal, $family:ident, $n:expr, $d:expr, $a:expr, $k:expr, $h:expr) => {
        SlhDsaParameters {
            name: $name,
            family: Family::$family,
            n: $n,
            d: $d,
            a: $a,
            k: $k,
            h: $h,
        }
    };
}

impl SlhDsaParameters {
    /// SLH-DSA-SHA2-128s。
    pub const SHA2_128S: Self = set!("SLH-DSA-SHA2-128s", Sha2, 16, 7, 12, 14, 63);
    /// SLH-DSA-SHAKE-128s。
    pub const SHAKE_128S: Self = set!("SLH-DSA-SHAKE-128s", Shake, 16, 7, 12, 14, 63);
    /// SLH-DSA-SHA2-128f。
    pub const SHA2_128F: Self = set!("SLH-DSA-SHA2-128f", Sha2, 16, 22, 6, 33, 66);
    /// SLH-DSA-SHAKE-128f。
    pub const SHAKE_128F: Self = set!("SLH-DSA-SHAKE-128f", Shake, 16, 22, 6, 33, 66);
    /// SLH-DSA-SHA2-192s。
    pub const SHA2_192S: Self = set!("SLH-DSA-SHA2-192s", Sha2, 24, 7, 14, 17, 63);
    /// SLH-DSA-SHAKE-192s。
    pub const SHAKE_192S: Self = set!("SLH-DSA-SHAKE-192s", Shake, 24, 7, 14, 17, 63);
    /// SLH-DSA-SHA2-192f。
    pub const SHA2_192F: Self = set!("SLH-DSA-SHA2-192f", Sha2, 24, 22, 8, 33, 66);
    /// SLH-DSA-SHAKE-192f。
    pub const SHAKE_192F: Self = set!("SLH-DSA-SHAKE-192f", Shake, 24, 22, 8, 33, 66);
    /// SLH-DSA-SHA2-256s。
    pub const SHA2_256S: Self = set!("SLH-DSA-SHA2-256s", Sha2, 32, 8, 14, 22, 64);
    /// SLH-DSA-SHAKE-256s。
    pub const SHAKE_256S: Self = set!("SLH-DSA-SHAKE-256s", Shake, 32, 8, 14, 22, 64);
    /// SLH-DSA-SHA2-256f。
    pub const SHA2_256F: Self = set!("SLH-DSA-SHA2-256f", Sha2, 32, 17, 9, 35, 68);
    /// SLH-DSA-SHAKE-256f。
    pub const SHAKE_256F: Self = set!("SLH-DSA-SHAKE-256f", Shake, 32, 17, 9, 35, 68);

    /// 全部十二組。
    pub const ALL: [Self; 12] = [
        Self::SHA2_128S,
        Self::SHAKE_128S,
        Self::SHA2_128F,
        Self::SHAKE_128F,
        Self::SHA2_192S,
        Self::SHAKE_192S,
        Self::SHA2_192F,
        Self::SHAKE_192F,
        Self::SHA2_256S,
        Self::SHAKE_256S,
        Self::SHA2_256F,
        Self::SHAKE_256F,
    ];

    /// 名稱，例如 "SLH-DSA-SHA2-128s"。常數時間。
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// 安全參數 n，種子與節點的位元組數。常數時間。
    pub const fn n(&self) -> usize {
        self.n
    }

    /// 公鑰 PK.seed ‖ PK.root 的位元組數。常數時間。
    pub const fn public_key_length(&self) -> usize {
        2 * self.n
    }

    /// 私鑰 SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root 的位元組數。常數時間。
    pub const fn private_key_length(&self) -> usize {
        4 * self.n
    }

    /// 簽章 R ‖ SIG_FORS ‖ SIG_HT 的位元組數。常數時間。
    pub const fn signature_length(&self) -> usize {
        (1 + self.k * (1 + self.a) + self.h + self.d * self.wots_len()) * self.n
    }

    pub(crate) const fn family(&self) -> Family {
        self.family
    }

    pub(crate) const fn d(&self) -> usize {
        self.d
    }

    pub(crate) const fn a(&self) -> usize {
        self.a
    }

    pub(crate) const fn k(&self) -> usize {
        self.k
    }

    pub(crate) const fn h(&self) -> usize {
        self.h
    }

    pub(crate) const fn h_prime(&self) -> usize {
        self.h / self.d
    }

    // lg w = 4, so len1 = 2n and len2 = 3
    pub(crate) const fn wots_len1(&self) -> usize {
        2 * self.n
    }

    pub(crate) const fn wots_len(&self) -> usize {
        self.wots_len1() + 3
    }
}
