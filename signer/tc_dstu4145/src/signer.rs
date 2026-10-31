use crate::{Dstu4145Curve, Dstu4145Error};
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_dsa::{Dsa, DsaInit, DsaKCalculator};
use tc_ec_core::{FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModAdd, ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// BC 的 `Dstu4145Signer`：烏克蘭 DSTU 4145-2002 的 GF(2^m) 橢圓曲線簽章，每個簽章的
/// 秘密 e 由 `K` 抽取，BC 用亂數，即 `RandomDsaKCalculator`。公鑰是 Q = −d·G，見
/// [`Dstu4145KeyPairGenerator`](crate::Dstu4145KeyPairGenerator)。雜湊以小端序讀成域元素。
///
/// 以常數時間的曲線上的金鑰初始化，d 與 e 才不會外洩。`tc_f2m_curve` 的域乘法在有
/// PCLMULQDQ 的 x86 上是常數時間，其他平台查表，帶著它揭露的 cache-timing 側通道，乘點
/// 與 h·x 都受影響。
pub struct Dstu4145Signer<C: Dstu4145Curve, K> {
    k_calculator: K,
    state: Option<State<C>>,
}

/// `init` 收下的金鑰、群的階與域的次數。
struct State<C: Dstu4145Curve> {
    key: Key<C>,
    n: PaddedBigUint,
    field_size: u32,
}

/// 簽章用的私鑰或驗證用的公鑰。
enum Key<C: Dstu4145Curve> {
    Signing(EcPrivateKey<C>),
    Verifying(EcPublicKey<C>),
}

impl<C: Dstu4145Curve, K> Dstu4145Signer<C, K> {
    /// 以 `k_calculator` 抽取 e、尚未 `init` 的簽章器。常數時間。
    pub const fn new(k_calculator: K) -> Self {
        Self {
            k_calculator,
            state: None,
        }
    }

    /// 依 G 的曲線取出階與域的次數，裝上金鑰。變動時間：只依公開的網域。
    fn init_key(&mut self, g: &C::Point, key: Key<C>) -> Result<(), Dstu4145Error> {
        self.state = None;
        let curve = g.curve();
        let n = curve.order().cloned().ok_or(Dstu4145Error::MissingOrder)?;
        if n == PaddedBigUint::from(0u8) {
            return Err(Dstu4145Error::MissingOrder);
        }
        self.state = Some(State {
            key,
            n,
            field_size: curve.field_size(),
        });
        Ok(())
    }
}

impl<C: Dstu4145Curve, K> DsaInit<EcPrivateKey<C>> for Dstu4145Signer<C, K> {
    type Error = Dstu4145Error;

    /// 保存簽章用的私鑰複本，drop 時清除 d；曲線要有階。變動時間：只依公開的網域。
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), Dstu4145Error> {
        self.init_key(key.g(), Key::Signing(key.clone()))
    }
}

impl<C: Dstu4145Curve, K> DsaInit<EcPublicKey<C>> for Dstu4145Signer<C, K> {
    type Error = Dstu4145Error;

    /// 保存驗證用的公鑰 Q = −d·G；曲線要有階。變動時間：只依公開的網域。
    fn init(&mut self, key: &EcPublicKey<C>) -> Result<(), Dstu4145Error> {
        self.init_key(key.g(), Key::Verifying(key.clone()))
    }
}

impl<C, K> Dsa for Dstu4145Signer<C, K>
where
    C: Dstu4145Curve,
    K: DsaKCalculator<PaddedBigUint>,
{
    type Integer = PaddedBigUint;
    type Error = Dstu4145Error;

    /// 群的階 n。`init` 之前呼叫會 panic。常數時間。
    fn order(&self) -> &PaddedBigUint {
        &self.state.as_ref().expect("the signer is initialized").n
    }

    /// BC 的 `GenerateSignature`：h 是雜湊的域元素（零時取 1），抽 e 算 F = (e·G).x，
    /// r = h·F 截成 n 的位元數減一，s = r·d + e mod n；F、r 或 s 為零時重抽。對 d 與 e 是
    /// 常數時間，除了重抽的次數與上述 F2m 乘法的側通道：模運算是常數時間，乘點用常數時間
    /// 的曲線。
    fn generate_signature(
        &mut self,
        message: &[u8],
    ) -> Result<(PaddedBigUint, PaddedBigUint), Dstu4145Error> {
        let state = self.state.as_ref().ok_or(Dstu4145Error::NotInitialized)?;
        let Key::Signing(key) = &state.key else {
            return Err(Dstu4145Error::NotForSigning);
        };
        let n = NonZero::new(state.n.clone()).expect("init checked n");
        let g = key.g();
        let h = hash_to_element(&g.curve(), state.field_size, message);
        let zero = PaddedBigUint::from(0u8);

        self.k_calculator.init(&state.n, key.d(), message);
        loop {
            let e = Zeroizing::new(self.k_calculator.next_k());
            let Some(fe) = C::multiply(g, &e).normalize().x() else {
                continue;
            };
            if fe.is_zero() {
                continue;
            }
            let r = element_to_integer(&state.n, &h.multiply(&fe));
            if r == zero {
                continue;
            }
            let product = Zeroizing::new(r.mod_mul(key.d(), &n));
            let s = product.mod_add(&e, &n);
            if s != zero {
                return Ok((r, s));
            }
        }
    }

    /// BC 的 `VerifySignature`：r 與 s 要在 `[1, n − 1]`，R = s·G + r·Q 不得為無窮遠點，
    /// h·R.x 截成 n 的位元數減一要等於 r。以私鑰初始化時回傳錯誤。變動時間：只能用於公開值，
    /// 金鑰、訊息與簽章都是公開的。
    fn verify_signature(
        &self,
        message: &[u8],
        r: &PaddedBigUint,
        s: &PaddedBigUint,
    ) -> Result<bool, Dstu4145Error> {
        let state = self.state.as_ref().ok_or(Dstu4145Error::NotInitialized)?;
        let Key::Verifying(key) = &state.key else {
            return Err(Dstu4145Error::NotForVerifying);
        };
        let n = &state.n;
        let zero = PaddedBigUint::from(0u8);
        if *r == zero || *s == zero || r >= n || s >= n {
            return Ok(false);
        }
        let g = key.g();
        let h = hash_to_element(&g.curve(), state.field_size, message);
        let point = C::multiply(g, s).add(&C::multiply(key.q(), r)).normalize();
        let Some(x) = point.x() else {
            return Ok(false);
        };
        Ok(element_to_integer(n, &h.multiply(&x)) == *r)
    }
}

/// BC 的 `Hash2FieldElement`：雜湊以小端序讀成整數，截成 m 位元，做成域元素；零時取 1。
/// 變動時間：只能用於公開值，雜湊是公開的。
fn hash_to_element<C: Dstu4145Curve>(curve: &C, field_size: u32, hash: &[u8]) -> C::Field {
    let length = curve.one().encoded_length();
    let mut bytes = vec![0u8; length];
    for (byte, input) in bytes.iter_mut().rev().zip(hash) {
        *byte = *input;
    }
    keep_low_bits(&mut bytes, field_size as usize);
    let element = curve
        .element(&bytes)
        .expect("m bits fit the field's encoding");
    if element.is_zero() {
        curve.one()
    } else {
        element
    }
}

/// BC 的 `FieldElement2Integer`：域元素的整數截成 n 的位元數減一。常數時間程度同域元素的
/// 編碼：只依長度分支。
fn element_to_integer<F: FieldElement>(n: &PaddedBigUint, element: &F) -> PaddedBigUint {
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; element.encoded_length()]);
    element.encode_to(&mut bytes);
    keep_low_bits(&mut bytes, n.bits() as usize - 1);
    let Ok(value) = PaddedBigUint::from_be(&bytes);
    value
}

/// BC 的 `Truncate`：大端序的 `bytes` 只留低 `bits` 位元。常數時間：只依長度分支。
fn keep_low_bits(bytes: &mut [u8], bits: usize) {
    let length = bytes.len();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let low = (length - 1 - index) * 8;
        if low >= bits {
            *byte = 0;
        } else if bits - low < 8 {
            *byte &= (1u8 << (bits - low)) - 1;
        }
    }
}
