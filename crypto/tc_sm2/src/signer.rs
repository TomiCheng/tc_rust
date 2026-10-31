use crate::user_id::{MAX_USER_ID_LENGTH, coordinate, z};
use crate::{Sm2Curve, Sm2Error, Sm2SignerParams};
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_dsa::{DsaEncoding, DsaKCalculator, StandardDsaEncoding};
use tc_ec_core::{FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModAdd, ModInverse, ModMul, ModSub, NonZero};
use tc_signer::{Signer, SignerInit};
use tc_sm3::Sm3Digest;
use tc_zeroize::Zeroizing;

/// BC 的 `SM2Signer`：GM/T 0003 的 SM2 簽章。訊息前先接上 Z = H(ENTL ‖ ID ‖ a ‖ b ‖ G ‖ P)，
/// e = H(Z ‖ M)；簽章 r = (e + x₁) mod n，s = (1 + d)⁻¹ · (k − r·d) mod n，以 `N` 編碼，
/// 預設是 DER。k 由 `K` 提供：BC 固定用亂數的 `RandomDsaKCalculator`，這裡也可以用
/// RFC 6979 的確定性 k。雜湊預設是 SM3。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dsa::RandomDsaKCalculator;
/// use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
/// use tc_fp_custom::named_curves::SM2P256V1;
/// use tc_fp_custom::{SM2P256V1FieldElement, SecPCtCurve};
/// use tc_signer::{Signer, SignerInit};
/// use tc_sm2::{Sm2Signer, Sm2SignerParams};
///
/// let curve = SM2P256V1.ct_curve();
/// let g = SM2P256V1.ct_generator(&curve);
/// let mut rng = rand::rng();
/// let mut generator = EcKeyPairGenerator::<&SecPCtCurve<SM2P256V1FieldElement>>::new();
/// generator.init(EcKeyGenerationParams::new(g, &mut rng))?;
/// let (public_key, private_key) = generator.generate_key_pair()?;
///
/// // 簽章與驗證要用同一個使用者 ID。
/// let id = b"alice@example.com".to_vec();
/// let mut signer = Sm2Signer::new(RandomDsaKCalculator::new(rand::rng()));
/// signer.init(&Sm2SignerParams::new(private_key).with_user_id(id.clone()))?;
/// signer.update(b"hello")?;
/// let mut signature = vec![0; signer.max_signature_size()];
/// let length = signer.generate_signature(&mut signature)?;
///
/// let mut verifier = Sm2Signer::new(RandomDsaKCalculator::new(rand::rng()));
/// verifier.init(&Sm2SignerParams::new(public_key).with_user_id(id))?;
/// verifier.update(b"hello")?;
/// assert!(verifier.verify_signature(&signature[..length])?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Sm2Signer<C: Sm2Curve, K, D = Sm3Digest, N = StandardDsaEncoding> {
    k_calculator: K,
    digest: D,
    encoding: N,
    state: Option<State<C>>,
}

/// `init` 收下的金鑰、群的階與 Z，以及這則訊息是否已接上 Z。
struct State<C: Sm2Curve> {
    key: Key<C>,
    n: NonZero<PaddedBigUint>,
    field_length: usize,
    z: Vec<u8>,
    started: bool,
}

/// 簽章用的私鑰，或驗證用的公鑰。
enum Key<C: Sm2Curve> {
    Private(EcPrivateKey<C>),
    Public(EcPublicKey<C>),
}

impl<C: Sm2Curve, K> Sm2Signer<C, K> {
    /// BC 的 `SM2Signer()`：SM3 與 DER，k 由 `k_calculator` 提供。常數時間。
    pub fn new(k_calculator: K) -> Self {
        Self::with_digest(k_calculator, Sm3Digest::new())
    }
}

impl<C: Sm2Curve, K, D> Sm2Signer<C, K, D> {
    /// BC 的 `SM2Signer(digest)`：另一種雜湊，編碼仍是 DER。常數時間。
    pub fn with_digest(k_calculator: K, digest: D) -> Self {
        Self {
            k_calculator,
            digest,
            encoding: StandardDsaEncoding,
            state: None,
        }
    }
}

impl<C: Sm2Curve, K, D, N> Sm2Signer<C, K, D, N> {
    /// BC 的 `SM2Signer(encoding, digest)`：換掉簽章編碼，例如
    /// `tc_dsa::PlainDsaEncoding`。常數時間。
    pub fn with_encoding<M>(self, encoding: M) -> Sm2Signer<C, K, D, M> {
        Sm2Signer {
            k_calculator: self.k_calculator,
            digest: self.digest,
            encoding,
            state: None,
        }
    }
}

impl<C: Sm2Curve, K, D: Digest + Clone, N> Sm2Signer<C, K, D, N> {
    /// 共用的 `init`：檢查使用者 ID，算出 Z，開始新的訊息。變動時間：只處理公開的值；
    /// 私鑰的公鑰點由呼叫端先算好。
    fn start(&mut self, key: Key<C>, user_id: &[u8], point: &C::Point) -> Result<(), Sm2Error> {
        if user_id.len() >= MAX_USER_ID_LENGTH {
            return Err(Sm2Error::InvalidUserId);
        }
        let g = match &key {
            Key::Private(key) => key.g(),
            Key::Public(key) => key.g(),
        };
        let curve = g.curve();
        let n = NonZero::new(curve.order().ok_or(Sm2Error::MissingOrder)?.clone())
            .ok_or(Sm2Error::MissingOrder)?;
        let field_length = curve.one().encoded_length();
        let z = z::<C, D>(&self.digest, user_id, g, point, field_length);
        self.digest.reset();
        self.state = Some(State {
            key,
            n,
            field_length,
            z,
            started: false,
        });
        Ok(())
    }

    /// BC 的 `CheckData`：訊息的第一個位元組之前先接上 Z。`init` 之前回傳錯誤。常數時間：
    /// Z 是公開的。
    fn begin(&mut self) -> Result<&mut State<C>, Sm2Error> {
        let state = self.state.as_mut().ok_or(Sm2Error::NotInitialized)?;
        if !state.started {
            self.digest.update(&state.z);
            state.started = true;
        }
        Ok(state)
    }

    /// e = H(Z ‖ M)，結束這則訊息。常數時間程度同雜湊。
    fn finish(&mut self) -> Result<(PaddedBigUint, Vec<u8>), Sm2Error> {
        self.begin()?;
        let mut hash = vec![0u8; self.digest.digest_size()];
        self.digest.do_final(&mut hash);
        if let Some(state) = self.state.as_mut() {
            state.started = false;
        }
        let Ok(e) = PaddedBigUint::from_be(&hash);
        Ok((e, hash))
    }
}

/// 有限點的 x 座標當作整數。對座標是常數時間。
fn x_coordinate<P: Point>(point: &P, field_length: usize) -> PaddedBigUint {
    let bytes = coordinate(point.x(), field_length);
    let Ok(x) = PaddedBigUint::from_be(&bytes);
    x
}

impl<C: Sm2Curve, K, D: Digest + Clone, N> SignerInit<Sm2SignerParams<EcPrivateKey<C>>>
    for Sm2Signer<C, K, D, N>
{
    type Error = Sm2Error;

    /// BC 的 `Init(true, …)`：d 要在 `[1, n - 2]`，算出公鑰點與 Z。失敗時維持未初始化。
    /// 對 d 是常數時間：乘點用常數時間的曲線，範圍檢查只透露是否通過。
    fn init(&mut self, params: &Sm2SignerParams<EcPrivateKey<C>>) -> Result<(), Sm2Error> {
        self.state = None;
        let key = params.key();
        let curve = key.g().curve();
        let n = curve.order().ok_or(Sm2Error::MissingOrder)?;
        if *key.d() >= n - 1u32 {
            return Err(Sm2Error::PrivateKeyOutOfRange);
        }
        let point = C::multiply(key.g(), key.d()).normalize();
        self.start(Key::Private(key.clone()), params.user_id(), &point)
    }
}

impl<C: Sm2Curve, K, D: Digest + Clone, N> SignerInit<Sm2SignerParams<EcPublicKey<C>>>
    for Sm2Signer<C, K, D, N>
{
    type Error = Sm2Error;

    /// BC 的 `Init(false, …)`：算出 Z。失敗時維持未初始化。變動時間：只處理公開的值。
    fn init(&mut self, params: &Sm2SignerParams<EcPublicKey<C>>) -> Result<(), Sm2Error> {
        self.state = None;
        let key = params.key();
        let point = key.q().normalize();
        self.start(Key::Public(key.clone()), params.user_id(), &point)
    }
}

impl<C: Sm2Curve, K, D: Digest + Clone, N> SignerInit<EcPrivateKey<C>> for Sm2Signer<C, K, D, N> {
    type Error = Sm2Error;

    /// 以 BC 預設的使用者 ID 簽章。對 d 是常數時間，同 [`Sm2SignerParams`] 的 `init`。
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), Sm2Error> {
        SignerInit::init(self, &Sm2SignerParams::new(key.clone()))
    }
}

impl<C: Sm2Curve, K, D: Digest + Clone, N> SignerInit<EcPublicKey<C>> for Sm2Signer<C, K, D, N> {
    type Error = Sm2Error;

    /// 以 BC 預設的使用者 ID 驗證。變動時間：只處理公開的值。
    fn init(&mut self, key: &EcPublicKey<C>) -> Result<(), Sm2Error> {
        SignerInit::init(self, &Sm2SignerParams::new(key.clone()))
    }
}

impl<C, K, D, N> Signer for Sm2Signer<C, K, D, N>
where
    C: Sm2Curve,
    K: DsaKCalculator<PaddedBigUint>,
    D: Digest + Clone,
    N: DsaEncoding,
{
    type Error = Sm2Error;

    /// 編碼依群的階最多佔的位元組數。`init` 之前呼叫會 panic。變動時間：只能用於公開值，
    /// 階是公開的。
    fn max_signature_size(&self) -> usize {
        let state = self.state.as_ref().expect("the signer is initialized");
        self.encoding.max_encoding_size(&state.n)
    }

    /// 把 `input` 加進雜湊，第一次前先接上 Z。`init` 之前回傳錯誤。常數時間程度同雜湊。
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        self.begin()?;
        self.digest.update(input);
        Ok(())
    }

    /// BC 的 `GenerateSignature`：抽 k，r = (e + x₁) mod n，r 為零或 r + k = n 時重抽；
    /// s = (1 + d)⁻¹ · (k − r·d) mod n，為零時重抽；編碼進 `output`。以公鑰初始化時回傳
    /// 錯誤。對 d 與 k 是常數時間：乘點用常數時間的曲線，模運算與反元素是常數時間的；只有
    /// 重抽的次數反映在時間上，而它與最後的 k 無關。
    fn generate_signature(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        if !matches!(
            self.state.as_ref().ok_or(Sm2Error::NotInitialized)?.key,
            Key::Private(_)
        ) {
            return Err(Sm2Error::WrongKeyForSigning);
        }
        let (e, hash) = self.finish()?;
        let state = self.state.as_ref().expect("checked above");
        let Key::Private(key) = &state.key else {
            unreachable!("checked above");
        };
        let n = &state.n;
        let zero = PaddedBigUint::from(0u8);
        let one = PaddedBigUint::from(1u8);
        let inverse = Zeroizing::new(
            key.d()
                .mod_add(&one, n)
                .mod_inverse(n)
                .ok_or(Sm2Error::PrivateKeyOutOfRange)?,
        );
        self.k_calculator.init(n, key.d(), &hash);
        let (r, s) = loop {
            let (k, r) = loop {
                let k = Zeroizing::new(self.k_calculator.next_k());
                let p = C::multiply(key.g(), &k).normalize();
                let r = e.mod_add(&x_coordinate(&p, state.field_length), n);
                if r != zero && r.mod_add(&k, n) != zero {
                    break (k, r);
                }
            };
            let rd = Zeroizing::new(r.mod_mul(key.d(), n));
            let difference = Zeroizing::new(k.mod_sub(&rd, n));
            let s = inverse.mod_mul(&difference, n);
            if s != zero {
                break (r, s);
            }
        };
        self.encoding
            .encode(n, &r, &s, output)
            .map_err(Sm2Error::Encoding)
    }

    /// BC 的 `VerifySignature`：r 與 s 要在 `[1, n)`，t = (r + s) mod n 不為零，
    /// (x₁, y₁) = s·G + t·P 不是無窮遠點，(e + x₁) mod n 要等於 r；解不出的簽章視為不符。
    /// 以私鑰初始化時回傳錯誤。變動時間：只能用於公開值，簽章與訊息都是公開的。
    fn verify_signature(&mut self, signature: &[u8]) -> Result<bool, Self::Error> {
        if !matches!(
            self.state.as_ref().ok_or(Sm2Error::NotInitialized)?.key,
            Key::Public(_)
        ) {
            return Err(Sm2Error::WrongKeyForSigning);
        }
        let (e, _) = self.finish()?;
        let state = self.state.as_ref().expect("checked above");
        let Key::Public(key) = &state.key else {
            unreachable!("checked above");
        };
        let n = &state.n;
        let Ok((r, s)) = self.encoding.decode(n, signature) else {
            return Ok(false);
        };
        let zero = PaddedBigUint::from(0u8);
        if r == zero || s == zero {
            return Ok(false);
        }
        let t = r.mod_add(&s, n);
        if t == zero {
            return Ok(false);
        }
        let point = C::multiply(key.g(), &s)
            .add(&C::multiply(key.q(), &t))
            .normalize();
        if point.is_infinity() {
            return Ok(false);
        }
        Ok(e.mod_add(&x_coordinate(&point, state.field_length), n) == r)
    }

    /// BC 的 `Reset`：丟掉訊息，保留金鑰與 Z。常數時間。
    fn reset(&mut self) {
        self.digest.reset();
        if let Some(state) = self.state.as_mut() {
            state.started = false;
        }
    }
}
