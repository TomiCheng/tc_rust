use crate::{Sm2Curve, Sm2Error, Sm2KeyExchangePrivateParams, Sm2KeyExchangePublicParams};
use alloc::vec;
use alloc::vec::Vec;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_ec_core::{FieldElement, Point};
use tc_ec_key::EcPrivateKey;
use tc_modular::{ModAdd, ModMul, NonZero};
use tc_sm3::Sm3Digest;
use tc_zeroize::Zeroizing;

// BC 的 `CheckUserID`：ID 的位元數要放得進 16 位元的 ENTL。
const MAX_USER_ID_LENGTH: usize = 8192;

/// 金鑰確認的標籤，BC 的 `CalculateKeyWithConfirmation` 回傳的後半段。
///
/// 發起方：`to_send` 是要寄給回應方的 S_A（BC 的 S2），回應方的 S_B 已在計算時核對過，
/// `expected` 為 `None`。回應方：`to_send` 是要寄給發起方的 S_B（S1），`expected` 是之後
/// 要向發起方核對的 S_A（S2），請以常數時間比較。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sm2Confirmation {
    /// 要寄給對方的標籤。
    pub to_send: Vec<u8>,
    /// 回應方之後要核對的標籤。
    pub expected: Option<Vec<u8>>,
}

/// BC 的 `SM2KeyExchange`：雙方各有長期與臨時金鑰，交換公鑰與使用者 ID 後，各自算出
/// 同一個共享點 U，再以 KDF 導出金鑰；可另外以 S_A、S_B 互相確認。雜湊預設是 SM3。
///
/// 交換公鑰與確認標籤由呼叫端自行傳遞，同 BC；所以不實作 `tc_agreement` 的 trait：輸出的
/// 金鑰長度由呼叫端決定，確認還要多一個輸入與多個輸出。
pub struct Sm2KeyExchange<C: Sm2Curve, D = Sm3Digest> {
    digest: D,
    state: Option<State<C>>,
}

/// `init` 後的狀態。
struct State<C: Sm2Curve> {
    initiator: bool,
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    static_point: C::Point,
    ephemeral_point: C::Point,
    user_id: Vec<u8>,
    w: u32,
}

impl<C: Sm2Curve> Sm2KeyExchange<C, Sm3Digest> {
    /// 以 SM3 為雜湊、尚未 `init` 的金鑰交換。常數時間。
    pub fn new() -> Self {
        Self::with_digest(Sm3Digest::new())
    }
}

impl<C: Sm2Curve> Default for Sm2KeyExchange<C, Sm3Digest> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Sm2Curve, D: Digest + Clone> Sm2KeyExchange<C, D> {
    /// 以 `digest` 為雜湊的金鑰交換，同 BC 的 `SM2KeyExchange(IDigest)`。常數時間。
    pub fn with_digest(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }

    /// BC 的 `Init`：兩把私鑰要在同一個網域，使用者 ID 短於 8192 位元組；算出兩把公鑰點。
    /// w 照 GM/T 0003 取 ⌈⌈log₂ n⌉ / 2⌉ − 1；BC 改用域的位元數，在 SM2 的曲線上兩者相同。
    /// 對兩把私鑰是常數時間：曲線是常數時間的。
    pub fn init(&mut self, params: &Sm2KeyExchangePrivateParams<C>) -> Result<(), Sm2Error> {
        self.state = None;
        let g = params.static_key().g();
        if params.ephemeral_key().g() != g {
            return Err(Sm2Error::DomainMismatch);
        }
        if params.user_id().len() >= MAX_USER_ID_LENGTH {
            return Err(Sm2Error::InvalidUserId);
        }
        let n = g.curve().order().ok_or(Sm2Error::MissingOrder)?.clone();
        self.state = Some(State {
            initiator: params.is_initiator(),
            static_point: C::multiply(g, params.static_key().d()).normalize(),
            ephemeral_point: C::multiply(g, params.ephemeral_key().d()).normalize(),
            static_key: params.static_key().clone(),
            ephemeral_key: params.ephemeral_key().clone(),
            user_id: params.user_id().to_vec(),
            w: n.bits().div_ceil(2) - 1,
        });
        Ok(())
    }

    /// BC 的 `CalculateKey`：導出 `key.len()` 位元組的共享金鑰寫入 `key`。對兩把私鑰與共享
    /// 點是常數時間；公開的公鑰與 ID 依值處理。
    pub fn calculate_key(
        &self,
        public: &Sm2KeyExchangePublicParams<C>,
        key: &mut [u8],
    ) -> Result<(), Sm2Error> {
        let state = self.state.as_ref().ok_or(Sm2Error::NotInitialized)?;
        let shared = self.shared(state, public)?;
        self.kdf(&shared, key);
        Ok(())
    }

    /// BC 的 `CalculateKeyWithConfirmation`：導出金鑰寫入 `key`，並算出確認標籤。發起方要
    /// 給回應方寄來的 S_B，以常數時間核對，不符時清除 `key` 並回傳錯誤；回應方不需要。
    /// 對兩把私鑰與共享點是常數時間；核對的結果由錯誤透露。
    pub fn calculate_key_with_confirmation(
        &self,
        confirmation_tag: Option<&[u8]>,
        public: &Sm2KeyExchangePublicParams<C>,
        key: &mut [u8],
    ) -> Result<Sm2Confirmation, Sm2Error> {
        let state = self.state.as_ref().ok_or(Sm2Error::NotInitialized)?;
        if state.initiator && confirmation_tag.is_none() {
            return Err(Sm2Error::MissingConfirmationTag);
        }
        let shared = self.shared(state, public)?;
        self.kdf(&shared, key);

        let field_length = shared.y.len();
        let own = &state.ephemeral_point;
        let other = &public.ephemeral_key().q().normalize();
        let (first, second) = if state.initiator {
            (own, other)
        } else {
            (other, own)
        };
        let mut inner = self.digest.clone();
        inner.reset();
        inner.update(&shared.x);
        inner.update(&shared.z_initiator);
        inner.update(&shared.z_responder);
        for point in [first, second] {
            inner.update(&coordinate(point.x(), field_length));
            inner.update(&coordinate(point.y(), field_length));
        }
        let mut inner_hash = Zeroizing::new(vec![0u8; self.digest.digest_size()]);
        inner.do_final(&mut inner_hash);
        let s1 = self.tag(0x02, &shared.y, &inner_hash);
        let s2 = self.tag(0x03, &shared.y, &inner_hash);

        if let Some(tag) = confirmation_tag.filter(|_| state.initiator) {
            if !fixed_time_eq(&s1, tag) {
                key.fill(0);
                return Err(Sm2Error::ConfirmationMismatch);
            }
            return Ok(Sm2Confirmation {
                to_send: s2,
                expected: None,
            });
        }
        Ok(Sm2Confirmation {
            to_send: s1,
            expected: Some(s2),
        })
    }

    /// BC 的 `CalculateU` 與 `GetZ`：對方的兩把公鑰要在同一個網域；
    /// tA = d_A + x̄₁·r_A，U = h·tA·(P_B + x̄₂·R_B) mod n，以兩次常數時間的乘點相加算出，
    /// U 為無窮遠點時回傳錯誤；Z 依角色排成發起方在前。對私鑰與 U 是常數時間：tA、k₁、k₂
    /// 以模加與模乘算出；x̄ 與 Z 只依公開的點與 ID。
    fn shared(
        &self,
        state: &State<C>,
        public: &Sm2KeyExchangePublicParams<C>,
    ) -> Result<Shared, Sm2Error> {
        let g = state.static_key.g();
        if public.static_key().g() != g || public.ephemeral_key().g() != g {
            return Err(Sm2Error::DomainMismatch);
        }
        if public.user_id().len() >= MAX_USER_ID_LENGTH {
            return Err(Sm2Error::InvalidUserId);
        }
        let curve = g.curve();
        let field_length = curve.one().encoded_length();
        let n = NonZero::new(curve.order().ok_or(Sm2Error::MissingOrder)?.clone())
            .ok_or(Sm2Error::MissingOrder)?;
        let h = curve
            .cofactor()
            .cloned()
            .unwrap_or_else(|| PaddedBigUint::from(1u8));

        let other_static = public.static_key().q().normalize();
        let other_ephemeral = public.ephemeral_key().q().normalize();
        let x1 = reduce::<C>(&state.ephemeral_point, state.w, field_length);
        let x2 = reduce::<C>(&other_ephemeral, state.w, field_length);
        let product = Zeroizing::new(x1.mod_mul(state.ephemeral_key.d(), &n));
        let t = Zeroizing::new(state.static_key.d().mod_add(&product, &n));
        let k1 = Zeroizing::new(h.mod_mul(&t, &n));
        let k2 = Zeroizing::new(k1.mod_mul(&x2, &n));
        let u = C::multiply(&other_static, &k1)
            .add(&C::multiply(&other_ephemeral, &k2))
            .normalize();
        if u.is_infinity() {
            return Err(Sm2Error::InvalidAgreement);
        }

        let own_z = self.z(&state.user_id, g, &state.static_point, field_length);
        let other_z = self.z(public.user_id(), g, &other_static, field_length);
        let (z_initiator, z_responder) = if state.initiator {
            (own_z, other_z)
        } else {
            (other_z, own_z)
        };
        Ok(Shared {
            x: coordinate(u.x(), field_length),
            y: coordinate(u.y(), field_length),
            z_initiator,
            z_responder,
        })
    }

    /// BC 的 `GetZ`：H(ENTL ‖ ID ‖ a ‖ b ‖ x_G ‖ y_G ‖ x_P ‖ y_P)，ENTL 是 ID 的位元數的兩個
    /// 大端序位元組。變動時間：只處理公開的值。
    fn z(&self, user_id: &[u8], g: &C::Point, point: &C::Point, field_length: usize) -> Vec<u8> {
        let curve = point.curve();
        let mut digest = self.digest.clone();
        digest.reset();
        let bits = (user_id.len() * 8) as u16;
        digest.update(&bits.to_be_bytes());
        digest.update(user_id);
        for element in [curve.a(), curve.b()] {
            let mut bytes = vec![0u8; field_length];
            element.encode_to(&mut bytes);
            digest.update(&bytes);
        }
        for p in [g, point] {
            digest.update(&coordinate(p.x(), field_length));
            digest.update(&coordinate(p.y(), field_length));
        }
        let mut z = vec![0u8; self.digest.digest_size()];
        digest.do_final(&mut z);
        z
    }

    /// BC 的 `Kdf`：H(x_U ‖ y_U ‖ Z_A ‖ Z_B ‖ ct)，ct 從 1 起算的大端序 32 位元計數，串接到
    /// 填滿 `key`。對 U 與金鑰是常數時間。
    fn kdf(&self, shared: &Shared, key: &mut [u8]) {
        let mut base = self.digest.clone();
        base.reset();
        base.update(&shared.x);
        base.update(&shared.y);
        base.update(&shared.z_initiator);
        base.update(&shared.z_responder);
        let mut block = Zeroizing::new(vec![0u8; self.digest.digest_size()]);
        for (counter, chunk) in (1u32..).zip(key.chunks_mut(block.len())) {
            let mut round = base.clone();
            round.update(&counter.to_be_bytes());
            round.do_final(&mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    /// BC 的 `S1`／`S2`：H(prefix ‖ y_U ‖ inner)。對 U 是常數時間。
    fn tag(&self, prefix: u8, y: &[u8], inner: &[u8]) -> Vec<u8> {
        let mut digest = self.digest.clone();
        digest.reset();
        digest.update(&[prefix]);
        digest.update(y);
        digest.update(inner);
        let mut tag = vec![0u8; self.digest.digest_size()];
        digest.do_final(&mut tag);
        tag
    }
}

/// 共享點 U 的座標與雙方的 Z，U 的座標用畢清除。
struct Shared {
    x: Zeroizing<Vec<u8>>,
    y: Zeroizing<Vec<u8>>,
    z_initiator: Vec<u8>,
    z_responder: Vec<u8>,
}

/// 有限點的一個座標，編成 `field_length` 位元組。對座標是常數時間。
fn coordinate<F: FieldElement>(element: Option<F>, field_length: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0u8; field_length]);
    element.expect("the point is finite").encode_to(&mut bytes);
    bytes
}

/// BC 的 `Reduce`：x̄ = 2^w + (x mod 2^w)，x 是點的 x 座標。變動時間：只用於公開的臨時
/// 公鑰。
fn reduce<C: Sm2Curve>(point: &C::Point, w: u32, field_length: usize) -> PaddedBigUint {
    let bytes = coordinate(point.x(), field_length);
    let Ok(x) = BigUint::from_be(&bytes);
    let mut bound = BigUint::from(0u8);
    bound.set_bit(w, true);
    let mut reduced = x % &bound;
    reduced.set_bit(w, true);
    PaddedBigUint::from(reduced)
}
