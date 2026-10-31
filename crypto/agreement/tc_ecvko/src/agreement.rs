use crate::{EcVkoError, EcVkoParams};
use alloc::vec;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// BC 的 `ECVkoAgreement`，RFC 7836 4.3 的 GOST VKO：共享點 (h·UKM·d)·Q 的座標以小端序
/// 串接後雜湊，結果長度是雜湊的長度。RFC 7836 用 GOST R 34.11-2012 與 GOST 曲線；以常數
/// 時間的曲線上的金鑰初始化，私鑰才不會外洩。
pub struct EcVkoAgreement<C: Curve<Scalar = PaddedBigUint>, D> {
    digest: D,
    state: Option<State<C>>,
}

/// `init` 收下的私鑰與 UKM 解讀成的整數。
struct State<C: Curve<Scalar = PaddedBigUint>> {
    key: EcPrivateKey<C>,
    ukm: PaddedBigUint,
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> EcVkoAgreement<C, D> {
    /// 以 `digest` 雜湊共享點、尚未 `init` 的協商。常數時間。
    pub fn new(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> AgreementInit<EcVkoParams<C>>
    for EcVkoAgreement<C, D>
{
    type Error = EcVkoError;

    /// BC 的 `Init`：保存私鑰的複本（drop 時清除 d），UKM 以小端序解讀成整數；曲線要有
    /// 階。變動時間：只依公開的 UKM 與網域。
    fn init(&mut self, params: &EcVkoParams<C>) -> Result<(), EcVkoError> {
        self.state = None;
        params
            .key()
            .g()
            .curve()
            .order()
            .ok_or(EcVkoError::MissingOrder)?;
        let mut ukm = params.ukm().to_vec();
        ukm.reverse();
        let Ok(ukm) = PaddedBigUint::from_be(&ukm);
        self.state = Some(State {
            key: params.key().clone(),
            ukm,
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> Agreement for EcVkoAgreement<C, D> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcVkoError;

    /// BC 的 `AgreementSize`：雜湊的長度。常數時間。
    fn agreement_size(&self) -> usize {
        self.digest.digest_size()
    }

    /// BC 的 `CalculateAgreement`：對方的公鑰要在同一個網域、不是無窮遠點；
    /// P = (h·UKM·d mod n)·Q 不得為無窮遠點；結果是 H(x_P ‖ y_P)，座標各以小端序編成域的
    /// 位元組數。對私鑰與 P 是常數時間：h·UKM 只依公開值，乘上 d 用模乘，乘點用常數時間
    /// 的曲線。
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcVkoError> {
        let state = self.state.as_ref().ok_or(EcVkoError::NotInitialized)?;
        let output = output
            .get_mut(..self.agreement_size())
            .ok_or(EcVkoError::BufferTooSmall)?;
        let g = state.key.g();
        if public_key.g() != g {
            return Err(EcVkoError::DomainMismatch);
        }
        let curve = g.curve();
        let n = NonZero::new(curve.order().ok_or(EcVkoError::MissingOrder)?.clone())
            .ok_or(EcVkoError::MissingOrder)?;
        let h = curve
            .cofactor()
            .cloned()
            .unwrap_or_else(|| PaddedBigUint::from(1u8));
        let hu = h.mod_mul(&state.ukm, &n);
        let hd = Zeroizing::new(hu.mod_mul(state.key.d(), &n));

        let q = clean_point(curve.clone(), public_key.q())
            .ok()
            .filter(|q| !q.is_infinity())
            .ok_or(EcVkoError::InvalidPublicKey)?;
        let p = C::multiply(&q, &hd).normalize();
        if p.is_infinity() {
            return Err(EcVkoError::InvalidAgreement);
        }

        let mut digest = self.digest.clone();
        digest.reset();
        for coordinate in [p.x(), p.y()] {
            let coordinate = coordinate.expect("a finite point");
            let mut bytes = Zeroizing::new(vec![0u8; coordinate.encoded_length()]);
            coordinate.encode_to(&mut bytes);
            bytes.reverse();
            digest.update(&bytes);
        }
        digest.do_final(output);
        Ok(())
    }
}
