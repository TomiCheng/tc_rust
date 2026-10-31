//! BC 的 `JPakeUtilities`：J-PAKE 的基本運算。BC 公開它們，這裡只給 `JPakeParticipant`
//! 用；群組的運算集中在 [`Domain`]，以便重用 Montgomery 參數。

use crate::{JPakeError, JPakePrimeOrderGroup, JPakeZeroKnowledgeProof};
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomRange};
use tc_constant_time::{ConstantTimeEq, fixed_time_eq};
use tc_digest::Digest;
use tc_macs::{Hmac, KeyRef, Mac, MacInit};
use tc_modular::{ModMul, ModPow, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// 群組 p、q、g，與 p、q 的 Montgomery 參數。
pub(crate) struct Domain {
    p: PaddedMontyParams,
    q: PaddedMontyParams,
    g: PaddedBigUint,
}

impl Domain {
    /// 為 `group` 建好 Montgomery 參數；p、q 要是奇數。變動時間：只依公開的群組分支。
    pub(crate) fn new(group: &JPakePrimeOrderGroup) -> Result<Self, JPakeError> {
        let p = Odd::new(group.p().clone()).ok_or(JPakeError::ModulusNotPrime)?;
        let q = Odd::new(group.q().clone()).ok_or(JPakeError::OrderNotPrime)?;
        Ok(Self {
            p: PaddedMontyParams::new(p),
            q: PaddedMontyParams::new(q),
            g: group.g().clone(),
        })
    }

    /// 群組的生成元 g。常數時間。
    pub(crate) fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// 子群的階 q 的 Montgomery 參數。常數時間。
    pub(crate) fn q(&self) -> &PaddedMontyParams {
        &self.q
    }

    /// BC 的 `GenerateX1`：`[0, q − 1]` 中的均勻亂數，寬度同 q。對抽出的值是常數時間：
    /// 只有被丟棄的候選值多少會反映在時間上。
    pub(crate) fn generate_x1<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Zeroizing<PaddedBigUint> {
        let zero = PaddedBigUint::from(0u8);
        Zeroizing::new(PaddedBigUint::random_range(rng, &zero, self.q.modulus()))
    }

    /// BC 的 `GenerateX2`：`[1, q − 1]` 中的均勻亂數，寬度同 q。對抽出的值是常數時間：
    /// 只有被丟棄的候選值多少會反映在時間上。
    pub(crate) fn generate_x2<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Zeroizing<PaddedBigUint> {
        let one = PaddedBigUint::from(1u8);
        Zeroizing::new(PaddedBigUint::random_range(rng, &one, self.q.modulus()))
    }

    /// BC 的 `CalculateGx` 與 `CalculateA`：base^exponent mod p。對 exponent 是常數時間：
    /// 圈數只看它的寬度。
    pub(crate) fn power(&self, base: &PaddedBigUint, exponent: &PaddedBigUint) -> PaddedBigUint {
        let base = Zeroizing::new(PaddedMontyForm::new(base, &self.p));
        let power = Zeroizing::new(base.pow(exponent));
        power.retrieve()
    }

    /// BC 的 `CalculateGA`：a·b·c mod p，三者都是公開值。常數時間。
    pub(crate) fn product(
        &self,
        a: &PaddedBigUint,
        b: &PaddedBigUint,
        c: &PaddedBigUint,
    ) -> PaddedBigUint {
        let mut product = PaddedMontyForm::new(a, &self.p);
        product *= &PaddedMontyForm::new(b, &self.p);
        product *= &PaddedMontyForm::new(c, &self.p);
        product.retrieve()
    }

    /// BC 的 `CalculateX2s`：x2·s mod q，寬度同 q。常數時間。
    pub(crate) fn x2s(&self, x2: &PaddedBigUint, s: &PaddedBigUint) -> Zeroizing<PaddedBigUint> {
        let mut product = Zeroizing::new(PaddedMontyForm::new(x2, &self.q));
        *product *= &*Zeroizing::new(PaddedMontyForm::new(s, &self.q));
        Zeroizing::new(product.retrieve())
    }

    /// BC 的 `CalculateZeroKnowledgeProof`：以 Schnorr 簽章證明知道 gx = generator^x 的 x。
    /// v 在 `[0, q − 1]` 中隨機取，回傳 {generator^v, r = v − x·h mod q}，h 見
    /// [`proof_hash`](Self::proof_hash)。對 x 與 v 是常數時間；雜湊的輸入都是公開值。
    pub(crate) fn prove<D: Digest, R: CryptoRng + ?Sized>(
        &self,
        generator: &PaddedBigUint,
        gx: &PaddedBigUint,
        x: &PaddedBigUint,
        participant_id: &str,
        digest: &mut D,
        rng: &mut R,
    ) -> JPakeZeroKnowledgeProof {
        let v = self.generate_x1(rng);
        let gv = self.power(generator, &v);
        let h = self.proof_hash(generator, &gv, gx, participant_id, digest);
        let mut r = Zeroizing::new(PaddedMontyForm::new(&v, &self.q));
        let mut xh = Zeroizing::new(PaddedMontyForm::new(x, &self.q));
        *xh *= &PaddedMontyForm::new(&h, &self.q);
        *r -= &*xh;
        JPakeZeroKnowledgeProof::new(gv, r.retrieve())
    }

    /// BC 的 `ValidateZeroKnowledgeProof`：gx 在 `(0, p)`、gx^q mod p 為 1，且
    /// generator^r · gx^h mod p 等於 g^v。變動時間：只用於公開值。
    pub(crate) fn verify<D: Digest>(
        &self,
        generator: &PaddedBigUint,
        gx: &PaddedBigUint,
        proof: &JPakeZeroKnowledgeProof,
        participant_id: &str,
        digest: &mut D,
    ) -> Result<(), JPakeError> {
        let h = BigUint::from(self.proof_hash(generator, proof.gv(), gx, participant_id, digest));
        let p = BigUint::from(self.p.modulus().clone());
        let q = BigUint::from(self.q.modulus().clone());
        let gx = BigUint::from(gx.clone());
        let modulus = NonZero::new(p.clone()).expect("p is odd");
        let one = BigUint::from(1u8);
        let valid = gx > BigUint::from(0u8) && gx < p && gx.mod_pow(&q, &modulus) == one && {
            let generator = BigUint::from(generator.clone());
            let r = BigUint::from(proof.r().clone());
            let gr = generator.mod_pow(&r, &modulus);
            gr.mod_mul(&gx.mod_pow(&h, &modulus), &modulus) == BigUint::from(proof.gv().clone())
        };
        if valid {
            Ok(())
        } else {
            Err(JPakeError::InvalidProof)
        }
    }

    /// BC 的 `CalculateHashForZeroKnowledgeProof`：generator、g^v、gx 與參與者 ID 各自前置
    /// 4 位元組大端序的長度後雜湊。BC 把雜湊值當成有號整數，這裡取它模 q 的值；gx 的階是
    /// q，所以兩者在證明裡等價。變動時間：只用於公開值。
    fn proof_hash<D: Digest>(
        &self,
        generator: &PaddedBigUint,
        gv: &PaddedBigUint,
        gx: &PaddedBigUint,
        participant_id: &str,
        digest: &mut D,
    ) -> PaddedBigUint {
        digest.reset();
        for value in [generator, gv, gx] {
            update_with_length(digest, &unsigned_bytes(value));
        }
        update_with_length(digest, participant_id.as_bytes());
        let mut output = vec![0u8; digest.digest_size()];
        digest.do_final(&mut output);

        let q = BigUint::from(self.q.modulus().clone());
        let Ok(unsigned) = BigUint::from_be(&output);
        let h = if output.first().is_some_and(|byte| byte & 0x80 != 0) {
            // 二補數：h = unsigned − 2^(8·長度)，所以 h mod q = q − ((2^(8·長度) − unsigned) mod q)。
            let wrap = BigUint::from(1u8) << (8 * output.len() as u32);
            let r = (wrap - unsigned) % &q;
            if r == BigUint::from(0u8) { r } else { &q - r }
        } else {
            unsigned % &q
        };
        PaddedBigUint::from(h)
    }

    /// BC 的 `CalculateKeyingMaterial`：(B / g^(x2·x4·s))^x2 = (gx4^(−x2·s mod q) · B)^x2
    /// mod p，寬度同 p。對 x2 與 s 是常數時間。
    pub(crate) fn keying_material(
        &self,
        gx4: &PaddedBigUint,
        x2: &PaddedBigUint,
        s: &PaddedBigUint,
        b: &PaddedBigUint,
    ) -> Zeroizing<PaddedBigUint> {
        let x2s = self.x2s(x2, s);
        let negated = Zeroizing::new(-&*Zeroizing::new(PaddedMontyForm::new(&x2s, &self.q)));
        let exponent = Zeroizing::new(negated.retrieve());
        let mut base = Zeroizing::new(PaddedMontyForm::new(gx4, &self.p).pow(&exponent));
        *base *= &PaddedMontyForm::new(b, &self.p);
        let key = Zeroizing::new(base.pow(x2));
        Zeroizing::new(key.retrieve())
    }
}

/// BC 的 `CalculateS`：密碼當成無號大端序整數，模 q；結果為 0 時回傳錯誤。
/// 對密碼是常數時間：只依它的長度決定寬度；是否為 0 只由錯誤透露。
pub(crate) fn calculate_s(
    q: &PaddedMontyParams,
    password: &[u8],
) -> Result<Zeroizing<PaddedBigUint>, JPakeError> {
    let Ok(password) = PaddedBigUint::from_be(password);
    let password = Zeroizing::new(password);
    let s = Zeroizing::new(&*password % q.modulus());
    if s.ct_eq(&PaddedBigUint::from(0u8)).unwrap_u8() == 1 {
        return Err(JPakeError::InvalidPassword);
    }
    Ok(s)
}

/// BC 的 `ValidateGx4` 與 `ValidateGa`：value 不得為 1，否則回傳 `error`。變動時間：只用於
/// 公開值。
pub(crate) fn validate_not_one(value: &PaddedBigUint, error: JPakeError) -> Result<(), JPakeError> {
    if *value == PaddedBigUint::from(1u8) {
        Err(error)
    } else {
        Ok(())
    }
}

/// BC 的 `ValidateParticipantIdsDiffer`：雙方的參與者 ID 必須不同。變動時間：只用於公開值。
pub(crate) fn validate_participant_ids_differ(
    participant_id: &str,
    other_participant_id: &str,
) -> Result<(), JPakeError> {
    if participant_id == other_participant_id {
        Err(JPakeError::SameParticipantId)
    } else {
        Ok(())
    }
}

/// BC 的 `ValidateParticipantIdsEqual`：酬載要來自第一輪的同一個對象。變動時間：只用於
/// 公開值。
pub(crate) fn validate_participant_ids_equal(
    expected_participant_id: &str,
    actual_participant_id: &str,
) -> Result<(), JPakeError> {
    if expected_participant_id == actual_participant_id {
        Ok(())
    } else {
        Err(JPakeError::UnexpectedParticipant)
    }
}

/// BC 的 `CalculateMacTag`，NIST SP 800-56A 的單向金鑰確認：
/// MacKey = H(K ‖ "JPAKE_KC")，MacTag = HMAC(MacKey, "KC_1_U" ‖ 自己的 ID ‖ 對方的 ID ‖
/// g^x1 ‖ g^x2 ‖ g^x3 ‖ g^x4)，整數都取最短的無號大端序。雙方都用 "KC_1_U"，因為第三輪的
/// 寄件者總是確認的發起者。變動時間：K 的前導零位元組個數反映在雜湊的長度上，這是 BC 的
/// 編碼使然、攔不住；其餘輸入是公開值，MacKey 用完即清除。
pub(crate) fn mac_tag<D: Digest + Clone>(
    participant_id: &str,
    partner_participant_id: &str,
    gx: [&PaddedBigUint; 4],
    keying_material: &PaddedBigUint,
    digest: &mut D,
) -> Vec<u8> {
    digest.reset();
    digest.update(&unsigned_bytes(keying_material));
    digest.update(b"JPAKE_KC");
    let mut mac_key = Zeroizing::new(vec![0u8; digest.digest_size()]);
    digest.do_final(&mut mac_key);

    let mut mac = Hmac::new(digest.clone());
    let Ok(()) = mac.init(&KeyRef::new(&mac_key));
    let mut update = |input: &[u8]| mac.update(input).expect("the MAC is initialized");
    update(b"KC_1_U");
    update(participant_id.as_bytes());
    update(partner_participant_id.as_bytes());
    for value in gx {
        update(&unsigned_bytes(value));
    }
    let mut tag = vec![0u8; mac.mac_size()];
    mac.do_final(&mut tag).expect("the tag fits");
    tag
}

/// BC 的 `ValidateMacTag`：以對方的角度算出 MacTag（雙方 ID 互換，g^x1、g^x2 與 g^x3、g^x4
/// 互換），再與收到的比較，比較不會提早結束。變動時間：計算 MacTag 的部分同 [`mac_tag`]；
/// 比較的結果只由錯誤透露。
pub(crate) fn validate_mac_tag<D: Digest + Clone>(
    participant_id: &str,
    partner_participant_id: &str,
    gx: [&PaddedBigUint; 4],
    keying_material: &PaddedBigUint,
    digest: &mut D,
    partner_mac_tag: &[u8],
) -> Result<(), JPakeError> {
    let expected = mac_tag(
        partner_participant_id,
        participant_id,
        [gx[2], gx[3], gx[0], gx[1]],
        keying_material,
        digest,
    );
    if fixed_time_eq(&expected, partner_mac_tag) {
        Ok(())
    } else {
        Err(JPakeError::MacTagMismatch)
    }
}

/// value 最短的無號大端序位元組，BC 的 `AsUnsignedByteArray`：去掉前導的零，0 是空的。
/// 變動時間：前導零位元組的個數反映在時間上，用於秘密值時只透露這個個數。
fn unsigned_bytes(value: &PaddedBigUint) -> Zeroizing<Vec<u8>> {
    let full = Zeroizing::new(ArrayEncoding::<u8>::to_be(value));
    let start = full
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(full.len());
    Zeroizing::new(full[start..].to_vec())
}

/// BC 的 `UpdateDigestIncludingSize`：先寫 4 位元組大端序的長度，再寫 bytes。變動時間：
/// 只用於公開值。
fn update_with_length<D: Digest>(digest: &mut D, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).expect("a length below 2^32");
    digest.update(&length.to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard_groups::{nist_3072, sun_jce_1024};
    use tc_sha::{Sha1Digest, Sha256Digest};

    fn domain() -> Domain {
        Domain::new(&sun_jce_1024()).unwrap()
    }

    #[test]
    fn one_is_refused_as_g_x4_or_ga() {
        let ten = PaddedBigUint::from(10u8);
        let one = PaddedBigUint::from(1u8);
        assert_eq!(validate_not_one(&ten, JPakeError::GxIsOne), Ok(()));
        assert_eq!(
            validate_not_one(&one, JPakeError::GxIsOne),
            Err(JPakeError::GxIsOne)
        );
        assert_eq!(
            validate_not_one(&one, JPakeError::GaIsOne),
            Err(JPakeError::GaIsOne)
        );
    }

    #[test]
    fn participant_ids_compare_case_sensitively() {
        assert_eq!(validate_participant_ids_differ("a", "b"), Ok(()));
        assert_eq!(validate_participant_ids_differ("a", "A"), Ok(()));
        assert_eq!(
            validate_participant_ids_differ("a", "a"),
            Err(JPakeError::SameParticipantId)
        );
        assert_eq!(validate_participant_ids_equal("a", "a"), Ok(()));
        assert_eq!(
            validate_participant_ids_equal("a", "b"),
            Err(JPakeError::UnexpectedParticipant)
        );
    }

    #[test]
    fn a_mac_tag_validates_only_from_the_partners_side() {
        let domain = domain();
        let mut rng = rand::rng();
        let mut digest = Sha256Digest::new();
        let x1 = domain.generate_x1(&mut rng);
        let x2 = domain.generate_x2(&mut rng);
        let x3 = domain.generate_x1(&mut rng);
        let x4 = domain.generate_x2(&mut rng);
        let gx1 = domain.power(domain.g(), &x1);
        let gx2 = domain.power(domain.g(), &x2);
        let gx3 = domain.power(domain.g(), &x3);
        let gx4 = domain.power(domain.g(), &x4);
        let gb = domain.product(&gx3, &gx1, &gx2);
        let s = calculate_s(domain.q(), b"password").unwrap();
        let x4s = domain.x2s(&x4, &s);
        let b = domain.power(&gb, &x4s);
        let key = domain.keying_material(&gx4, &x2, &s, &b);
        let gx = [&gx1, &gx2, &gx3, &gx4];
        let tag = mac_tag(
            "participantId",
            "partnerParticipantId",
            gx,
            &key,
            &mut digest,
        );

        let partner = [&gx3, &gx4, &gx1, &gx2];
        assert_eq!(
            validate_mac_tag(
                "partnerParticipantId",
                "participantId",
                partner,
                &key,
                &mut digest,
                &tag
            ),
            Ok(())
        );
        assert_eq!(
            validate_mac_tag(
                "participantId",
                "partnerParticipantId",
                gx,
                &key,
                &mut digest,
                &tag
            ),
            Err(JPakeError::MacTagMismatch),
            "its own tag"
        );
        assert_eq!(
            validate_mac_tag(
                "participantId",
                "partnerParticipantId",
                partner,
                &key,
                &mut digest,
                &tag
            ),
            Err(JPakeError::MacTagMismatch),
            "the ids switched"
        );
    }

    #[test]
    fn a_zero_knowledge_proof_holds_only_for_its_group_digest_participant_and_value() {
        let domain = domain();
        let mut rng = rand::rng();
        let mut digest = Sha256Digest::new();
        let g = domain.g();
        let x1 = domain.generate_x1(&mut rng);
        let gx1 = domain.power(g, &x1);
        let proof1 = domain.prove(g, &gx1, &x1, "participant1", &mut digest, &mut rng);
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant1", &mut digest),
            Ok(())
        );

        let other = Domain::new(&nist_3072()).unwrap();
        let wrong = Err(JPakeError::InvalidProof);
        assert_eq!(
            other.verify(other.g(), &gx1, &proof1, "participant1", &mut digest),
            wrong,
            "another group"
        );
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant1", &mut Sha1Digest::new()),
            wrong,
            "another digest"
        );
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant2", &mut digest),
            wrong,
            "another participant"
        );

        let x2 = domain.generate_x2(&mut rng);
        let gx2 = domain.power(g, &x2);
        assert_eq!(
            domain.verify(g, &gx2, &proof1, "participant1", &mut digest),
            wrong,
            "another g^x"
        );
        let proof2 = domain.prove(g, &gx2, &x2, "participant1", &mut digest, &mut rng);
        assert_eq!(
            domain.verify(g, &gx1, &proof2, "participant1", &mut digest),
            wrong,
            "another proof"
        );

        let group = sun_jce_1024();
        for (gx, case) in [
            (PaddedBigUint::from(0u8), "g^x = 0"),
            (group.p().clone(), "g^x = p"),
            (group.q() + 1u32, "g^x = q + 1"),
        ] {
            assert_eq!(
                domain.verify(g, &gx, &proof1, "participant1", &mut digest),
                wrong,
                "{case}"
            );
        }
    }

    #[test]
    fn a_password_that_is_zero_modulo_q_is_refused() {
        let domain = domain();
        let q = ArrayEncoding::<u8>::to_be(domain.q().modulus());
        assert_eq!(
            calculate_s(domain.q(), &q).map(|_| ()),
            Err(JPakeError::InvalidPassword)
        );
        assert_eq!(
            *calculate_s(domain.q(), &[1]).unwrap(),
            PaddedBigUint::from(1u8)
        );
    }

    #[test]
    fn a_negative_hash_is_reduced_as_bouncy_castle_reads_it() {
        // q = 7、雜湊 0xff：BC 讀成 −1，模 7 為 6。
        let group = JPakePrimeOrderGroup::new(
            PaddedBigUint::from(29u8),
            PaddedBigUint::from(7u8),
            PaddedBigUint::from(16u8),
        );
        let domain = Domain::new(&group).unwrap();
        let mut digest = Fixed(0xff);
        let one = PaddedBigUint::from(1u8);
        let h = domain.proof_hash(&one, &one, &one, "", &mut digest);
        assert_eq!(h, PaddedBigUint::from(6u8));
        let mut digest = Fixed(0x7f);
        let h = domain.proof_hash(&one, &one, &one, "", &mut digest);
        assert_eq!(h, PaddedBigUint::from(0x7fu8 % 7));
    }

    /// 只輸出固定一個位元組的雜湊。
    #[derive(Clone)]
    struct Fixed(u8);

    impl tc_digest::TryDigest for Fixed {
        type Error = core::convert::Infallible;

        fn digest_size(&self) -> usize {
            1
        }

        fn byte_length(&self) -> usize {
            1
        }

        fn try_update(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            output[0] = self.0;
            Ok(1)
        }

        fn try_reset(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
