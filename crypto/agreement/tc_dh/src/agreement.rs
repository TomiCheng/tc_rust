use crate::DhAgreementError;
use crate::basic_agreement::write_be;
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_constant_time::ConstantTimeEq;
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator, DhPrivateKey, DhPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// BC 的 `DHAgreement`：RFC 2631 的 MTI/A0 兩階段協商。雙方都有長期金鑰對，先以
/// [`calculate_message`](Self::calculate_message) 互寄一次性的公開值，共享秘密是
/// (對方長期公鑰)^(自己的一次性私鑰) · (對方的訊息)^(自己的長期私鑰) mod p。
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dh::DhAgreement;
/// use tc_dh_key::standard_groups::rfc3526_2048;
/// use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};
///
/// // 雙方事先各有一對長期金鑰，並取得對方的長期公鑰。
/// let mut rng = rand::rng();
/// let mut generator = DhKeyPairGenerator::new();
/// generator.init(DhKeyGenerationParams::new(rfc3526_2048(), &mut rng))?;
/// let (alice_public, alice_private) = generator.generate_key_pair()?;
/// let (bob_public, bob_private) = generator.generate_key_pair()?;
///
/// // 每次協商，雙方各算出一個一次性的訊息寄給對方。
/// let mut alice = DhAgreement::new(rand::rng());
/// alice.init(&alice_private)?;
/// let alice_message = alice.calculate_message()?;
/// let mut bob = DhAgreement::new(rand::rng());
/// bob.init(&bob_private)?;
/// let bob_message = bob.calculate_message()?;
///
/// // 各自以對方的長期公鑰與訊息得到同一個秘密，再交給 KDF。
/// let mut alice_secret = vec![0; alice.agreement_size()];
/// alice.calculate_agreement(&bob_public, &bob_message, &mut alice_secret)?;
/// let mut bob_secret = vec![0; bob.agreement_size()];
/// bob.calculate_agreement(&alice_public, &alice_message, &mut bob_secret)?;
/// assert_eq!(alice_secret, bob_secret);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DhAgreement<R> {
    rng: R,
    state: Option<(DhPrivateKey, PaddedMontyParams)>,
    ephemeral: Option<DhPrivateKey>,
}

impl<R: CryptoRng> DhAgreement<R> {
    /// 尚未 `init` 的協商；`rng` 用來產生一次性的金鑰。常數時間。
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            state: None,
            ephemeral: None,
        }
    }

    /// 保存長期私鑰的複本（drop 時清除 x），丟掉前一次的一次性私鑰；以
    /// `DhParameters::validate` 檢查參數，並為 p 建好 Montgomery 參數。變動時間：只依
    /// 公開的參數分支。
    pub fn init(&mut self, key: &DhPrivateKey) -> Result<(), DhAgreementError> {
        self.state = None;
        self.ephemeral = None;
        key.params()
            .validate()
            .map_err(DhAgreementError::InvalidParameters)?;
        let p = Odd::new(key.params().p().clone()).ok_or(DhAgreementError::InvalidParameters(
            tc_dh_key::DhError::InvalidModulus,
        ))?;
        self.state = Some((key.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }

    /// BC 的 `CalculateMessage`：產生一次性的金鑰對，保留私鑰 r，回傳要寄給對方的
    /// g^r mod p。對 r 是常數時間，同 `DhKeyPairGenerator`。
    pub fn calculate_message(&mut self) -> Result<PaddedBigUint, DhAgreementError> {
        let Self {
            rng,
            state,
            ephemeral,
        } = self;
        let (key, _) = state.as_ref().ok_or(DhAgreementError::NotInitialized)?;
        let mut generator = DhKeyPairGenerator::new();
        generator
            .init(DhKeyGenerationParams::new(key.params().clone(), rng))
            .map_err(DhAgreementError::InvalidParameters)?;
        let (public_key, private_key) = generator
            .generate_key_pair()
            .map_err(DhAgreementError::InvalidParameters)?;
        *ephemeral = Some(private_key);
        Ok(public_key.y().clone())
    }

    /// p 的位元組數。`init` 之前呼叫會 panic。常數時間。
    pub fn agreement_size(&self) -> usize {
        let (key, _) = self.state.as_ref().expect("the agreement is initialized");
        (key.params().p().bits() as usize).div_ceil(8)
    }

    /// BC 的 `CalculateAgreement`：對方的長期公鑰要與自己的參數相同；它與 `message` 都要
    /// 通過 `DhPublicKey::validate`，否則對方可送小階元素套出重複使用的私鑰；
    /// (長期公鑰)^r 不得為 1。結果寫成 p 的位元組數、前面補零的大端序。
    ///
    /// 檢查依公開的值分支；兩次取冪對私鑰是常數時間，是否為 1 以常數時間比較，只由錯誤
    /// 透露。
    pub fn calculate_agreement(
        &self,
        public_key: &DhPublicKey,
        message: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<(), DhAgreementError> {
        let (key, monty) = self
            .state
            .as_ref()
            .ok_or(DhAgreementError::NotInitialized)?;
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or(DhAgreementError::MessageNotCalculated)?;
        if public_key.params() != key.params() {
            return Err(DhAgreementError::WrongParameters);
        }
        DhPublicKey::new(message.clone(), key.params().clone())
            .validate()
            .map_err(DhAgreementError::InvalidMessage)?;
        public_key
            .validate()
            .map_err(DhAgreementError::InvalidPublicKey)?;
        let size = self.agreement_size();
        let output = output
            .get_mut(..size)
            .ok_or(DhAgreementError::BufferTooSmall)?;

        let partial =
            Zeroizing::new(PaddedMontyForm::new(public_key.y(), monty).pow(ephemeral.x()));
        let partial_value = Zeroizing::new(partial.retrieve());
        if partial_value.ct_eq(&PaddedBigUint::from(1u8)).unwrap_u8() == 1 {
            return Err(DhAgreementError::InvalidAgreement);
        }
        let mut shared = Zeroizing::new(PaddedMontyForm::new(message, monty).pow(key.x()));
        *shared *= &*partial;
        write_be(&Zeroizing::new(shared.retrieve()), output);
        Ok(())
    }
}
