//! 參數產生器與金鑰對產生器：Bouncy Castle `Gost3410Test` 的 512 位元參數與驗證資料
//! （程序 A 與 A'）、金鑰的範圍，以及錯誤。

use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_gost3410_key::{
    Gost3410Error, Gost3410KeyGenerationParams, Gost3410KeyPairGenerator, Gost3410Parameters,
    Gost3410ParametersGenerator, Gost3410PrivateKey, Gost3410PublicKey,
    Gost3410ValidationParameters,
};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn integer(hex: &str) -> PaddedBigUint {
    let Ok(value) = PaddedBigUint::from_be(&bytes(hex));
    value
}

/// BC 的 `FixedSecureRandom`：依序交出固定的位元組。
struct Fixed {
    data: Vec<u8>,
    position: usize,
}

impl Fixed {
    /// BC 測試的 `FixedSecureRandom.From(seed, zeroTwo(64))`。
    fn new(seed: &str) -> Self {
        let mut data = bytes(seed);
        data.extend([vec![0; 63], vec![2]].concat());
        Self { data, position: 0 }
    }
}

impl TryRng for Fixed {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("the generators read whole byte strings")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("the generators read whole byte strings")
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        let end = self.position + output.len();
        output.copy_from_slice(&self.data[self.position..end]);
        self.position = end;
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

#[test]
fn procedure_a_gives_the_parameters_and_validation_data_of_bouncy_castle() {
    let mut rng = Fixed::new("00005EC900007341");
    let mut generator = Gost3410ParametersGenerator::new();
    generator.init(512, 1, &mut rng).unwrap();
    let params = generator.generate_parameters().unwrap();
    assert_eq!(
        params.p(),
        &integer(
            "EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3"
        )
    );
    assert_eq!(
        params.q(),
        &integer("98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D")
    );
    assert_eq!(
        params.validation(),
        Some(&Gost3410ValidationParameters::new(24265, 29505))
    );
    assert_eq!(rng.position, rng.data.len(), "every byte is read");
}

#[test]
fn procedure_a_prime_keeps_the_64_bit_validation_data() {
    let mut rng = Fixed::new("000000003DFC46F1000000000000000D");
    let mut generator = Gost3410ParametersGenerator::new();
    generator.init(512, 2, &mut rng).unwrap();
    let params = generator.generate_parameters().unwrap();
    assert_eq!(
        params.q(),
        &integer("931A58FB6F0DCDF2FE7549BC3F19F4724B56898F7F921A076601EDB18C93DC75")
    );
    let validation = params.validation().unwrap();
    assert_eq!(
        (validation.x0_long(), validation.c_long()),
        (0x3DFC46F1, 0xD)
    );
    assert_eq!((validation.x0(), validation.c()), (0, 0));
}

#[test]
fn generated_keys_lie_in_range_and_y_is_a_to_the_x() {
    let mut rng = rand::rng();
    let mut generator = Gost3410ParametersGenerator::new();
    generator.init(512, 1, &mut rng).unwrap();
    let params = generator.generate_parameters().unwrap();
    params.validate().unwrap();

    let mut rng = rand::rng();
    let mut keys = Gost3410KeyPairGenerator::new();
    keys.init(Gost3410KeyGenerationParams::new(params.clone(), &mut rng))
        .unwrap();
    let (public_key, private_key) = keys.generate_key_pair().unwrap();
    public_key.validate().unwrap();
    private_key.validate().unwrap();
    assert!(private_key.x().bits() <= 256);
    assert_eq!(public_key.params(), &params);
}

#[test]
fn errors_are_reported() {
    let mut generator = Gost3410ParametersGenerator::new();
    assert_eq!(
        generator.generate_parameters().map(|_| ()),
        Err(Gost3410Error::NotInitialized)
    );
    for (size, procedure, error) in [
        (768, 1, Gost3410Error::InvalidSize),
        (512, 3, Gost3410Error::InvalidProcedure),
    ] {
        let mut rng = rand::rng();
        let mut generator = Gost3410ParametersGenerator::new();
        assert_eq!(generator.init(size, procedure, &mut rng), Err(error));
    }

    let int = |value: u32| PaddedBigUint::from(value);
    for (params, error) in [
        (
            Gost3410Parameters::new(int(22), int(11), int(3)),
            Gost3410Error::InvalidModulus,
        ),
        (
            Gost3410Parameters::new(int(23), int(10), int(3)),
            Gost3410Error::InvalidOrder,
        ),
        (
            Gost3410Parameters::new(int(23), int(29), int(3)),
            Gost3410Error::InvalidOrder,
        ),
        (
            Gost3410Parameters::new(int(23), int(11), int(1)),
            Gost3410Error::InvalidGenerator,
        ),
    ] {
        assert_eq!(params.validate(), Err(error));
    }
    let params = Gost3410Parameters::new(int(23), int(11), int(2));
    assert_eq!(
        Gost3410PublicKey::new(int(23), params.clone()).validate(),
        Err(Gost3410Error::InvalidPublicKey)
    );
    assert_eq!(
        Gost3410PrivateKey::new(int(11), params.clone()).validate(),
        Err(Gost3410Error::InvalidPrivateKey)
    );
    assert_eq!(
        Gost3410PrivateKey::new(int(0), params).validate(),
        Err(Gost3410Error::InvalidPrivateKey)
    );
}
