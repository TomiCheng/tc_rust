//! The RSA operation with the CRT, as Bouncy Castle's `RsaCoreEngine` runs
//! it for a CRT key, over `PaddedBigUint`.

use alloc::vec;

use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint};
use tc_modular::{ModMul, ModPow, ModSub, NonZero};
use tc_zeroize::{Zeroize, Zeroizing};

use crate::block::{input_block_size, output_block_size, write_be};
use crate::{RsaError, RsaPrivateCrtKeyParams};

/// What an engine keeps from its initialization: the modulus and `n - 1`
/// for the range check of the input, the public exponent at its own width
/// for the check of the result, the CRT values at the widths they came in,
/// the size of the modulus in bits, and the direction. The secret values
/// are wiped on drop.
struct CrtKey {
    modulus: NonZero<PaddedBigUint>,
    modulus_less_one: PaddedBigUint,
    public_exponent: PaddedBigUint,
    p: NonZero<PaddedBigUint>,
    q: NonZero<PaddedBigUint>,
    dp: PaddedBigUint,
    dq: PaddedBigUint,
    q_inv: PaddedBigUint,
    bits: u32,
    direction: CipherDirection,
}

/// Wipes the CRT values, the primes by taking them out of their
/// `NonZero`. Constant time: the widths are public.
impl Drop for CrtKey {
    fn drop(&mut self) {
        for prime in [&mut self.p, &mut self.q] {
            let one = NonZero::new(PaddedBigUint::from(1u8)).expect("one is not zero");
            core::mem::replace(prime, one).into_inner().zeroize();
        }
        self.dp.zeroize();
        self.dq.zeroize();
        self.q_inv.zeroize();
    }
}

/// The RSA operation with the CRT over [`PaddedBigUint`], as Bouncy
/// Castle's `RsaCoreEngine` runs it for a CRT key: `x^d mod n` as two
/// powers modulo the primes, at their width, then recombined, and checked
/// by raising the result back to `e`, which turns down a result a fault
/// has spoiled, as Lenstra's attack on the CRT needs. The key is copied in
/// at initialization. The blocks are as those of
/// [`RsaCoreEngine`](crate::RsaCoreEngine): the output always takes the
/// full length of the modulus, leading zeros kept.
pub struct PaddedRsaCrtCoreEngine {
    key: Option<CrtKey>,
}

impl PaddedRsaCrtCoreEngine {
    /// An engine to be initialized before it processes. Constant time.
    pub const fn new() -> Self {
        Self { key: None }
    }

    /// The key, once the engine is initialized. Constant time.
    fn key(&self) -> Result<&CrtKey, RsaError> {
        self.key.as_ref().ok_or(RsaError::NotInitialized)
    }
}

/// Through [`new`](PaddedRsaCrtCoreEngine::new). Constant time.
impl Default for PaddedRsaCrtCoreEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies the key in, once [`validate`](crate::RsaKeyParams::validate)
/// passes it, and fails with `InvalidKey` otherwise. The public exponent is
/// kept at the width of its own bits, so that the check of a result costs
/// the few squarings of `e` rather than those of the width of the modulus.
/// Variable time: only for public values, as the modulus, the public
/// exponent and the outcome of the checks are; the secret values are only
/// copied, and read for zero.
impl<P> AsymmetricBlockCipherInit<P> for PaddedRsaCrtCoreEngine
where
    P: RsaPrivateCrtKeyParams<PaddedBigUint>,
{
    type Error = RsaError;

    fn init(&mut self, direction: CipherDirection, params: &P) -> Result<(), RsaError> {
        if !params.validate() {
            return Err(RsaError::InvalidKey);
        }
        let nonzero =
            |value: &PaddedBigUint| NonZero::new(value.clone()).ok_or(RsaError::InvalidKey);
        let modulus = nonzero(params.modulus())?;
        let e = params.public_exponent();
        self.key = Some(CrtKey {
            modulus_less_one: &*modulus - 1u32,
            public_exponent: with_width(e, e.bits().div_ceil(tc_bigint::Word::BITS) as usize),
            p: nonzero(params.p())?,
            q: nonzero(params.q())?,
            dp: params.dp().clone(),
            dq: params.dq().clone(),
            q_inv: params.q_inv().clone(),
            bits: modulus.bits(),
            direction,
            modulus,
        });
        Ok(())
    }
}

/// Reads the input as a big-endian integer `x` with `1 < x < n - 1`, as
/// Bouncy Castle does, and computes `m = x^d mod n` through the CRT:
/// `mP = (x mod p)^dP mod p` and `mQ = (x mod q)^dQ mod q`, each at the
/// width of its prime, `h = (mP - mQ) · qInv mod p`, and `m = h · q + mQ`.
/// It then checks that `m^e mod n` is `x` again, and fails with
/// `FaultyDecryptionOrSigning` otherwise, writing nothing; the result is
/// written over the full length of the modulus. Constant time, as the
/// arithmetic of `PaddedBigUint` and `tc_modular` is, apart from the
/// outcome of the range check and of the check of the result, which the
/// error shows. There is no blinding: a caller who needs it blinds the
/// input, as Bouncy Castle's `RsaBlindedEngine` does.
impl AsymmetricBlockCipher for PaddedRsaCrtCoreEngine {
    type Error = RsaError;

    /// `(bits - 1) / 8` bytes when encrypting, which here is signing with
    /// the private key, and `(bits + 7) / 8` when decrypting; zero before
    /// initialization. Constant time.
    fn input_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| input_block_size(key.bits, key.direction))
    }

    /// `(bits + 7) / 8` bytes in both directions; zero before
    /// initialization. Constant time.
    fn output_block_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| output_block_size(key.bits))
    }

    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, RsaError> {
        let key = self.key()?;
        if input.len() > self.input_block_size() {
            return Err(RsaError::InputTooLarge);
        }
        let length = self.output_block_size();
        if output.len() < length {
            return Err(RsaError::OutputTooShort);
        }
        let Ok(x) = PaddedBigUint::from_be(input);
        let x = Zeroizing::new(x);
        if x.bits() <= 1 {
            return Err(RsaError::InputTooSmall);
        }
        if *x >= key.modulus_less_one {
            return Err(RsaError::InputTooLarge);
        }

        let m_p = Zeroizing::new(power_mod_prime(&x, &key.dp, &key.p));
        let m_q = Zeroizing::new(power_mod_prime(&x, &key.dq, &key.q));
        let difference = Zeroizing::new(m_p.mod_sub(&m_q, &key.p));
        let h = Zeroizing::new(difference.mod_mul(&key.q_inv, &key.p));
        let mut m = Zeroizing::new(with_width(&h, key.modulus.as_limbs().len()));
        *m *= &*key.q;
        *m += &*m_q;

        if m.mod_pow(&key.public_exponent, &key.modulus) != *x {
            return Err(RsaError::FaultyDecryptionOrSigning);
        }
        write_be(&*m, &mut output[..length]);
        Ok(length)
    }
}

/// `(x mod prime)^exponent mod prime`, with the residue cut to the width of
/// the prime, so that the power runs at that width and not at the wider
/// one of `x`. Constant time: the widths are public.
fn power_mod_prime(
    x: &PaddedBigUint,
    exponent: &PaddedBigUint,
    prime: &NonZero<PaddedBigUint>,
) -> PaddedBigUint {
    let residue = Zeroizing::new(with_width(&(x % &**prime), prime.as_limbs().len()));
    residue.mod_pow(exponent, prime)
}

/// `value` at `width` limbs: zero limbs added, or the limbs past that
/// width, which must be zero, taken off. Constant time: the widths are
/// public.
fn with_width(value: &PaddedBigUint, width: usize) -> PaddedBigUint {
    let limbs = value.as_limbs();
    let kept = width.min(limbs.len());
    let mut resized = vec![Limb::new(0); width.max(1)];
    resized[..kept].copy_from_slice(&limbs[..kept]);
    PaddedBigUint::new(resized.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
        KeyPairGeneratorInit,
    };
    use tc_bigint::{ArrayEncoding, PaddedBigUint};

    use super::PaddedRsaCrtCoreEngine;
    use crate::{
        RsaCoreEngine, RsaError, RsaKeyGenerationParamsOwned, RsaKeyOwned, RsaKeyPairGenerator,
        RsaKeyParams, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyParams,
    };

    /// The first key of Wycheproof's `rsa_pkcs1_2048_test.json`, from C2SP,
    /// with its CRT values; the public exponent is 65537.
    const N: &str = concat!(
        "b3510a2bcd4ce644c5b594ae5059e12b2f054b658d5da5959a2fdf1871b808bc",
        "3df3e628d2792e51aad5c124b43bda453dca5cde4bcf28e7bd4effba0cb4b742",
        "bbb6d5a013cb63d1aa3a89e02627ef5398b52c0cfd97d208abeb8d7c9bce0bbe",
        "b019a86ddb589beb29a5b74bf861075c677c81d430f030c265247af9d3c9140c",
        "cb65309d07e0adc1efd15cf17e7b055d7da3868e4648cc3a180f0ee7f8e1e7b1",
        "8098a3391b4ce7161e98d57af8a947e201a463e2d6bbca8059e5706e9dfed8f4",
        "856465ffa712ed1aa18e888d12dc6aa09ce95ecfca83cc5b0b15db09c8647f5d",
        "524c0f2e7620a3416b9623cadc0f097af573261c98c8400aa12af38e43cad84d",
    );
    const D: &str = concat!(
        "1a502d0eea6c7b69e21d5839101f705456ed0ef852fb47fe21071f54c5f33c8c",
        "eb066c62d727e32d26c58137329f89d3195325b795264c195d85472f7507dbd0",
        "961d2951f935a26b34f0ac24d15490e1128a9b7138915bc7dbfa8fe396357131",
        "c543ae9c98507368d9ceb08c1c6198a3eda7aea185a0e976cd42c22d00f003d9",
        "f19d96ea4c9afcbfe1441ccc802cfb0689f59d804c6a4e4f404c15174745ed6c",
        "b8bc88ef0b33ba0d2a80e35e43bc90f350052e72016e75b00d357a381c9c0d46",
        "7069ca660887c987766349fcc43460b4aa516bce079edd87ba164307b752c277",
        "ed9528ad3ba0bf1877349ed3b7966a6c240110409bf4d0fade0c68fdadd847fd",
    );
    const P: &str = concat!(
        "ec125cf37e310a2ff46263b9b2e0629d6390005ec88913d4fb71bd4dd8561244",
        "98aaeba983d7ba2bd942e64d223feb7a23af4d605efeea6bd70d39afe99d35a3",
        "aa15e74a1768778093be0edd4a8d09b2def6dc9b67ff85764625c2e19236db4c",
        "401ce30a2572d3ecb4f969b7ad19c522c02d774465676e1a3776c54d6248348b",
    );
    const Q: &str = concat!(
        "c2742abcd9897bd4b0b671f973fc82a8f84abf5705ff88dd41948623afe9dca6",
        "0dc6543390767feaebeb539576ee8bfa61b5fcbca94a7cef75a09150c540fa96",
        "94dd8004ad23718c889049219369c99f4458d4afc148f6f07df87324a96d9cf7",
        "b385dd8622414a1832f9f29446f050c2d5a6407649dc41ab70e23b3dcc22c987",
    );
    const DP: &str = concat!(
        "96a9798d250263400bb6277342881627e07cecdf91187b01b89ff47314188a7c",
        "20fb24800156d2c85d5666e8df6ceff9f9804ddfad80ff5767de56ecc029c72b",
        "f6c717df9f64daafc29acf9dc7908f9a0ad67e20e8949936ccba18d021a2c4fe",
        "bb04349a2b2047c4901385b6e5d0c691d118b33f81802b32ac272ef09e42fad5",
    );
    const DQ: &str = concat!(
        "0554f41b0b87f68a45722b3be0cf4ab1e165034c1a91002ab8f29e9ef9e2dab6",
        "fee7b2455bafb42037e9d2f7e533f348a147412fd72080be7c2633f5d802c91c",
        "39e6bcece3e675e59995033c55737020dad9e8b30d04b828adfb9304ad54a11a",
        "35a4f50709876ac5b118236ba76a4d7c9a291dd9607b169de1d182385691999f",
    );
    const Q_INV: &str = concat!(
        "1c640189d9bfe8c623833210a76c420c6f44e5d760e259916cec2ae2b1564569",
        "60fd95e2747660c389562250f055049cfab7e5c3039549384a7a2aaeb1c824d3",
        "af709482a8cf9b587022a00b1f0722db50f33cb26dc20dd2245d5265df61ee29",
        "83c938c2167dcee121fc4b4479c237e728cf633ab60a8c0ecd04fce7e3baa559",
    );

    fn int(text: &str) -> PaddedBigUint {
        let bytes: alloc::vec::Vec<u8> = text
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        PaddedBigUint::from_be(&bytes).unwrap()
    }

    fn wycheproof(dp: PaddedBigUint) -> RsaPrivateCrtKeyOwned<PaddedBigUint> {
        RsaPrivateCrtKeyOwned::new(
            int(N),
            PaddedBigUint::from(65537u32),
            int(D),
            int(P),
            int(Q),
            dp,
            int(DQ),
            int(Q_INV),
        )
    }

    /// The output of `engine` on `input`, at the 256 bytes of a 2048-bit
    /// modulus.
    fn process(
        engine: &mut impl AsymmetricBlockCipher<Error = RsaError>,
        input: &[u8],
    ) -> Result<[u8; 256], RsaError> {
        let mut output = [0; 256];
        assert_eq!(engine.process_block(input, &mut output)?, 256);
        Ok(output)
    }

    #[test]
    fn the_crt_agrees_with_the_plain_power_of_d() {
        let key = wycheproof(int(DP));
        let mut crt = PaddedRsaCrtCoreEngine::new();
        crt.init(CipherDirection::Decrypt, &key).unwrap();
        let plain_key = RsaKeyOwned::new(true, key.modulus().clone(), key.exponent().clone());
        let mut plain = RsaCoreEngine::new();
        plain.init(CipherDirection::Decrypt, &plain_key).unwrap();
        for fill in [0x02u8, 0x5a, 0xb3] {
            let input = [fill; 255];
            assert_eq!(
                process(&mut crt, &input),
                process(&mut plain, &input),
                "{fill:#x}"
            );
        }
    }

    #[test]
    fn a_message_encrypted_with_the_public_key_comes_back() {
        let key = wycheproof(int(DP));
        let public = RsaKeyOwned::new(false, key.modulus().clone(), key.public_exponent().clone());
        let mut encrypt = RsaCoreEngine::new();
        encrypt.init(CipherDirection::Encrypt, &public).unwrap();
        let mut message = [0x42; 255];
        message[0] = 0x01;
        let ciphertext = process(&mut encrypt, &message).unwrap();

        let mut decrypt = PaddedRsaCrtCoreEngine::new();
        decrypt.init(CipherDirection::Decrypt, &key).unwrap();
        let plaintext = process(&mut decrypt, &ciphertext).unwrap();
        assert_eq!(plaintext[0], 0);
        assert_eq!(&plaintext[1..], &message[..]);
    }

    #[test]
    fn a_wrong_crt_value_is_caught_by_the_check_of_the_result() {
        let key = wycheproof(int(DP) + 2u32);
        let mut engine = PaddedRsaCrtCoreEngine::new();
        engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[0x5a; 255], &mut output),
            Err(RsaError::FaultyDecryptionOrSigning)
        );
        assert_eq!(output, [0; 256]);
    }

    #[test]
    fn a_generated_key_signs_and_its_public_key_verifies() {
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint>::new();
        generator
            .init(RsaKeyGenerationParamsOwned::new(StdRng::seed_from_u64(1)).with_strength(1024))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();

        let mut sign = PaddedRsaCrtCoreEngine::new();
        sign.init(CipherDirection::Encrypt, &private).unwrap();
        assert_eq!(
            (sign.input_block_size(), sign.output_block_size()),
            (127, 128)
        );
        let message = [0x37; 127];
        let mut signature = [0; 128];
        sign.process_block(&message, &mut signature).unwrap();

        let mut verify = RsaCoreEngine::new();
        verify.init(CipherDirection::Decrypt, &public).unwrap();
        let mut recovered = [0; 128];
        verify.process_block(&signature, &mut recovered).unwrap();
        assert_eq!(recovered[0], 0);
        assert_eq!(&recovered[1..], &message[..]);
    }

    #[test]
    fn inputs_outside_two_to_n_less_two_are_turned_down() {
        let key = wycheproof(int(DP));
        let mut engine = PaddedRsaCrtCoreEngine::new();
        engine.init(CipherDirection::Decrypt, &key).unwrap();
        let mut output = [0; 256];
        assert_eq!(
            engine.process_block(&[1], &mut output),
            Err(RsaError::InputTooSmall)
        );
        let n = int(N).to_be();
        assert_eq!(
            engine.process_block(&n, &mut output),
            Err(RsaError::InputTooLarge)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 255]),
            Err(RsaError::OutputTooShort)
        );
    }

    #[test]
    fn a_key_that_fails_its_checks_is_turned_down() {
        let mut engine = PaddedRsaCrtCoreEngine::new();
        let key = wycheproof(PaddedBigUint::from(0u8));
        assert!(!key.validate());
        assert_eq!(
            engine.init(CipherDirection::Decrypt, &key),
            Err(RsaError::InvalidKey)
        );
    }

    #[test]
    fn an_engine_not_yet_initialized_processes_nothing() {
        let mut engine = PaddedRsaCrtCoreEngine::new();
        assert_eq!(
            (engine.input_block_size(), engine.output_block_size()),
            (0, 0)
        );
        assert_eq!(
            engine.process_block(&[2], &mut [0; 2]),
            Err(RsaError::NotInitialized)
        );
    }
}
