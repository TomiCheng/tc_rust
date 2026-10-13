//! OAEP over RSA, with the vectors of PKCS#1 v2.1 that Bouncy Castle's
//! `OaepTest` runs, and further ones worked out apart, with Python.

mod common;

use common::hex;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::{EncodingError, OaepEncoding};
use tc_bigint::{ArrayEncoding, FixedBigUint, Word};
use tc_digest::{Digest, TryDigest};
use tc_rsa_v2::{FixedRsaCoreEngine, RsaError, RsaKeyOwned};
use tc_sha::{Sha1Digest, Sha256Digest};

const LIMBS: usize = 2048 / Word::BITS as usize;
type U2048 = FixedBigUint<LIMBS>;
type Engine = FixedRsaCoreEngine<LIMBS>;
type Key = RsaKeyOwned<U2048>;
type Error = EncodingError<RsaError>;

/// A key of the vectors, and what to encrypt with it: the message, the
/// seed, and the ciphertext that comes of them.
struct Vectors {
    modulus: &'static str,
    private_exponent: &'static str,
    cases: [(&'static str, &'static str, &'static str); 6],
}

/// The 1024-bit and 1027-bit keys of the PKCS#1 v2.1 vectors, with SHA-1
/// and the public exponent 65537.
const VECTORS: [Vectors; 2] = [
    Vectors {
        modulus: concat!(
            "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab",
            "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72",
            "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514",
            "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
        ),
        private_exponent: concat!(
            "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd",
            "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55",
            "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf",
            "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
        ),
        cases: [
            (
                "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34",
                "18b776ea21069d69776a33e96bad48e1dda0a5ef",
                concat!(
                    "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb",
                    "21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535f",
                    "a9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426",
                    "d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a",
                ),
            ),
            (
                "750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5",
                "0cc742ce4a9b7f32f951bcb251efd925fe4fe35f",
                concat!(
                    "640db1acc58e0568fe5407e5f9b701dff8c3c91e716c536fc7fcec6cb5b71c11",
                    "65988d4a279e1577d730fc7a29932e3f00c81515236d8d8e31017a7a09df4352",
                    "d904cdeb79aa583adcc31ea698a4c05283daba9089be5491f67c1a4ee48dc74b",
                    "bbe6643aef846679b4cb395a352d5ed115912df696ffe0702932946d71492b44",
                ),
            ),
            (
                concat!(
                    "d94ae0832e6445ce42331cb06d531a82b1db4baad30f746dc916df24d4e3c245",
                    "1fff59a6423eb0e1d02d4fe646cf699dfd818c6e97b051",
                ),
                "2514df4695755a67b288eaf4905c36eec66fd2fd",
                concat!(
                    "423736ed035f6026af276c35c0b3741b365e5f76ca091b4e8c29e2f0befee603",
                    "595aa8322d602d2e625e95eb81b2f1c9724e822eca76db8618cf09c5343503a4",
                    "360835b5903bc637e3879fb05e0ef32685d5aec5067cd7cc96fe4b2670b6eac3",
                    "066b1fcf5686b68589aafb7d629b02d8f8625ca3833624d4800fb081b1cf94eb",
                ),
            ),
            (
                "52e650d98e7f2a048b4f86852153b97e01dd316f346a19f67a85",
                "c4435a3e1a18a68b6820436290a37cefb85db3fb",
                concat!(
                    "45ead4ca551e662c9800f1aca8283b0525e6abae30be4b4aba762fa40fd3d38e",
                    "22abefc69794f6ebbbc05ddbb11216247d2f412fd0fba87c6e3acd888813646f",
                    "d0e48e785204f9c3f73d6d8239562722dddd8771fec48b83a31ee6f592c4cfd4",
                    "bc88174f3b13a112aae3b9f7b80e0fc6f7255ba880dc7d8021e22ad6a85f0755",
                ),
            ),
            (
                "8da89fd9e5f974a29feffb462b49180f6cf9e802",
                "b318c42df3be0f83fea823f5a7b47ed5e425a3b5",
                concat!(
                    "36f6e34d94a8d34daacba33a2139d00ad85a9345a86051e73071620056b920e2",
                    "19005855a213a0f23897cdcd731b45257c777fe908202befdd0b58386b1244ea",
                    "0cf539a05d5d10329da44e13030fd760dcd644cfef2094d1910d3f433e1c7c6d",
                    "d18bc1f2df7f643d662fb9dd37ead9059190f4fa66ca39e869c4eb449cbdc439",
                ),
            ),
            (
                "26521050844271",
                "e4ec0982c2336f3a677f6a356174eb0ce887abc2",
                concat!(
                    "42cee2617b1ecea4db3f4829386fbd61dafbf038e180d837c96366df24c097b4",
                    "ab0fac6bdf590d821c9f10642e681ad05b8d78b378c0f46ce2fad63f74e0ad3d",
                    "f06b075d7eb5f5636f8d403b9059ca761b5c62bb52aa45002ea70baace08ded2",
                    "43b9d8cbd62a68ade265832b56564e43a6fa42ed199a099769742df1539e8255",
                ),
            ),
        ],
    },
    Vectors {
        modulus: concat!(
            "051240b6cc0004fa48d0134671c078c7c8dec3b3e2f25bc2564467339db38853",
            "d06b85eea5b2de353bff42ac2e46bc97fae6ac9618da9537a5c8f553c1e35762",
            "5991d6108dcd7885fb3a25413f53efcad948cb35cd9b9ae9c1c67626d113d57d",
            "de4c5bea76bb5bb7de96c00d07372e9685a6d75cf9d239fa148d70931b5f3fb0",
            "39",
        ),
        private_exponent: concat!(
            "0411ffca3b7ca5e9e9be7fe38a85105e353896db05c5796aecd2a725161eb365",
            "1c8629a9b862b904d7b0c7b37f8cb5a1c2b54001018a00a1eb2cafe4ee4e9492",
            "c348bc2bedab4b9ebbf064e8eff322b9009f8eec653905f40df88a3cdc49d456",
            "7f75627d41aca624129b46a0b7c698e5e65f2b7ba102c749a10135b6540d0401",
        ),
        cases: [
            (
                concat!(
                    "4a86609534ee434a6cbca3f7e962e76d455e3264c19f605f6e5ff6137c65c56d",
                    "7fb344cd52bc93374f3d166c9f0c6f9c506bad19330972d2",
                ),
                "1cac19ce993def55f98203f6852896c95ccca1f3",
                concat!(
                    "04cce19614845e094152a3fe18e54e3330c44e5efbc64ae16886cb1869014cc5",
                    "781b1f8f9e045384d0112a135ca0d12e9c88a8e4063416deaae3844f60d6e96f",
                    "e155145f4525b9a34431ca3766180f70e15a5e5d8e8b1a516ff870609f13f896",
                    "935ced188279a58ed13d07114277d75c6568607e0ab092fd803a223e4a8ee0b1",
                    "a8",
                ),
            ),
            (
                concat!(
                    "b0adc4f3fe11da59ce992773d9059943c03046497ee9d9f9a06df1166db46d98",
                    "f58d27ec074c02eee6cbe2449c8b9fc5080c5c3f4433092512ec46aa793743c8",
                ),
                "f545d5897585e3db71aa0cb8da76c51d032ae963",
                concat!(
                    "0097b698c6165645b303486fbf5a2a4479c0ee85889b541a6f0b858d6b6597b1",
                    "3b854eb4f839af03399a80d79bda6578c841f90d645715b280d37143992dd186",
                    "c80b949b775cae97370e4ec97443136c6da484e970ffdb1323a20847821d3b18",
                    "381de13bb49aaea66530c4a4b8271f3eae172cd366e07e6636f1019d2a28aed1",
                    "5e",
                ),
            ),
            (
                concat!(
                    "bf6d42e701707b1d0206b0c8b45a1c72641ff12889219a82bdea965b5e79a96b",
                    "0d0163ed9d578ec9ada20f2fbcf1ea3c4089d83419ba81b0c60f3606da99",
                ),
                "ad997feef730d6ea7be60d0dc52e72eacbfdd275",
                concat!(
                    "0301f935e9c47abcb48acbbe09895d9f5971af14839da4ff95417ee453d1fd77",
                    "319072bb7297e1b55d7561cd9d1bb24c1a9a37c619864308242804879d86ebd0",
                    "01dce5183975e1506989b70e5a83434154d5cbfd6a24787e60eb0c658d2ac193",
                    "302d1192c6e622d4a12ad4b53923bca246df31c6395e37702c6a78ae081fb9d0",
                    "65",
                ),
            ),
            (
                "fb2ef112f5e766eb94019297934794f7be2f6fc1c58e",
                "136454df5730f73c807a7e40d8c1a312ac5b9dd3",
                concat!(
                    "02d110ad30afb727beb691dd0cf17d0af1a1e7fa0cc040ec1a4ba26a42c59d0a",
                    "796a2e22c8f357ccc98b6519aceb682e945e62cb734614a529407cd452bee3e4",
                    "4fece8423cc19e55548b8b994b849c7ecde4933e76037e1d0ce44275b08710c6",
                    "8e430130b929730ed77e09b015642c5593f04e4ffb9410798102a8e96ffdfe11",
                    "e4",
                ),
            ),
            (
                "28ccd447bb9e85166dabb9e5b7d1adadc4b9d39f204e96d5e440ce9ad928bc1c2284",
                "bca8057f824b2ea257f2861407eef63d33208681",
                concat!(
                    "00dbb8a7439d90efd919a377c54fae8fe11ec58c3b858362e23ad1b8a4431079",
                    "9066b99347aa525691d2adc58d9b06e34f288c170390c5f0e11c0aa3645959f1",
                    "8ee79e8f2be8d7ac5c23d061f18dd74b8c5f2a58fcb5eb0c54f99f01a8324756",
                    "8292536583340948d7a8c97c4acd1e98d1e29dc320e97a260532a8aa7a758a1e",
                    "c2",
                ),
            ),
            (
                "f22242751ec6b1",
                "2e7e1e17f647b5ddd033e15472f90f6812f3ac4e",
                concat!(
                    "00a5ffa4768c8bbecaee2db77e8f2eec99595933545520835e5ba7db9493d3e1",
                    "7cddefe6a5f567624471908db4e2d83a0fbee60608fc84049503b2234a07dc83",
                    "b27b22847ad8920ff42f674ef79b76280b00233d2b51b8cb2703a9d42bfbc825",
                    "0c96ec32c051e57f1b4ba528db89c37e4c54e27e6e64ac69635ae887d9541619",
                    "a9",
                ),
            ),
        ],
    },
];

/// The first message of the 1024-bit key.
const MESSAGE: &str = "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34";

/// `MESSAGE` with the 1024-bit key, the label hashed by SHA-256 and MGF1
/// over SHA-1, with the seed `01 02 .. 20`.
const MIXED: &str = concat!(
    "054aaa8fe4898737cb14994881ae47956f5a3950d50aaec39cf8cd9912c3c581",
    "5e9fa6e0dda940215cd4fb9bb51e6b66c99daeccca31ff8cb712fa092855c445",
    "7f3cecc46ca543166502211607e1081d1272b0ca898ede899aa7cfd347fe7b13",
    "39a61851b1a1b2d070c59365b12036c2ff959b9bcc40bfcccaf00c719985139e",
);

/// `MESSAGE` with the 1024-bit key, SHA-1, the label `TLS label`, and the
/// seed of the first vector.
const LABELLED: &str = concat!(
    "a58b3111c2e41d5142b64b78f125da8961bc6fe57219f9822bf8780e887a8048",
    "55a9c4df1205be6b07c265f5362be88de592d85b02571b4bc419acb407b4e03f",
    "10a59036f99ad14e2a34eef38932e6c45f3a081ce136b205236c9dbb31e255cc",
    "3dcfa2d1f8ff19e367df0863236a7796b540b484eeacdbce063bc8cff9781667",
);

fn key(vectors: &Vectors, private: bool) -> Key {
    let int = |text: &str| U2048::from_be(&hex(text)).unwrap();
    let exponent = if private {
        vectors.private_exponent
    } else {
        "010001"
    };
    RsaKeyOwned::new(private, int(vectors.modulus), int(exponent))
}

/// A source that gives back the bytes it was made with, and then fails.
struct Fixed(Vec<u8>);

impl TryRng for Fixed {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!("only bytes are drawn")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!("only bytes are drawn")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

fn process<M: Digest, R: CryptoRng>(
    encoding: &mut OaepEncoding<Engine, M, R>,
    direction: CipherDirection,
    key: &Key,
    input: &[u8],
) -> Result<Vec<u8>, Error> {
    encoding.init(direction, key)?;
    let mut output = vec![0; encoding.output_block_size()];
    let length = encoding.process_block(input, &mut output)?;
    output.truncate(length);
    Ok(output)
}

fn encrypt<M: Digest, R: CryptoRng>(
    encoding: &mut OaepEncoding<Engine, M, R>,
    key: &Key,
    message: &[u8],
) -> Vec<u8> {
    process(encoding, CipherDirection::Encrypt, key, message).unwrap()
}

fn decrypt<M: Digest, R: CryptoRng>(
    encoding: &mut OaepEncoding<Engine, M, R>,
    key: &Key,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    process(encoding, CipherDirection::Decrypt, key, ciphertext)
}

/// The encoding with SHA-1, drawing the bytes of `seed`.
fn seeded(seed: &str) -> OaepEncoding<Engine, Sha1Digest, Fixed> {
    OaepEncoding::new(Fixed(hex(seed)))
}

/// The encoding with SHA-1, drawing from a source seeded with `seed`.
fn sha1(seed: u64) -> OaepEncoding<Engine, Sha1Digest, StdRng> {
    OaepEncoding::new(StdRng::seed_from_u64(seed))
}

#[test]
fn the_pkcs1_vectors_encrypt_to_their_ciphertexts_and_back() {
    for (bits, vectors) in [1024, 1027].into_iter().zip(&VECTORS) {
        for (number, &(message, seed, ciphertext)) in vectors.cases.iter().enumerate() {
            let name = format!("{bits} {}", number + 1);
            let mut encoding = seeded(seed);
            assert_eq!(
                encrypt(&mut encoding, &key(vectors, false), &hex(message)),
                hex(ciphertext),
                "{name}"
            );
            assert_eq!(
                decrypt(&mut encoding, &key(vectors, true), &hex(ciphertext)),
                Ok(hex(message)),
                "{name}"
            );
        }
    }
}

#[test]
fn the_blocks_are_twice_the_hash_and_two_bytes_short_of_the_modulus() {
    let mut encoding = sha1(1);
    encoding
        .init(CipherDirection::Encrypt, &key(&VECTORS[0], false))
        .unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (86, 128)
    );
    encoding
        .init(CipherDirection::Decrypt, &key(&VECTORS[0], true))
        .unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (128, 86)
    );
    // The 1027-bit modulus takes 129 bytes.
    encoding
        .init(CipherDirection::Encrypt, &key(&VECTORS[1], false))
        .unwrap();
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (87, 129)
    );
}

#[test]
fn a_label_hashed_by_another_digest_gives_the_ciphertext_worked_out_apart() {
    let seed: Vec<u8> = (1..=32).collect();
    let mut encoding =
        OaepEncoding::<Engine, _, _>::from_parts(Engine::new(), Sha1Digest::new(), Fixed(seed))
            .with_label_digest(Sha256Digest::new(), &[]);
    assert_eq!(
        encrypt(&mut encoding, &key(&VECTORS[0], false), &hex(MESSAGE)),
        hex(MIXED)
    );
    assert_eq!(
        decrypt(&mut encoding, &key(&VECTORS[0], true), &hex(MIXED)),
        Ok(hex(MESSAGE))
    );
    // Sizes follow the hash of the label: 128 - 2 * 32 - 2 bytes.
    assert_eq!(encoding.output_block_size(), 62);
    assert_eq!(
        decrypt(&mut sha1(2), &key(&VECTORS[0], true), &hex(MIXED)),
        Err(EncodingError::InvalidBlock)
    );
}

#[test]
fn a_label_gives_the_ciphertext_worked_out_apart_and_only_it_decrypts_it() {
    let seed = VECTORS[0].cases[0].1;
    let mut encoding = seeded(seed).with_label(b"TLS label");
    assert_eq!(
        encrypt(&mut encoding, &key(&VECTORS[0], false), &hex(MESSAGE)),
        hex(LABELLED)
    );
    assert_eq!(
        decrypt(&mut encoding, &key(&VECTORS[0], true), &hex(LABELLED)),
        Ok(hex(MESSAGE))
    );
    for mut other in [sha1(3), sha1(3).with_label(b"TLS label!")] {
        assert_eq!(
            decrypt(&mut other, &key(&VECTORS[0], true), &hex(LABELLED)),
            Err(EncodingError::InvalidBlock)
        );
    }
}

#[test]
fn each_encryption_draws_a_fresh_seed() {
    let mut encoding = sha1(4);
    let first = encrypt(&mut encoding, &key(&VECTORS[0], false), &hex(MESSAGE));
    let second = encrypt(&mut encoding, &key(&VECTORS[0], false), &hex(MESSAGE));
    assert_ne!(first, second);
    for ciphertext in [first, second] {
        assert_eq!(
            decrypt(&mut encoding, &key(&VECTORS[0], true), &ciphertext),
            Ok(hex(MESSAGE))
        );
    }
}

#[test]
fn messages_from_empty_to_the_whole_input_block_round_trip() {
    let mut encoding = sha1(5);
    for length in [0, 1, 85, 86] {
        let message = vec![0x5a; length];
        let ciphertext = encrypt(&mut encoding, &key(&VECTORS[0], false), &message);
        assert_eq!(
            decrypt(&mut encoding, &key(&VECTORS[0], true), &ciphertext),
            Ok(message),
            "{length}"
        );
    }
    encoding
        .init(CipherDirection::Encrypt, &key(&VECTORS[0], false))
        .unwrap();
    assert_eq!(
        encoding.process_block(&[0x5a; 87], &mut [0; 128]),
        Err(EncodingError::InputTooLarge)
    );
}

/// Blocks laid out apart, with Python, with SHA-1 and the seed of the
/// first vector, and encrypted with the 1024-bit key; the message is ten
/// bytes of `5a`.
#[test]
fn blocks_laid_out_wrong_fail_decryption_alike() {
    let good = concat!(
        "5f09bf8dca600b7a3a0b8a2607835b5a0ceb2fc49c3eda0ec83607894b18024f",
        "e66f8611d1f31d73ded979d8161aee1089e4b8784d50976c7b02b8b6dc95f304",
        "2f5fc91e13aea9ee94f931818a735fb9e8f0c8ccb3af28b571b0680e780b26b4",
        "d3ae3ddfa2687956489d6599925f4301c56b7f4fbdbb57cb7bc5ebde21e7f460",
    );
    let mut encoding = sha1(6);
    assert_eq!(
        decrypt(&mut encoding, &key(&VECTORS[0], true), &hex(good)),
        Ok(vec![0x5a; 10])
    );
    for (name, bad) in [
        (
            "with a leading byte of one",
            concat!(
                "52e81e46f5221b787e1650806e95514b937e6618f1265e4788b7a5d1f450950b",
                "a0e3c8ee4d38b9b2cce8945d337d27221ff71302725fc54553039c6c0d3c01cd",
                "e01cb253f70e05ebd9286f4bffc96e782125fd86277818b177ef4bead843722e",
                "ae0ab528b9021e8dd8f77f8d59abfb7a3faf5a941ad76da3fabec85a8cb4c152",
            ),
        ),
        (
            "with a separator of two",
            concat!(
                "494e212196fe65c16436d10addad60ed51c75220477a8e5519f237e18294d2b3",
                "015166a7b8df9fb68ce7d3b5be0ba7e70b801be83149d38e96256ca072827c2d",
                "5401eb88cc3722542b24dc3866853fd4451d21af588aecb18d7f690fe54b59cc",
                "4d8a7e33a006e098f66d815a1096614508e21638561bfe5e4a4c9c3ee49f8c98",
            ),
        ),
        (
            "with no separator",
            concat!(
                "3c55dd4945b8bd6cdd8610f70ba4a25d406883e7d4cf2997b3b5ed50f0a87693",
                "14b778f6a25926eea3d0d2da6087d053dd2b9d37b3a1ca1072af96b39545a122",
                "bd371a46c670ffb3516a04406c3b94c2041839bfc10d31418225af1225e91d51",
                "56291b0ddd49e57e06bbb368c8d1d7271ce5730a6319afa5aeea7eac396ca954",
            ),
        ),
        (
            "with a bit of the label hash off",
            concat!(
                "78a932c56dc6412835441da8443b374480aa07ba9348acc54aa138e3a62c575e",
                "4975c8399ebc4850fda4e2d5001feefb57c2dbdd9489d4c4335f82318e3cc796",
                "209ae5e0082b782e910d292bcb5d4ad7366d7c2ac9201ef258462126deaaf632",
                "3125b176be972d5142b665af742777a9ea30b949cb8215c4ef1d0f058d071b44",
            ),
        ),
    ] {
        assert_eq!(
            decrypt(&mut encoding, &key(&VECTORS[0], true), &hex(bad)),
            Err(EncodingError::InvalidBlock),
            "{name}"
        );
    }
}

#[test]
fn an_encoding_not_yet_initialized_processes_nothing() {
    let mut encoding = sha1(7);
    assert_eq!(
        (encoding.input_block_size(), encoding.output_block_size()),
        (0, 0)
    );
    assert_eq!(
        encoding.process_block(&[1], &mut [0; 128]),
        Err(EncodingError::NotInitialized)
    );
}

#[test]
fn an_output_shorter_than_the_output_block_is_turned_down() {
    let mut encoding = sha1(8);
    encoding
        .init(CipherDirection::Encrypt, &key(&VECTORS[0], false))
        .unwrap();
    assert_eq!(
        encoding.process_block(&[1], &mut [0; 127]),
        Err(EncodingError::OutputTooShort)
    );
    let ciphertext = encrypt(&mut encoding, &key(&VECTORS[0], false), &[1]);
    encoding
        .init(CipherDirection::Decrypt, &key(&VECTORS[0], true))
        .unwrap();
    assert_eq!(
        encoding.process_block(&ciphertext, &mut [0; 85]),
        Err(EncodingError::OutputTooShort)
    );
    assert_eq!(encoding.process_block(&ciphertext, &mut [0; 86]), Ok(1));
}

#[test]
fn the_errors_of_the_engine_come_through() {
    let mut encoding = sha1(9);
    encoding
        .init(CipherDirection::Decrypt, &key(&VECTORS[0], true))
        .unwrap();
    assert_eq!(
        encoding.process_block(&[0xff; 128], &mut [0; 86]),
        Err(EncodingError::Cipher(RsaError::InputTooLarge))
    );
}

#[test]
fn the_encoding_is_named_after_its_engine() {
    assert_eq!(sha1(10).to_string(), "RSA/OAEPPadding");
}

#[test]
fn the_engine_the_digest_and_the_source_come_back_out_of_the_encoding() {
    let mut rng = StdRng::seed_from_u64(11);
    let mut encoding = OaepEncoding::<Engine, Sha1Digest, _>::new(&mut rng);
    encoding
        .init(CipherDirection::Encrypt, &key(&VECTORS[0], false))
        .unwrap();
    assert_eq!(encoding.underlying_cipher().input_block_size(), 127);
    let (engine, digest, _) = encoding.into_parts();
    assert_eq!(
        (engine.output_block_size(), digest.digest_size()),
        (128, 20)
    );
    // The borrow ends with the encoding, and the source is the caller's again.
    let _: &mut StdRng = &mut rng;
}
