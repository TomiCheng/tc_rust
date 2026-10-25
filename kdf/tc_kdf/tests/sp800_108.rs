//! SP 800-108 against the NIST CAVP vectors that BC's tests read: the first vector of each
//! counter length and counter location, over HMAC-SHA256 and CMAC-AES128.

use tc_aes::AesEngine;
use tc_kdf::sp800_108::{
    KdfCounter, KdfCounterParamsRef, KdfDoublePipeline, KdfDoublePipelineParamsRef, KdfFeedback,
    KdfFeedbackParamsRef, KdfInitError,
};
use tc_kdf::{Kdf, KdfError, KdfInit};
use tc_macs::{Cmac, Hmac};
use tc_sha::Sha256Digest;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Prf {
    HmacSha256,
    CmacAes128,
}

fn derive<K, P>(mut kdf: K, params: &P, len: usize) -> Vec<u8>
where
    K: Kdf + KdfInit<P>,
    P: ?Sized,
{
    kdf.init(params).ok().unwrap();
    let mut output = vec![0; len];
    assert_eq!(kdf.generate_bytes(&mut output).ok(), Some(len));
    output
}

fn hmac() -> Hmac<Sha256Digest> {
    Hmac::new(Sha256Digest::new())
}

fn cmac() -> Cmac<AesEngine> {
    Cmac::new(AesEngine::new())
}
/// PRF, r, L in bits, Ki, data before the counter, data after it, KO.
type CounterVector = (
    Prf,
    usize,
    usize,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const COUNTER: &[CounterVector] = &[
    (
        Prf::CmacAes128,
        8,
        128,
        "dff1e50ac0b69dc40f1051d46c2b069c",
        "",
        "c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5",
        "8be8f0869b3c0ba97b71863d1b9f7813",
    ),
    (
        Prf::CmacAes128,
        16,
        128,
        "30ec5f6fa1def33cff008178c4454211",
        "",
        "c95e7b1d4f2570259abfc05bb00730f0284c3bb9a61d07259848a1cb57c81d8a6c3382c500bf801dfc8f70726b082cf4c3fa34386c1e7bf0e5471438",
        "00018fff9574994f5c4457f461c7a67e",
    ),
    (
        Prf::CmacAes128,
        24,
        128,
        "ca1cf43e5ccd512cc719a2f9de41734c",
        "",
        "e3884ac963196f02ddd09fc04c20c88b60faa775b5ef6feb1faf8c5e098b5210e2b4e45d62cc0bf907fd68022ee7b15631b5c8daf903d99642c5b831",
        "1cb2b12326cc5ec1eba248167f0efd58",
    ),
    (
        Prf::CmacAes128,
        32,
        128,
        "c10b152e8c97b77e18704e0f0bd38305",
        "",
        "98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4",
        "26faf61908ad9ee881b8305c221db53f",
    ),
    (
        Prf::CmacAes128,
        8,
        128,
        "e61a51e1633e7d0de704dcebbd8f962f",
        "5eef88f8cb188e63e08e23c957ee424a3345da88400c567548b57693931a847501f8e1bce1c37a09ef8c6e2ad553dd0f603b52cc6d4e4cbb76eb6c8f",
        "",
        "63a5647d0fe69d21fc420b1a8ce34cc1",
    ),
    (
        Prf::CmacAes128,
        16,
        128,
        "b03616e032b6d1aa53352a8d7dfabcfe",
        "fba6aea08c2ccf83f7142b72a476839a98a7d967125c9dfc83ae82f1fb6c913afc82bf65342356d2e7f929528589bc94c2f54d52b2487ee9f4a52510",
        "",
        "8c5175addd7d847e30f48ef6ce373954",
    ),
    (
        Prf::CmacAes128,
        24,
        128,
        "03dd577bd0e65a26502453d5de9e682b",
        "bf4e85e80ee83637bbe972a371c5a74d0511e0eeb9485f3d1d075f1fdbb00f5ea7f64b080cf2c8d21b213bb1e96cd047ddc3f005851bf4b07e7a0232",
        "",
        "f8fa72a1f1c0b234c7f76a425778ad4e",
    ),
    (
        Prf::CmacAes128,
        32,
        128,
        "02f9ff0a7b136bdbdb09bc420a35d46f",
        "ebdacfb0d14c6e38602dc95b43cea8d354596c360b31a02ea780d4fe35728ec75de2fb357c36c1210c10d35369982989ad02ab4f4094fdc86618e3f9",
        "",
        "207ee3acb1d1785fb36109f9970153d8",
    ),
    (
        Prf::CmacAes128,
        8,
        128,
        "b6e04abd1651f8794d4326f4c684e631",
        "93612f7256c46a3d856d3e951e32dbf15fe11159d0b389ad38d603850fee6d18d22031435ed36ee20da76745fbea4b10fe1e",
        "99322aae605a5f01e32b",
        "dcb1db87a68762c6b3354779fa590bef",
    ),
    (
        Prf::CmacAes128,
        16,
        128,
        "63cf79372dbe425d2c5832603fb96d93",
        "91f5b0021524e8f85dc4af0bb83a9386e89635d19f9e4652d8d1837d2cdcd0b20fa50c1397ed450410cc9109b2ae1bad0b85",
        "81205d2dc8429ce7e428",
        "50569fc30e309a6337c14c5ba320271f",
    ),
    (
        Prf::CmacAes128,
        24,
        128,
        "bc1b3659d7c2fcf008b0da456fd876c5",
        "c8e13862185cbbee6544c2a7367d5216becf6352464b35e362c328f31b378f3481cdc09c46efed015dead1958db5701a940d",
        "a75853711d59f7b819b0",
        "da6a63b32c2f051e9833d61f92f35d70",
    ),
    (
        Prf::CmacAes128,
        32,
        128,
        "90e33a1e76adedcabd2214326be71abf",
        "3d2f38c571575807eecd0ec9e3fd860fb605f0b17139ce01904abba7ae688a50e620341787f69f00b872343f42b18c979f6f",
        "8885034123cb45e27440",
        "9e2156cd13e079c1e6c6379f9a55f433",
    ),
    (
        Prf::HmacSha256,
        8,
        128,
        "3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83",
        "",
        "98e9988bb4cc8b34d7922e1c68ad692ba2a1d9ae15149571675f17a77ad49e80c8d2a85e831a26445b1f0ff44d7084a17206b4896c8112daad18605a",
        "6c037652990674a07844732d0ad985f9",
    ),
    (
        Prf::HmacSha256,
        16,
        128,
        "743434c930fe923c350ec202bef28b768cd6062cf233324e21a86c31f9406583",
        "",
        "9bdb8a454bd55ab30ced3fd420fde6d946252c875bfe986ed34927c7f7f0b106dab9cc85b4c702804965eb24c37ad883a8f695587a7b6094d3335bbc",
        "19c8a56db1d2a9afb793dc96fbde4c31",
    ),
    (
        Prf::HmacSha256,
        24,
        128,
        "388e93e0273e62f086f52f6f5369d9e4626d143dce3b6afc7caf2c6e7344276b",
        "",
        "697bb34b3fbe6853864cac3e1bc6c8c44a4335565479403d949fcbb5e2c1795f9a3849df743389d1a99fe75ef566e6227c591104122a6477dd8e8c8e",
        "d697442b3dd51f96cae949586357b9a6",
    ),
    (
        Prf::HmacSha256,
        32,
        128,
        "dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0",
        "",
        "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac",
        "10621342bfb0fd40046c0e29f2cfdbf0",
    ),
    (
        Prf::HmacSha256,
        8,
        128,
        "08d0a37d2e2fb84d44838efaeac28135d964b0daf154369783cfe007fa883966",
        "80866d761e34084b45ea668a25deabffdbca446aa0bf793bccdf3790d584d26056315a4c060ac7b1b01cace96ba97e8fed81953c8b82ba5132dd1713",
        "",
        "8f5b47d23d5d3ba632acdf6543509bd8",
    ),
    (
        Prf::HmacSha256,
        16,
        128,
        "3b11d0b6f1b49d1a41eecc7448766bbfee47d32a28a3f2be3d3b5f21c4d1e6c6",
        "a6aca3725e8687268cd9cefcc4f3799090568e777a18e82569922463658c4e8fce319316edc172eae3c7e4f4224ffe7d72730ec2f8472f80122a5cc0",
        "",
        "fffbde92bad6dbfc61953b78c47f7b93",
    ),
    (
        Prf::HmacSha256,
        24,
        128,
        "585245d11e0b69d10e2ea39c76c8625003aa775037e476009856ac8e3e9f9b48",
        "1b8234e4a0c9f674fd6f29965bd03df4a8d30b17cf95b058ac46bc2fe9d8ec79a004a2e11165ae3131b9b9440abf9a6fded0d31af468aa56fee00158",
        "",
        "73781a39ab0f3cdae0d8ea9649ecbe9b",
    ),
    (
        Prf::HmacSha256,
        32,
        128,
        "ec8674a48a7baf28f865e63a3e8313fd55a09c8a46fb491916a871d1e65ab7f4",
        "808772849ce4e97060618f8e510419a82d78a72ff265aa247335069fc73eca8df5276c850b5f052f0551da5319bb9e39318a820b167c6f999c67d4ae",
        "",
        "9417ee14f9ebeb2e2c7bce18aa56a1a5",
    ),
    (
        Prf::HmacSha256,
        8,
        128,
        "6fd0f7b67db5b9ef0fd21d4408dae15af5524b00e8d583e9872760ebf6d53397",
        "fc67e8cd41dcb339fe376892b3c196ad4d70573e031cebac67bb32a00a878d0064446a98fcce9ccaa6d8d388e3cbdfb8dcc6",
        "e9798604020da472f161",
        "b24833fe4a28f84fb4341bc42abc4ae6",
    ),
    (
        Prf::HmacSha256,
        16,
        128,
        "e4f6a0b7bc8941f115f9523a050f527687213a4236bb8047d9ec6671be35278c",
        "883c38f759847b142a05ba28152a391b826468fda0a269d55248d1c3daf2e66fe91c20b85c57f6b5464903bc93500e5bee04",
        "9c52c875593e59580155",
        "c9f14ec1dbc676ac650ffcd143bf5c5c",
    ),
    (
        Prf::HmacSha256,
        24,
        128,
        "367fc005cb2565a92cf8b1cfdf4869ccad04c9fdfc8250d027d82a33cd0b36e0",
        "f3a71b1465972703773ec0c92681bc27e626587fe683a07fed69c9bb0a1053afa1ec187cf26fa9dd8c690f415af98d442470",
        "b9dc98f750c71d74e243",
        "67301e0b417c5af335caee31b3e620c3",
    ),
    (
        Prf::HmacSha256,
        32,
        128,
        "60e118235b5fca0b15f8dbe6109b6a1a2f9d0d6f69cecfb5f65d4eb5a1c00a36",
        "3c04bf77b146ef5842daafe19edb9530b7d19b3519aa5c7e797ca5cea0d82ddea484d87d735e3541cf0ba1505cf5c45d8067",
        "9803f3f48ea0a23e2856",
        "d296bb7b1707c9109d19abf026c141f8",
    ),
];

/// PRF, r (`None` without a counter), L in bits, Ki, IV, fixed input, KO.
type FeedbackVector = (
    Prf,
    Option<usize>,
    usize,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const FEEDBACK: &[FeedbackVector] = &[
    (
        Prf::CmacAes128,
        Some(8),
        512,
        "b270a032965c6c1f06c4a6f89f18f2d1",
        "858f8eb9d1d7c6b7bb7cb9eb690fb48f",
        "1a791bc6002f39333e1cf6dcdf8392f74f189c27fb6d8111993c2e4f48d656c0bd98fdcaf3e9af63e4fba28cb2935beaa24ed2",
        "2ae3daac8fd12a7a8133e8a0a440d1a2a6aae78bb0e14a092818f93857c8efefb2e92b0f2198514c667f8d6773ddc0bb3ea42b86999a90bb384a619eb185f1ed",
    ),
    (
        Prf::CmacAes128,
        Some(16),
        512,
        "194cbc62d388e155da2dfdcad3ef9989",
        "55c9d5e508c5edfef57b591df0eb5d89",
        "5aa889f785565cd44cb4ea873c1ecd123f3033fd55eb5ab355fefbb50880cf3155e72a577e37d9d1d446d4636a34e98a497654",
        "b955a297e9ab5fbea3e3d01f2755dc5f2192838865ac1930464cf7b484dc9e421b87b0e0e1caf48632ed60a18f26ec9eb05a5ab916c2df4b9d94a4f907b10a4f",
    ),
    (
        Prf::CmacAes128,
        Some(24),
        512,
        "7028c9bc1570607c237444d92b9fd9e2",
        "c9c7c0e528a41d1ba69c09d90e51536d",
        "eb231f350eb3d9694d16f5387652fc0bbf6ca53dba36f7ca230c3f0f1b5b7b5ebc1e4f323ea27ba45e20ff00813c43eddb8682",
        "f50897267bbbb334e5dac9127021da347baff73457e112b93de8e56de6f3ba0062df7356ea1b69a036cc02c37eb2fa8f123d879126c5db10c208c6c895590070",
    ),
    (
        Prf::CmacAes128,
        Some(32),
        512,
        "607a069650470c92021850add7506fed",
        "bcc557c72df7ed5163e39bf201d2354f",
        "d465d19beb40b57d51eb30f9b8170f33a07ffbf03e41b6ade6338cb85d75b910bc0af62e3a228bacaf68eb099d1d315ce09395",
        "d5741964649e1a4f825493f933cdc02a8edb6001a3986050cf7511184e4794cdec967e631d5b323f39315bf4bd2c45b692d632dfb6bdb86d509845fe63df550d",
    ),
    (
        Prf::HmacSha256,
        Some(8),
        512,
        "08f1d928d466e9a709832c93ea5f32384f3517e06a9c639c1ad543b2b23841c3",
        "836c1a8933e60dcde0031c8fac9141db0b56f638851815320cfd87d1fcf7a636",
        "7f34e1f4cc56773f6c1016717393d47a7c271dd1024335d913b804817254a59da3ee1fc66f26de9753c9fa9d83b3413dd963d5",
        "ea643447585d9cc52ad64b7034fad8c032ac187d83c30c0f6d7523f3eca1f184202ae2fa304d2e6f16d73036db084799ddffabb59d22bfe59b962432e5d1ef23",
    ),
    (
        Prf::HmacSha256,
        Some(16),
        512,
        "16e7096ddf96b0d861f31e7a6b33754b045c5e7107ea6ce0698f91c69c8e4dce",
        "eb4412d0665ab13b74c1ad09d5e3de0031380e56430459c543917f580d3d8b7b",
        "e32e45c140888b8b64c84da9852461d29c11b2ee34da2aae635821da94914f3f3f2efd81ebc9434840a174c32cef2a87d56746",
        "33175406d25ae0a7647268f548dc948c21d4215362e11a66779144a88f44ddc074e2df853152d87c55c79e47beb851fa216bd2fa04da425a1d7bcd2edde706c2",
    ),
    (
        Prf::HmacSha256,
        Some(24),
        512,
        "59d0fecdf3dec65a2ff4f2ba848b27f1f9b72f012a5404ff79fd722ee3d1b282",
        "16100f9763a1621f81b21693ac77595191539e168606c7637c19eaab25d4a310",
        "9663d24c6815c4c1063f22b03acbfe5fde32f4c9d0c4a6917f69a0b73ff987febe260d8f56674c883adb446e534c5164175387",
        "0976becd311a8ac8aa8eb6f4d775cd7f1c0ec766d9d3cf084b1e788fab2f402d00a1f463c5bf60536b6a0a0c098552270e561f67c3dd2e73a2664ce5ff8f55ec",
    ),
    (
        Prf::HmacSha256,
        Some(32),
        512,
        "94d74ec6747861a3b06fbf8db8bcce620bdca7f1edaa5155d34b58eb29df55d9",
        "694746501393b2fdd1220eb4e53a41961f760edb43a4216d6a2a7c0306ba162b",
        "e67c92a5816746464d8f12e32167664de4f183d6c5a867707103db44b697ff50434d21864c4fd1df7fe99629be0894eaa44ca6",
        "1475bf8c0b29c217207165c6618b99e59af773706e9afb11a1b46bbb7bc98b26bfaa24d39d168a6c5ae5e58d25e9817785ffdd1e419bcbc9ed043ef42223c4b6",
    ),
    (
        Prf::CmacAes128,
        None,
        512,
        "5c996c922f65de97d4408373229814c6",
        "28dc945cb8337ab5336c3e9b5bad21c7",
        "62afe5fed91e797221a854336b0aadd8a05ad0e3c8345729897b2efcec5a1178a2fa4c063007b67a7015e0d6b7271ea8d86b44",
        "88a9aae193abdd3fe8143bab66014ae41dc2d12ea9d08f5871588fc5d827924eb9942989d7a36d4b3b107997566472cad5942bd13cb5cff32b9dae30f1bb6300",
    ),
    (
        Prf::HmacSha256,
        None,
        512,
        "4b02ffb1cb9987496e19872597b026f7409d92433f9135068c29307985598586",
        "5c2a2262d14994904c9c2de36d66c7ebdaed32b5cc441c222258857f5af29bea",
        "a38f30844136c33e00d4254a8bc5f51e8473ac20e5628e77e4d91a704d58bf0d4d0fefb5f92d897f1958b0af188180b2e2d2f7",
        "ef46a7cc3f2fd3aac2d55c7386b99279098ad8af07e113c683e43601d3e0c9a48165a580d60b9c2df75cdfc066855607c0dd51ad8fc0296c3f72e83d3d5742e2",
    ),
];

/// PRF, r (`None` without a counter), L in bits, Ki, fixed input, KO.
type DoublePipelineVector = (
    Prf,
    Option<usize>,
    usize,
    &'static str,
    &'static str,
    &'static str,
);

const DOUBLE_PIPELINE: &[DoublePipelineVector] = &[
    (
        Prf::CmacAes128,
        Some(8),
        512,
        "08a5a251b8e4826fbf73292f4cd6c790",
        "aa5acbce73a98d4c4f361d5c22a2cc6f6bdc30027aa31af1ba8b15a5bd5b6a34d133519ad1a82483c2d2a6dd9a97273a780421",
        "ff1c72ec38b8968a1ce0942a571a1f522ddd2a1c6ffc2b60c90bb54a5c0e9de40d289686cbff127b408ec64ef615b18c1abc0736ae4c94e33e54d832e686276e",
    ),
    (
        Prf::CmacAes128,
        Some(16),
        512,
        "a71149f89c550fa105d0e4fe29a259f7",
        "bf5899496f84ea3d8960cef052f709fb4876c61dde68bba933104fd31ee4ff26b9b69e861efa63ab61e912001df8cbb6b04c44",
        "9d0ef8ba5276979f8ced4a62a0acb634fd1c424acf3c9198ec62e3a7a295518caebec574943c91ed039c6941c4ce1763ca4c0af5ccb438d1aa00d6762bf4a4fd",
    ),
    (
        Prf::CmacAes128,
        Some(24),
        512,
        "4a1ab30a4b66762ca5951332150acb3b",
        "9d7cba3fcc0449f4aeee5a5a628c7e50307f3814633fabfe315beddfc6416acfa025f74ffbcdbbae9bbf51d81164679b5887b5",
        "563940cd9c72c9d1009cdc84465048e12a819bb5cb5fa271ec8d4eae761a122f02ad3070dad9438f4b41799c5d29d7e126686c521718c916a79cb03f6761fe5d",
    ),
    (
        Prf::CmacAes128,
        Some(32),
        512,
        "34f0c2542bfe13c7149b68c8a1ef636b",
        "daefcc52d6e32e1614109268933087fce3d64a5a6f111ba1a8d343a1e388a1752aaea93853be52864997a81c84b04c4f3ff3bd",
        "fc0eae673e7db3c4660668e187bcd81d5ca9b89213d8d741e71c9bab89bb4fb3c4df541d89a8117f0f56b0f15111ae28abf81fb7d7349fbbcaf01137e4d73527",
    ),
    (
        Prf::HmacSha256,
        Some(8),
        512,
        "abd3b2464d5312d8cb2807ef4e3bf7cf91c7e4e990adac11f29afa513934cd08",
        "5872e2962f8467f7895189abb7d1f5f2d301498ac2f9de8faaac4a4e79b3a2b5ded58aed6d619e12045a0273df9845750a50a3",
        "da7e3b5c5d5b3c8623ce56d855e0737dd6f086d96054ebc1a588a147e7a68a157bd2abddbe1fccadc4499782e763908a914005f2767dca36395abec5efb39cb7",
    ),
    (
        Prf::HmacSha256,
        Some(16),
        512,
        "18d898675ddae58d5fd003129e67258416f720c469ad32a33413d1f5ec4f9659",
        "f58829b5e94da7a8fe7f0aab6bcc7e6d5faf420d558e911a8ab8af0f30f23fdeef95dfd67b2c7bae99652bf05f7e45d75e00ba",
        "d05c06a1b82d8fca328bbefff2ee4e6c3e5379160cfb926d25ec2a659c1e76c59b723348512da475108f843e69e7fb73092b51133ac0e51a91043256bbf88c93",
    ),
    (
        Prf::HmacSha256,
        Some(24),
        512,
        "b9ae7bfefd01bd135efef7b58058d7a8be563b471124efa4eacca983cd56a921",
        "d39a29c988bce8c616c9eed55d2a4b7c44337cb8afc4b72aaf0230ba9b31bbfd25bfe442ba1f1f341ab992c9db1b974efa86f4",
        "b4f293e997de0907df297aad03693bcca7623c12446c3efb45414271fb845574eb69065b5f4f23a0d61d22d03a94d6b72e545c2fcbfd102cf4dd757d4234f895",
    ),
    (
        Prf::HmacSha256,
        Some(32),
        512,
        "02d36fa021c20ddbdee469f0579468bae5cb13b548b6c61cdf9d3ec419111de2",
        "85abe38bf265fbdc6445ae5c71159f1548c73b7d526a623104904a0f8792070b3df9902b9669490425a385eadb0f9c76e46f0f",
        "d69f74f518c9f64f90a0beebab69f689b73b5c13eb0f860a95cad7d9814f8c506eb7b179a5c5b4466a9ec154c3bf1c13efd6ec0d82b02c29af2c690299edc453",
    ),
    (
        Prf::CmacAes128,
        None,
        512,
        "ada2452f1f141a82c7a1b7d3e09ffed1",
        "335660eb265d2044efa06eacd848d3f9f57d219011343318f3a964df4a6fb1bf6cbdee711c7fcbe73b8f257f992e47e8b065af",
        "a73bd29176e38e761222ae07d639181f4b2c555a3b261815cde5d88a67c8b95c58b6b66ea4f10608c6d799b051519fc8e89de00cdc556350a7d966475086f9af",
    ),
    (
        Prf::HmacSha256,
        None,
        512,
        "7d4f86fdfd1c4ba04c674a68d60316d12c99c1b1f44f0a8e02bd2601377ebcd9",
        "921ab061920b191de12f746ac9de08004f2c20f01775e27bcacdc21ee4a5ff0387758f36d8ec71c7a8c8208284f650b611837e",
        "506bc2ba51410b2a6e7c05d33891520ddd5f702ad3d6203d76d8dae1216d0783d8c59fae2e821d8eff2d8ddd93a6741c8f144fb96e9ca7d7c532468f213f5efe",
    ),
];

#[test]
fn counter_mode_matches_the_cavp_vectors_at_every_counter_location_and_length() {
    assert_eq!(COUNTER.len(), 24);
    for &(prf, r, l, ki, prefix, suffix, ko) in COUNTER {
        let (ki, prefix, suffix) = (hex(ki), hex(prefix), hex(suffix));
        let params = KdfCounterParamsRef::with_prefix(&ki, &prefix, &suffix, r);
        let output = match prf {
            Prf::HmacSha256 => derive(KdfCounter::new(hmac()), &params, l / 8),
            Prf::CmacAes128 => derive(KdfCounter::new(cmac()), &params, l / 8),
        };
        assert_eq!(output, hex(ko), "{prf:?} r={r}");
    }
}

#[test]
fn feedback_mode_matches_the_cavp_vectors_with_and_without_a_counter() {
    assert_eq!(FEEDBACK.len(), 10);
    for &(prf, r, l, ki, iv, fixed_input, ko) in FEEDBACK {
        let (ki, iv, fixed_input) = (hex(ki), hex(iv), hex(fixed_input));
        let params = match r {
            Some(r) => KdfFeedbackParamsRef::with_counter(&ki, &iv, &fixed_input, r),
            None => KdfFeedbackParamsRef::without_counter(&ki, &iv, &fixed_input),
        };
        let output = match prf {
            Prf::HmacSha256 => derive(KdfFeedback::new(hmac()), &params, l / 8),
            Prf::CmacAes128 => derive(KdfFeedback::new(cmac()), &params, l / 8),
        };
        assert_eq!(output, hex(ko), "{prf:?} r={r:?}");
    }
}

#[test]
fn double_pipeline_mode_matches_the_cavp_vectors_with_and_without_a_counter() {
    assert_eq!(DOUBLE_PIPELINE.len(), 10);
    for &(prf, r, l, ki, fixed_input, ko) in DOUBLE_PIPELINE {
        let (ki, fixed_input) = (hex(ki), hex(fixed_input));
        let params = match r {
            Some(r) => KdfDoublePipelineParamsRef::with_counter(&ki, &fixed_input, r),
            None => KdfDoublePipelineParamsRef::without_counter(&ki, &fixed_input),
        };
        let output = match prf {
            Prf::HmacSha256 => derive(KdfDoublePipeline::new(hmac()), &params, l / 8),
            Prf::CmacAes128 => derive(KdfDoublePipeline::new(cmac()), &params, l / 8),
        };
        assert_eq!(output, hex(ko), "{prf:?} r={r:?}");
    }
}

#[test]
fn split_calls_continue_the_same_output() {
    let (ki, fixed_input) = (vec![7; 32], vec![9; 20]);
    let params = KdfFeedbackParamsRef::with_counter(&ki, &[1; 32], &fixed_input, 16);
    let whole = derive(KdfFeedback::new(hmac()), &params, 100);

    let mut kdf = KdfFeedback::new(hmac());
    kdf.init(&params).unwrap();
    let mut pieces = Vec::new();
    for len in [1, 40, 7, 52] {
        let mut piece = vec![0; len];
        kdf.generate_bytes(&mut piece).unwrap();
        pieces.extend(piece);
    }
    assert_eq!(pieces, whole);
}

#[test]
fn an_8_bit_counter_stops_after_255_blocks_where_bc_would_wrap_it() {
    let ki = [7; 32];
    let mut kdf = KdfCounter::new(hmac());
    kdf.init(&KdfCounterParamsRef::new(&ki, b"label", 8))
        .unwrap();
    let mut all = vec![0; 255 * 32];
    assert_eq!(kdf.generate_bytes(&mut all), Ok(255 * 32));
    assert_eq!(
        kdf.generate_bytes(&mut [0; 1]),
        Err(KdfError::OutputTooLong)
    );
}

#[test]
fn init_rejects_a_counter_length_other_than_8_16_24_or_32_bits() {
    let ki = [7; 32];
    for bits in [0, 7, 12, 40, 64] {
        assert_eq!(
            KdfCounter::new(hmac()).init(&KdfCounterParamsRef::new(&ki, &[], bits)),
            Err(KdfInitError::InvalidCounterLength(bits))
        );
        assert_eq!(
            KdfFeedback::new(hmac()).init(&KdfFeedbackParamsRef::with_counter(&ki, &[], &[], bits)),
            Err(KdfInitError::InvalidCounterLength(bits))
        );
        assert_eq!(
            KdfDoublePipeline::new(hmac()).init(&KdfDoublePipelineParamsRef::with_counter(
                &ki,
                &[],
                bits
            )),
            Err(KdfInitError::InvalidCounterLength(bits))
        );
    }
}

#[test]
fn an_invalid_counter_length_keeps_the_previous_parameters() {
    let ki = [7; 32];
    let params = KdfCounterParamsRef::new(&ki, b"label", 32);
    let expected = derive(KdfCounter::new(hmac()), &params, 16);

    let mut kdf = KdfCounter::new(hmac());
    kdf.init(&params).unwrap();
    assert!(
        kdf.init(&KdfCounterParamsRef::new(&[1; 16], &[], 12))
            .is_err()
    );
    let mut output = [0; 16];
    kdf.generate_bytes(&mut output).unwrap();
    assert_eq!(output, expected[..]);
}

#[test]
fn generating_before_init_fails() {
    assert_eq!(
        KdfCounter::new(hmac()).generate_bytes(&mut [0; 4]),
        Err(KdfError::NotInitialised)
    );
    assert_eq!(
        KdfFeedback::new(cmac()).generate_bytes(&mut [0; 4]),
        Err(KdfError::NotInitialised)
    );
    assert_eq!(
        KdfDoublePipeline::new(hmac()).generate_bytes(&mut [0; 4]),
        Err(KdfError::NotInitialised)
    );
}
