//! `PssSigner`：Bouncy Castle `PssTest` 的十組 PKCS#1 v2.1 向量（SHA-1、salt 20 位元組，
//! 模數 1024 到 1536 位元，含模數位元數除以 8 餘 1 的金鑰）、隨機 salt 的往返、不同的
//! MGF 雜湊、固定 salt、預先雜湊、BC 算出的 XOF 遮罩，以及錯誤。

use num_traits::Num;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_keccak::ShakeDigest;
use tc_rsa::{RsaEngine, RsaKey, RsaKeyOwned, RsaPrivateCrtKeyOwned};
use tc_rsa_signer::{Mgf1, PssSigner, PssSignerError, XofMgf};
use tc_sha::{Sha1Digest, Sha256Digest};
use tc_signer::{Signer, SignerInit};

struct Key {
    n: &'static str,
    e: &'static str,
    d: &'static str,
    p: &'static str,
    q: &'static str,
    dp: &'static str,
    dq: &'static str,
    qinv: &'static str,
}

struct Example {
    message: &'static str,
    salt: &'static str,
    signature: &'static str,
}

const KEY1: Key = Key {
    n: "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137",
    e: "010001",
    d: "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b325",
    p: "e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443",
    q: "b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd",
    dp: "28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979",
    dq: "1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729",
    qinv: "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d",
};
const EXAMPLE1A: Example = Example {
    message: "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc315475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a41e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce78e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e331170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0167d0",
    salt: "dee959c7e06411361420ff80185ed57f3e6776af",
    signature: "9074308fb598e9701b2294388e52f971faac2b60a5145af185df5287b5ed2887e57ce7fd44dc8634e407c8e0e4360bc226f3ec227f9d9e54638e8d31f5051215df6ebb9c2f9579aa77598a38f914b5b9c1bd83c4e2f9f382a0d0aa3542ffee65984a601bc69eb28deb27dca12c82c2d4c3f66cd500f1ff2b994d8a4e30cbb33c",
};
const EXAMPLE1B: Example = Example {
    message: "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f71a1cca582d43ecc72b1bca16dfc7013226b9e",
    salt: "ef2869fa40c346cb183dab3d7bffc98fd56df42d",
    signature: "3ef7f46e831bf92b32274142a585ffcefbdca7b32ae90d10fb0f0c729984f04ef29a9df0780775ce43739b97838390db0a5505e63de927028d9d29b219ca2c4517832558a55d694a6d25b9dab66003c4cccd907802193be5170d26147d37b93590241be51c25055f47ef62752cfbe21418fafe98c22c4d4d47724fdb5669e843",
};
const KEY2: Key = Key {
    n: "01d40c1bcf97a68ae7cdbd8a7bf3e34fa19dcca4ef75a47454375f94514d88fed006fb829f8419ff87d6315da68a1ff3a0938e9abb3464011c303ad99199cf0c7c7a8b477dce829e8844f625b115e5e9c4a59cf8f8113b6834336a2fd2689b472cbb5e5cabe674350c59b6c17e176874fb42f8fc3d176a017edc61fd326c4b33c9",
    e: "010001",
    d: "027d147e4673057377fd1ea201565772176a7dc38358d376045685a2e787c23c15576bc16b9f444402d6bfc5d98a3e88ea13ef67c353eca0c0ddba9255bd7b8bb50a644afdfd1dd51695b252d22e7318d1b6687a1c10ff75545f3db0fe602d5f2b7f294e3601eab7b9d1cecd767f64692e3e536ca2846cb0c2dd486a39fa75b1",
    p: "016601e926a0f8c9e26ecab769ea65a5e7c52cc9e080ef519457c644da6891c5a104d3ea7955929a22e7c68a7af9fcad777c3ccc2b9e3d3650bce404399b7e59d1",
    q: "014eafa1d4d0184da7e31f877d1281ddda625664869e8379e67ad3b75eae74a580e9827abd6eb7a002cb5411f5266797768fb8e95ae40e3e8a01f35ff89e56c079",
    dp: "e247cce504939b8f0a36090de200938755e2444b29539a7da7a902f6056835c0db7b52559497cfe2c61a8086d0213c472c78851800b171f6401de2e9c2756f31",
    dq: "b12fba757855e586e46f64c38a70c68b3f548d93d787b399999d4c8f0bbd2581c21e19ed0018a6d5d3df86424b3abcad40199d31495b61309f27c1bf55d487c1",
    qinv: "564b1e1fa003bda91e89090425aac05b91da9ee25061e7628d5f51304a84992fdc33762bd378a59f030a334d532bd0dae8f298ea9ed844636ad5fb8cbdc03cad",
};
const EXAMPLE2A: Example = Example {
    message: "daba032066263faedb659848115278a52c44faa3a76f37515ed336321072c40a9d9b53bc05014078adf520875146aae70ff060226dcb7b1f1fc27e9360",
    salt: "57bf160bcb02bb1dc7280cf0458530b7d2832ff7",
    signature: "014c5ba5338328ccc6e7a90bf1c0ab3fd606ff4796d3c12e4b639ed9136a5fec6c16d8884bdd99cfdc521456b0742b736868cf90de099adb8d5ffd1deff39ba4007ab746cefdb22d7df0e225f54627dc65466131721b90af445363a8358b9f607642f78fab0ab0f43b7168d64bae70d8827848d8ef1e421c5754ddf42c2589b5b3",
};
const EXAMPLE2B: Example = Example {
    message: "e4f8601a8a6da1be34447c0959c058570c3668cfd51dd5f9ccd6ad4411fe8213486d78a6c49f93efc2ca2288cebc2b9b60bd04b1e220d86e3d4848d709d032d1e8c6a070c6af9a499fcf95354b14ba6127c739de1bb0fd16431e46938aec0cf8ad9eb72e832a7035de9b7807bdc0ed8b68eb0f5ac2216be40ce920c0db0eddd3860ed788efaccaca502d8f2bd6d1a7c1f41ff46f1681c8f1f818e9c4f6d91a0c7803ccc63d76a6544d843e084e363b8acc55aa531733edb5dee5b5196e9f03e8b731b3776428d9e457fe3fbcb3db7274442d785890e9cb0854b6444dace791d7273de1889719338a77fe",
    salt: "7f6dd359e604e60870e898e47b19bf2e5a7b2a90",
    signature: "010991656cca182b7f29d2dbc007e7ae0fec158eb6759cb9c45c5ff87c7635dd46d150882f4de1e9ae65e7f7d9018f6836954a47c0a81a8a6b6f83f2944d6081b1aa7c759b254b2c34b691da67cc0226e20b2f18b42212761dcd4b908a62b371b5918c5742af4b537e296917674fb914194761621cc19a41f6fb953fbcbb649dea",
};
const KEY4: Key = Key {
    n: "054adb7886447efe6f57e0368f06cf52b0a3370760d161cef126b91be7f89c421b62a6ec1da3c311d75ed50e0ab5fff3fd338acc3aa8a4e77ee26369acb81ba900fa83f5300cf9bb6c53ad1dc8a178b815db4235a9a9da0c06de4e615ea1277ce559e9c108de58c14a81aa77f5a6f8d1335494498848c8b95940740be7bf7c3705",
    e: "010001",
    d: "fa041f8cd9697ceed38ec8caa275523b4dd72b09a301d3541d72f5d31c05cbce2d6983b36183af10690bd46c46131e35789431a556771dd0049b57461bf060c1f68472e8a67c25f357e5b6b4738fa541a730346b4a07649a2dfa806a69c975b6aba64678acc7f5913e89c622f2d8abb1e3e32554e39df94ba60c002e387d9011",
    p: "029232336d2838945dba9dd7723f4e624a05f7375b927a87abe6a893a1658fd49f47f6c7b0fa596c65fa68a23f0ab432962d18d4343bd6fd671a5ea8d148413995",
    q: "020ef5efe7c5394aed2272f7e81a74f4c02d145894cb1b3cab23a9a0710a2afc7e3329acbb743d01f680c4d02afb4c8fde7e20930811bb2b995788b5e872c20bb1",
    dp: "026e7e28010ecf2412d9523ad704647fb4fe9b66b1a681581b0e15553a89b1542828898f27243ebab45ff5e1acb9d4df1b051fbc62824dbc6f6c93261a78b9a759",
    dq: "012ddcc86ef655998c39ddae11718669e5e46cf1495b07e13b1014cd69b3af68304ad2a6b64321e78bf3bbca9bb494e91d451717e2d97564c6549465d0205cf421",
    qinv: "010600c4c21847459fe576703e2ebecae8a5094ee63f536bf4ac68d3c13e5e4f12ac5cc10ab6a2d05a199214d1824747d551909636b774c22cac0b837599abcc75",
};
const EXAMPLE4A: Example = Example {
    message: "9fb03b827c8217d9",
    salt: "ed7c98c95f30974fbe4fbddcf0f28d6021c0e91d",
    signature: "0323d5b7bf20ba4539289ae452ae4297080feff4518423ff4811a817837e7d82f1836cdfab54514ff0887bddeebf40bf99b047abc3ecfa6a37a3ef00f4a0c4a88aae0904b745c846c4107e8797723e8ac810d9e3d95dfa30ff4966f4d75d13768d20857f2b1406f264cfe75e27d7652f4b5ed3575f28a702f8c4ed9cf9b2d44948",
};
const EXAMPLE4B: Example = Example {
    message: "0ca2ad77797ece86de5bf768750ddb5ed6a3116ad99bbd17edf7f782f0db1cd05b0f677468c5ea420dc116b10e80d110de2b0461ea14a38be68620392e7e893cb4ea9393fb886c20ff790642305bf302003892e54df9f667509dc53920df583f50a3dd61abb6fab75d600377e383e6aca6710eeea27156e06752c94ce25ae99fcbf8592dbe2d7e27453cb44de07100ebb1a2a19811a478adbeab270f94e8fe369d90b3ca612f9f",
    salt: "22d71d54363a4217aa55113f059b3384e3e57e44",
    signature: "049d0185845a264d28feb1e69edaec090609e8e46d93abb38371ce51f4aa65a599bdaaa81d24fba66a08a116cb644f3f1e653d95c89db8bbd5daac2709c8984000178410a7c6aa8667ddc38c741f710ec8665aa9052be929d4e3b16782c1662114c5414bb0353455c392fc28f3db59054b5f365c49e1d156f876ee10cb4fd70598",
};
const KEY8: Key = Key {
    n: "495370a1fb18543c16d3631e3163255df62be6eee890d5f25509e4f778a8ea6fbbbcdf85dff64e0d972003ab3681fbba6dd41fd541829b2e582de9f2a4a4e0a2d0900bef4753db3cee0ee06c7dfae8b1d53b5953218f9cceea695b08668edeaadced9463b1d790d5ebf27e9115b46cad4d9a2b8efab0561b0810344739ada0733f",
    e: "010001",
    d: "6c66ffe98980c38fcdeab5159898836165f4b4b817c4f6a8d486ee4ea9130fe9b9092bd136d184f95f504a607eac565846d2fdd6597a8967c7396ef95a6eeebb4578a643966dca4d8ee3de842de63279c618159c1ab54a89437b6a6120e4930afb52a4ba6ced8a4947ac64b30a3497cbe701c2d6266d517219ad0ec6d347dbe9",
    p: "08dad7f11363faa623d5d6d5e8a319328d82190d7127d2846c439b0ab72619b0a43a95320e4ec34fc3a9cea876422305bd76c5ba7be9e2f410c8060645a1d29edb",
    q: "0847e732376fc7900f898ea82eb2b0fc418565fdae62f7d9ec4ce2217b97990dd272db157f99f63c0dcbb9fbacdbd4c4dadb6df67756358ca4174825b48f49706d",
    dp: "05c2a83c124b3621a2aa57ea2c3efe035eff4560f33ddebb7adab81fce69a0c8c2edc16520dda83d59a23be867963ac65f2cc710bbcfb96ee103deb771d105fd85",
    dq: "04cae8aa0d9faa165c87b682ec140b8ed3b50b24594b7a3b2c220b3669bb819f984f55310a1ae7823651d4a02e99447972595139363434e5e30a7e7d241551e1b9",
    qinv: "07d3e47bf686600b11ac283ce88dbb3f6051e8efd04680e44c171ef531b80b2b7c39fc766320e2cf15d8d99820e96ff30dc69691839c4b40d7b06e45307dc91f3f",
};
const EXAMPLE8A: Example = Example {
    message: "81332f4be62948415ea1d899792eeacf6c6e1db1da8be13b5cea41db2fed467092e1ff398914c714259775f595f8547f735692a575e6923af78f22c6997ddb90fb6f72d7bb0dd5744a31decd3dc3685849836ed34aec596304ad11843c4f88489f209735f5fb7fdaf7cec8addc5818168f880acbf490d51005b7a8e84e43e54287977571dd99eea4b161eb2df1f5108f12a4142a83322edb05a75487a3435c9a78ce53ed93bc550857d7a9fb",
    salt: "1d65491d79c864b373009be6f6f2467bac4c78fa",
    signature: "0262ac254bfa77f3c1aca22c5179f8f040422b3c5bafd40a8f21cf0fa5a667ccd5993d42dbafb409c520e25fce2b1ee1e716577f1efa17f3da28052f40f0419b23106d7845aaf01125b698e7a4dfe92d3967bb00c4d0d35ba3552ab9a8b3eef07c7fecdbc5424ac4db1e20cb37d0b2744769940ea907e17fbbca673b20522380c5",
};
const EXAMPLE8B: Example = Example {
    message: "e2f96eaf0e05e7ba326ecca0ba7fd2f7c02356f3cede9d0faabf4fcc8e60a973e5595fd9ea08",
    salt: "435c098aa9909eb2377f1248b091b68987ff1838",
    signature: "2707b9ad5115c58c94e932e8ec0a280f56339e44a1b58d4ddcff2f312e5f34dcfe39e89c6a94dcee86dbbdae5b79ba4e0819a9e7bfd9d982e7ee6c86ee68396e8b3a14c9c8f34b178eb741f9d3f121109bf5c8172fada2e768f9ea1433032c004a8aa07eb990000a48dc94c8bac8aabe2b09b1aa46c0a2aa0e12f63fbba775ba7e",
};
const KEY9: Key = Key {
    n: "e6bd692ac96645790403fdd0f5beb8b9bf92ed10007fc365046419dd06c05c5b5b2f48ecf989e4ce269109979cbb40b4a0ad24d22483d1ee315ad4ccb1534268352691c524f6dd8e6c29d224cf246973aec86c5bf6b1401a850d1b9ad1bb8cbcec47b06f0f8c7f45d3fc8f319299c5433ddbc2b3053b47ded2ecd4a4caefd614833dc8bb622f317ed076b8057fe8de3f84480ad5e83e4a61904a4f248fb397027357e1d30e463139815c6fd4fd5ac5b8172a45230ecb6318a04f1455d84e5a8b",
    e: "010001",
    d: "6a7fd84fb85fad073b34406db74f8d61a6abc12196a961dd79565e9da6e5187bce2d980250f7359575359270d91590bb0e427c71460b55d51410b191bcf309fea131a92c8e702738fa719f1e0041f52e40e91f229f4d96a1e6f172e15596b4510a6daec26105f2bebc53316b87bdf21311666070e8dfee69d52c71a976caae79c72b68d28580dc686d9f5129d225f82b3d615513a882b3db91416b48ce08888213e37eeb9af800d81cab328ce420689903c00c7b5fd31b75503a6d419684d629",
    p: "f8eb97e98df12664eefdb761596a69ddcd0e76daece6ed4bf5a1b50ac086f7928a4d2f8726a77e515b74da41988f220b1cc87aa1fc810ce99a82f2d1ce821edced794c6941f42c7a1a0b8c4d28c75ec60b652279f6154a762aed165d47dee367",
    q: "ed4d71d0a6e24b93c2e5f6b4bbe05f5fb0afa042d204fe3378d365c2f288b6a8dad7efe45d153eef40cacc7b81ff934002d108994b94a5e4728cd9c963375ae49965bda55cbf0efed8d6553b4027f2d86208a6e6b489c176128092d629e49d3d",
    dp: "2bb68bddfb0c4f56c8558bffaf892d8043037841e7fa81cfa61a38c5e39b901c8ee71122a5da2227bd6cdeeb481452c12ad3d61d5e4f776a0ab556591befe3e59e5a7fddb8345e1f2f35b9f4cee57c32414c086aec993e9353e480d9eec6289f",
    dq: "4ff897709fad079746494578e70fd8546130eeab5627c49b080f05ee4ad9f3e4b7cba9d6a5dff113a41c3409336833f190816d8a6bc42e9bec56b7567d0f3c9c696db619b245d901dd856db7c8092e77e9a1cccd56ee4dba42c5fdb61aec2669",
    qinv: "77b9d1137b50404a982729316efafc7dfe66d34e5a182600d5f30a0a8512051c560d081d4d0a1835ec3d25a60f4e4d6aa948b2bf3dbb5b124cbbc3489255a3a948372f6978496745f943e1db4f18382ceaa505dfc65757bb3f857a58dce52156",
};
const EXAMPLE9A: Example = Example {
    message: "a88e265855e9d7ca36c68795f0b31b591cd6587c71d060a0b3f7f3eaef43795922028bc2b6ad467cfc2d7f659c5385aa70ba3672cdde4cfe4970cc7904601b278872bf51321c4a972f3c95570f3445d4f57980e0f20df54846e6a52c668f1288c03f95006ea32f562d40d52af9feb32f0fa06db65b588a237b34e592d55cf979f903a642ef64d2ed542aa8c77dc1dd762f45a59303ed75e541ca271e2b60ca709e44fa0661131e8d5d4163fd8d398566ce26de8730e72f9cca737641c244159420637028df0a18079d6208ea8b4711a2c750f5",
    salt: "c0a425313df8d7564bd2434d311523d5257eed80",
    signature: "586107226c3ce013a7c8f04d1a6a2959bb4b8e205ba43a27b50f124111bc35ef589b039f5932187cb696d7d9a32c0c38300a5cdda4834b62d2eb240af33f79d13dfbf095bf599e0d9686948c1964747b67e89c9aba5cd85016236f566cc5802cb13ead51bc7ca6bef3b94dcbdbb1d570469771df0e00b1a8a06777472d2316279edae86474668d4e1efff95f1de61c6020da32ae92bbf16520fef3cf4d88f61121f24bbd9fe91b59caf1235b2a93ff81fc403addf4ebdea84934a9cdaf8e1a9e",
};
const EXAMPLE9B: Example = Example {
    message: "c8c9c6af04acda414d227ef23e0820c3732c500dc87275e95b0d095413993c2658bc1d988581ba879c2d201f14cb88ced153a01969a7bf0a7be79c84c1486bc12b3fa6c59871b6827c8ce253ca5fefa8a8c690bf326e8e37cdb96d90a82ebab69f86350e1822e8bd536a2e",
    salt: "b307c43b4850a8dac2f15f32e37839ef8c5c0e91",
    signature: "80b6d643255209f0a456763897ac9ed259d459b49c2887e5882ecb4434cfd66dd7e1699375381e51cd7f554f2c271704b399d42b4be2540a0eca61951f55267f7c2878c122842dadb28b01bd5f8c025f7e228418a673c03d6bc0c736d0a29546bd67f786d9d692ccea778d71d98c2063b7a71092187a4d35af108111d83e83eae46c46aa34277e06044589903788f1d5e7cee25fb485e92949118814d6f2c3ee361489016f327fb5bc517eb50470bffa1afa5f4ce9aa0ce5b8ee19bf5501b958",
};

fn int(hex: &str) -> PaddedBigUint {
    PaddedBigUint::from_str_radix(hex, 16).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn public_key(key: &Key) -> RsaKey {
    RsaKeyOwned::new(false, int(key.n), int(key.e)).into()
}

fn private_key(key: &Key) -> RsaKey {
    RsaPrivateCrtKeyOwned::new(
        int(key.n),
        int(key.e),
        int(key.d),
        int(key.p),
        int(key.q),
        int(key.dp),
        int(key.dq),
        int(key.qinv),
    )
    .into()
}

fn sign<S: Signer + SignerInit<RsaKey>>(mut signer: S, key: &RsaKey, message: &[u8]) -> Vec<u8>
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    let mut signature = vec![0; signer.max_signature_size()];
    let length = signer.generate_signature(&mut signature).unwrap();
    signature.truncate(length);
    signature
}

fn verify<S: Signer + SignerInit<RsaKey>>(
    mut signer: S,
    key: &RsaKey,
    message: &[u8],
    signature: &[u8],
) -> bool
where
    <S as Signer>::Error: core::fmt::Debug,
    <S as SignerInit<RsaKey>>::Error: core::fmt::Debug,
{
    signer.init(key).unwrap();
    signer.update(message).unwrap();
    signer.verify_signature(signature).unwrap()
}

fn sha1_signer() -> PssSigner<RsaEngine, Sha1Digest, Mgf1<Sha1Digest>, rand::rngs::ThreadRng> {
    PssSigner::new(RsaEngine::new(), Sha1Digest::default(), rand::rng())
}

#[test]
fn the_ten_pkcs1_vectors_of_bouncy_castle_sign_and_verify() {
    for (key, examples) in [
        (&KEY1, [&EXAMPLE1A, &EXAMPLE1B]),
        (&KEY2, [&EXAMPLE2A, &EXAMPLE2B]),
        (&KEY4, [&EXAMPLE4A, &EXAMPLE4B]),
        (&KEY8, [&EXAMPLE8A, &EXAMPLE8B]),
        (&KEY9, [&EXAMPLE9A, &EXAMPLE9B]),
    ] {
        for example in examples {
            let message = bytes(example.message);
            let signer = || sha1_signer().with_salt(bytes(example.salt));
            let signature = sign(signer(), &private_key(key), &message);
            assert_eq!(signature, bytes(example.signature));
            assert!(verify(
                sha1_signer(),
                &public_key(key),
                &message,
                &signature
            ));
        }
    }
}

#[test]
fn random_salts_differ_and_verify_with_another_mgf_digest() {
    let message = [0x5a; 1000];
    let signer = || {
        PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng())
            .with_mask(Mgf1::new(Sha1Digest::default()))
            .with_salt_length(20)
    };
    let first = sign(signer(), &private_key(&KEY8), &message);
    let second = sign(signer(), &private_key(&KEY8), &message);
    assert_ne!(first, second);
    for signature in [&first, &second] {
        assert!(verify(signer(), &public_key(&KEY8), &message, signature));
    }
    assert!(!verify(sha1_signer(), &public_key(&KEY8), &message, &first));
    assert!(!verify(signer(), &public_key(&KEY8), &message[1..], &first));
}

#[test]
fn a_fixed_salt_verifies_only_with_the_same_salt() {
    let message = bytes("010203040506070809101112131415");
    let signer = |salt: &str| {
        PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng())
            .with_mask(Mgf1::new(Sha1Digest::default()))
            .with_salt(bytes(salt))
    };
    let signature = sign(signer("deadbeef"), &private_key(&KEY8), &message);
    assert!(verify(
        signer("deadbeef"),
        &public_key(&KEY8),
        &message,
        &signature
    ));
    assert!(!verify(
        signer("beefbeef"),
        &public_key(&KEY8),
        &message,
        &signature
    ));
}

#[test]
fn a_raw_signer_signs_a_hash_the_caller_computed() {
    let message = b"hashed by the caller";
    let mut hash = vec![0; 32];
    let mut digest = Sha256Digest::default();
    digest.update(message);
    digest.do_final(&mut hash);
    let raw = || PssSigner::raw(RsaEngine::new(), Sha256Digest::default(), rand::rng());
    let normal = || PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng());

    let signature = sign(raw(), &private_key(&KEY9), &hash);
    assert!(verify(normal(), &public_key(&KEY9), message, &signature));
    let signature = sign(normal(), &private_key(&KEY9), message);
    assert!(verify(raw(), &public_key(&KEY9), &hash, &signature));

    let mut short = raw();
    short.init(&private_key(&KEY9)).unwrap();
    short.update(&hash[1..]).unwrap();
    assert!(matches!(
        short.generate_signature(&mut [0; 192]),
        Err(PssSignerError::Digest(_))
    ));
}

/// BC 的 `PssSigner(RsaEngine, Sha256Digest, ShakeDigest(128), salt)` 以範例 9 的金鑰算出。
const SHAKE_SIGNATURE: &str = "e109808ad1973d72f7f0eaf784fc0efc6a1a7a6491593bc4e4b35a3cfbe8718e9a1e9c813699ccbc3dd8a52897512774c9ac0196d2bfc343d63b5ed4d392b9a75e17210a53e53ea176a82ed0fa68c1694be7fb9ab1cb531dd864814a210d8cb46b0bbbe4b4d9f428f55cd633d53ebf1fa6fe2ea0406772d705fc8278088404bb7f84595e0408e19df7bf6e61e7da8d52a58ee75fe13459b95c113d0ea88d37b9b33e9951c6d953630d4fdf9dd16f7e46629b15da7c5ff8296606f76ec3f9ff59";

#[test]
fn an_xof_mask_matches_bouncy_castle() {
    let message = b"masked with SHAKE128";
    let signer = || {
        PssSigner::new(RsaEngine::new(), Sha256Digest::default(), rand::rng())
            .with_mask(XofMgf::new(ShakeDigest::new(128)))
    };
    let fixed = signer().with_salt(bytes(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ));
    assert_eq!(
        sign(fixed, &private_key(&KEY9), message),
        bytes(SHAKE_SIGNATURE)
    );
    let signature = sign(signer(), &private_key(&KEY9), message);
    assert!(verify(signer(), &public_key(&KEY9), message, &signature));
    assert!(!verify(
        sha1_signer(),
        &public_key(&KEY9),
        message,
        &signature
    ));
}

#[test]
fn errors_are_reported() {
    let mut signer = sha1_signer();
    assert_eq!(signer.update(b"x"), Err(PssSignerError::NotInitialized));

    // 1024 位元的模數放不下 SHA-1 與 110 位元組的 salt。
    let mut too_long = sha1_signer().with_salt_length(110);
    assert!(matches!(
        too_long.init(&private_key(&KEY1)),
        Err(PssSignerError::KeyTooSmall)
    ));

    signer.init(&public_key(&KEY1)).unwrap();
    assert_eq!(
        signer.generate_signature(&mut [0; 128]),
        Err(PssSignerError::NotForSigning)
    );
    signer.init(&private_key(&KEY1)).unwrap();
    assert_eq!(
        signer.verify_signature(&[0; 128]),
        Err(PssSignerError::NotForVerifying)
    );

    // 引擎拒絕的簽章（大於模數）視為不符。
    let mut verifier = sha1_signer();
    verifier.init(&public_key(&KEY1)).unwrap();
    assert!(!verifier.verify_signature(&[0xff; 128]).unwrap());
}
