//! SEC 2 `sect*` 二元曲線的特化欄位具體化。
//!
//! 這些曲線已不建議用於新協定；此模組保留它們是為了既有資料互通與
//! Bouncy Castle 相容性。九種欄位由 K/R 變體共用，點運算則沿用
//! `tc_f2m_curve` 已驗證的四種座標公式。

use alloc::{sync::Arc, vec, vec::Vec};

use tc_bigint::{U256, U384, U1024};
use tc_f2m_curve::{F2mCurve, F2mInteger, F2mPoint, F2mPolynomial};

use crate::{
    SecT113Poly, SecT131Poly, SecT163Poly, SecT193Poly, SecT233Poly, SecT239Poly, SecT283Poly,
    SecT409Poly, SecT571Poly,
};

macro_rules! define_trinomial_curve {
    ($name:ident, $curve:ident, $point:ident, $poly:ty, $integer:ty,
     $m:expr, $k:expr, $a:expr, $b:expr, $order:expr, $cofactor:expr, $base:expr) => {
        pub type $curve = F2mCurve<$poly, $integer>;
        pub type $point = F2mPoint<$poly, $integer>;

        #[doc = concat!("建立 SEC 2 `", stringify!($name), "` 與其基點。")]
        #[must_use]
        pub fn $name() -> (Arc<$curve>, $point) {
            build_trinomial::<$poly, $integer>($m, $k, $a, $b, $order, $cofactor, $base)
        }
    };
}

macro_rules! define_pentanomial_curve {
    ($name:ident, $curve:ident, $point:ident, $poly:ty, $integer:ty,
     $m:expr, $k1:expr, $k2:expr, $k3:expr, $a:expr, $b:expr,
     $order:expr, $cofactor:expr, $base:expr) => {
        pub type $curve = F2mCurve<$poly, $integer>;
        pub type $point = F2mPoint<$poly, $integer>;

        #[doc = concat!("建立 SEC 2 `", stringify!($name), "` 與其基點。")]
        #[must_use]
        pub fn $name() -> (Arc<$curve>, $point) {
            build_pentanomial::<$poly, $integer>(
                $m, $k1, $k2, $k3, $a, $b, $order, $cofactor, $base,
            )
        }
    };
}

define_trinomial_curve!(
    sect113r1,
    SecT113R1Curve,
    SecT113R1Point,
    SecT113Poly,
    U256,
    113,
    9,
    "003088250CA6E7C7FE649CE85820F7",
    "00E8BEE4D3E2260744188BE0E9C723",
    "0100000000000000D9CCEC8A39E56F",
    2,
    "04009D73616F35F4AB1407D73562C10F00A52830277958EE84D1315ED31886"
);
define_trinomial_curve!(
    sect113r2,
    SecT113R2Curve,
    SecT113R2Point,
    SecT113Poly,
    U256,
    113,
    9,
    "00689918DBEC7E5A0DD6DFC0AA55C7",
    "0095E9A9EC9B297BD4BF36E059184F",
    "010000000000000108789B2496AF93",
    2,
    "0401A57A6A7B26CA5EF52FCDB816479700B3ADC94ED1FE674C06E695BABA1D"
);
define_pentanomial_curve!(
    sect131r1,
    SecT131R1Curve,
    SecT131R1Point,
    SecT131Poly,
    U256,
    131,
    2,
    3,
    8,
    "07A11B09A76B562144418FF3FF8C2570B8",
    "0217C05610884B63B9C6C7291678F9D341",
    "0400000000000000023123953A9464B54D",
    2,
    "040081BAF91FDF9833C40F9C181343638399078C6E7EA38C001F73C8134B1B4EF9E150"
);
define_pentanomial_curve!(
    sect131r2,
    SecT131R2Curve,
    SecT131R2Point,
    SecT131Poly,
    U256,
    131,
    2,
    3,
    8,
    "03E5A88919D7CAFCBF415F07C2176573B2",
    "04B8266A46C55657AC734CE38F018F2192",
    "0400000000000000016954A233049BA98F",
    2,
    "040356DCD8F2F95031AD652D23951BB366A80648F06D867940A5366D9E265DE9EB240F"
);
define_pentanomial_curve!(
    sect163k1,
    SecT163K1Curve,
    SecT163K1Point,
    SecT163Poly,
    U256,
    163,
    3,
    6,
    7,
    "1",
    "1",
    "04000000000000000000020108A2E0CC0D99F8A5EF",
    2,
    "0402FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE80289070FB05D38FF58321F2E800536D538CCDAA3D9"
);
define_pentanomial_curve!(
    sect163r1,
    SecT163R1Curve,
    SecT163R1Point,
    SecT163Poly,
    U256,
    163,
    3,
    6,
    7,
    "07B6882CAAEFA84F9554FF8428BD88E246D2782AE2",
    "0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9",
    "03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B",
    2,
    "040369979697AB43897789566789567F787A7876A65400435EDB42EFAFB2989D51FEFCE3C80988F41FF883"
);
define_pentanomial_curve!(
    sect163r2,
    SecT163R2Curve,
    SecT163R2Point,
    SecT163Poly,
    U256,
    163,
    3,
    6,
    7,
    "1",
    "020A601907B8C953CA1481EB10512F78744A3205FD",
    "040000000000000000000292FE77E70C12A4234C33",
    2,
    "0403F0EBA16286A2D57EA0991168D4994637E8343E3600D51FBC6C71A0094FA2CDD545B11C5C0C797324F1"
);
define_trinomial_curve!(
    sect193r1,
    SecT193R1Curve,
    SecT193R1Point,
    SecT193Poly,
    U256,
    193,
    15,
    "0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01",
    "00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814",
    "01000000000000000000000000C7F34A778F443ACC920EBA49",
    2,
    "0401F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E10025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05"
);
define_trinomial_curve!(
    sect193r2,
    SecT193R2Curve,
    SecT193R2Point,
    SecT193Poly,
    U256,
    193,
    15,
    "0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B",
    "00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE",
    "010000000000000000000000015AAB561B005413CCD4EE99D5",
    2,
    "0400D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C"
);
define_trinomial_curve!(
    sect233k1,
    SecT233K1Curve,
    SecT233K1Point,
    SecT233Poly,
    U256,
    233,
    74,
    "0",
    "1",
    "8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF",
    4,
    "04017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD612601DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3"
);
define_trinomial_curve!(
    sect233r1,
    SecT233R1Curve,
    SecT233R1Point,
    SecT233Poly,
    U256,
    233,
    74,
    "1",
    "0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD",
    "01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
    2,
    "0400FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052"
);
define_trinomial_curve!(
    sect239k1,
    SecT239K1Curve,
    SecT239K1Point,
    SecT239Poly,
    U256,
    239,
    158,
    "0",
    "1",
    "2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5",
    4,
    "0429A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA"
);
define_pentanomial_curve!(
    sect283k1,
    SecT283K1Curve,
    SecT283K1Point,
    SecT283Poly,
    U384,
    283,
    5,
    7,
    12,
    "0",
    "1",
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61",
    4,
    "040503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC245849283601CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259"
);
define_pentanomial_curve!(
    sect283r1,
    SecT283R1Curve,
    SecT283R1Point,
    SecT283Poly,
    U384,
    283,
    5,
    7,
    12,
    "1",
    "027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5",
    "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307",
    2,
    "0405F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B1205303676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4"
);
define_trinomial_curve!(
    sect409k1,
    SecT409K1Curve,
    SecT409K1Point,
    SecT409Poly,
    U1024,
    409,
    87,
    "0",
    "1",
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF",
    4,
    "040060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE902374601E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B"
);
define_trinomial_curve!(
    sect409r1,
    SecT409R1Curve,
    SecT409R1Point,
    SecT409Poly,
    U1024,
    409,
    87,
    "1",
    "0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F",
    "010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173",
    2,
    "04015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A70061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706"
);
define_pentanomial_curve!(
    sect571k1,
    SecT571K1Curve,
    SecT571K1Point,
    SecT571Poly,
    U1024,
    571,
    2,
    5,
    10,
    "0",
    "1",
    "020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001",
    4,
    "04026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C89720349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3"
);
define_pentanomial_curve!(
    sect571r1,
    SecT571R1Curve,
    SecT571R1Point,
    SecT571Poly,
    U1024,
    571,
    2,
    5,
    10,
    "1",
    "02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A",
    "03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47",
    2,
    "040303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B"
);

#[allow(clippy::too_many_arguments)]
fn build_trinomial<P: F2mPolynomial, B: F2mInteger>(
    m: usize,
    k: usize,
    a: &str,
    b: &str,
    order: &str,
    cofactor: u8,
    base: &str,
) -> (Arc<F2mCurve<P, B>>, F2mPoint<P, B>) {
    let curve = Arc::new(
        F2mCurve::trinomial(
            m,
            k,
            hex_integer(a),
            hex_integer(b),
            Some(hex_integer(order)),
            Some(small_integer(cofactor)),
        )
        .expect("SEC trinomial parameters are valid"),
    );
    let point = curve
        .decode_point(&hex_bytes(base))
        .expect("SEC base point is valid");
    (curve, point)
}

#[allow(clippy::too_many_arguments)]
fn build_pentanomial<P: F2mPolynomial, B: F2mInteger>(
    m: usize,
    k1: usize,
    k2: usize,
    k3: usize,
    a: &str,
    b: &str,
    order: &str,
    cofactor: u8,
    base: &str,
) -> (Arc<F2mCurve<P, B>>, F2mPoint<P, B>) {
    let curve = Arc::new(
        F2mCurve::pentanomial(
            m,
            k1,
            k2,
            k3,
            hex_integer(a),
            hex_integer(b),
            Some(hex_integer(order)),
            Some(small_integer(cofactor)),
        )
        .expect("SEC pentanomial parameters are valid"),
    );
    let point = curve
        .decode_point(&hex_bytes(base))
        .expect("SEC base point is valid");
    (curve, point)
}

fn hex_integer<B: F2mInteger>(value: &str) -> B {
    B::from_unsigned_be_bytes(&hex_bytes(value))
        .unwrap_or_else(|_| panic!("SEC constant does not fit the selected integer type"))
}

fn small_integer<B: F2mInteger>(value: u8) -> B {
    B::from_unsigned_be_bytes(&[value])
        .unwrap_or_else(|_| panic!("small SEC constant fits the selected integer type"))
}

fn hex_bytes(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut output = vec![0_u8; bytes.len().div_ceil(2)];
    let mut source = 0;
    let mut target = 0;
    if bytes.len() & 1 != 0 {
        output[0] = hex_digit(bytes[0]);
        source = 1;
        target = 1;
    }
    while source < bytes.len() {
        output[target] = hex_digit(bytes[source]) << 4 | hex_digit(bytes[source + 1]);
        source += 2;
        target += 1;
    }
    output
}

fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("SEC constant is valid hexadecimal"),
    }
}
