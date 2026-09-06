//! SEC `sect*` 曲線共用的九個二元體定義。

use tc_f2m_curve::F2mFieldElement;

use crate::{BinaryFieldSpec, SpecializedBinaryField, SpecializedBinaryPoly};

macro_rules! define_field {
    ($spec:ident, $field:ident, $poly:ident, $element:ident, $n:expr, $m:expr, $k1:expr, $k2:expr, $k3:expr, $root_z:expr) => {
        #[doc(hidden)]
        pub enum $spec {}

        impl BinaryFieldSpec<$n> for $spec {
            const M: usize = $m;
            const K1: usize = $k1;
            const K2: usize = $k2;
            const K3: usize = $k3;
            const ROOT_Z: [u64; $n] = $root_z;
        }

        pub type $field = SpecializedBinaryField<$spec, $n>;
        pub type $poly = SpecializedBinaryPoly<$spec, $n>;
        pub type $element = F2mFieldElement<$poly>;
    };
}

define_field!(
    SecT113Spec,
    SecT113Field,
    SecT113Poly,
    SecT113FieldElement,
    2,
    113,
    9,
    0,
    0,
    [0x0200_0000_0000_0020, 0]
);
define_field!(
    SecT131Spec,
    SecT131Field,
    SecT131Poly,
    SecT131FieldElement,
    3,
    131,
    2,
    3,
    8,
    [0x26BC_4D78_9AF1_3523, 0x26BC_4D78_9AF1_35E2, 0x6]
);
define_field!(
    SecT163Spec,
    SecT163Field,
    SecT163Poly,
    SecT163FieldElement,
    3,
    163,
    3,
    6,
    7,
    [
        0xB6DB_6DB6_DB6D_B6B0,
        0x4924_9249_2492_DB6D,
        0x0000_0004_9249_2492
    ]
);
define_field!(
    SecT193Spec,
    SecT193Field,
    SecT193Poly,
    SecT193FieldElement,
    4,
    193,
    15,
    0,
    0,
    [0x100, 0x0000_0002_0000_0000, 0, 0]
);
define_field!(
    SecT233Spec,
    SecT233Field,
    SecT233Poly,
    SecT233FieldElement,
    4,
    233,
    74,
    0,
    0,
    [
        0x0000_0001_0000_0000,
        0x0020_0000_0000_0020,
        0x8000_0000_0400_0000,
        0x0000_0010_0000_0000
    ]
);
define_field!(
    SecT239Spec,
    SecT239Field,
    SecT239Poly,
    SecT239FieldElement,
    4,
    239,
    158,
    0,
    0,
    [0x0000_0080_0000_0000, 0x0140_0000_0000_0000, 0, 0x80]
);
define_field!(
    SecT283Spec,
    SecT283Field,
    SecT283Poly,
    SecT283FieldElement,
    5,
    283,
    5,
    7,
    12,
    [
        0x0C30_C30C_30C3_0808,
        0x30C3_0C30_C30C_30C3,
        0x8208_2082_0820_830C,
        0x0820_8208_2082_0820,
        0x0000_0000_0208_2082
    ]
);
define_field!(
    SecT409Spec,
    SecT409Field,
    SecT409Poly,
    SecT409FieldElement,
    7,
    409,
    87,
    0,
    0,
    [0x0000_1000_0000_0000, 0, 0, 0x2000, 0, 0, 0]
);
define_field!(
    SecT571Spec,
    SecT571Field,
    SecT571Poly,
    SecT571FieldElement,
    9,
    571,
    2,
    5,
    10,
    [
        0x2BE1_195F_08CA_FB99,
        0x95F0_8CAF_8465_7C23,
        0xCAF8_4657_C232_BE11,
        0x657C_232B_E119_5F08,
        0xF846_57C2_308C_AF84,
        0x7C23_2BE1_195F_08CA,
        0xBE11_95F0_8CAF_8465,
        0x5F08_CAF8_4657_C232,
        0x0784_657C_232B_E119
    ]
);
