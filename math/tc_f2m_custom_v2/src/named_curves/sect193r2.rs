use super::SecTNamedCurve;
use super::hex::hex;
use crate::SecT193FieldElement;
use core::marker::PhantomData;

/// SEC 2 sect193r2.
pub const SECT193R2: SecTNamedCurve<SecT193FieldElement, 25> = SecTNamedCurve {
    a: hex("0163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b"),
    b: hex("00c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae"),
    order: hex("010000000000000000000000015aab561b005413ccd4ee99d5"),
    cofactor: 2,
    gx: hex("00d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"),
    gy: hex("01ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c"),
    field: PhantomData,
};
