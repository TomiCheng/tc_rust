# RC2

The `rc-cipher` feature has the rows. A block of 8 bytes and a key of 1 to 128 bytes. As in Bouncy Castle,
a plain key gives an effective key size of the whole key, and RC2's own params give another; see
[RC2](../Rc2.md).

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `RC2/ECB/NOPADDING` | `RC2/NONE/NOPADDING`, `RC2//NOPADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/PKCS7PADDING` | `RC2/ECB/PKCS7`, `RC2/ECB/PKCS5PADDING`, `RC2/ECB/PKCS5`, `RC2/NONE/PKCS7PADDING`, `RC2/NONE/PKCS7`, `RC2/NONE/PKCS5PADDING`, `RC2/NONE/PKCS5`, `RC2//PKCS7PADDING`, `RC2//PKCS7`, `RC2//PKCS5PADDING`, `RC2//PKCS5`, `RC2/ECB/RAW`, `RC2/ECB/`, `RC2/ECB`, `RC2/NONE/RAW`, `RC2/NONE/`, `RC2/NONE`, `RC2//RAW`, `RC2//`, `RC2/`, `RC2` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/ISO10126PADDING` | `RC2/ECB/ISO10126D2PADDING`, `RC2/ECB/ISO10126-2PADDING`, `RC2/NONE/ISO10126PADDING`, `RC2/NONE/ISO10126D2PADDING`, `RC2/NONE/ISO10126-2PADDING`, `RC2//ISO10126PADDING`, `RC2//ISO10126D2PADDING`, `RC2//ISO10126-2PADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/ISO7816-4PADDING` | `RC2/ECB/ISO9797-1PADDING`, `RC2/NONE/ISO7816-4PADDING`, `RC2/NONE/ISO9797-1PADDING`, `RC2//ISO7816-4PADDING`, `RC2//ISO9797-1PADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/X923PADDING` | `RC2/ECB/X9.23PADDING`, `RC2/NONE/X923PADDING`, `RC2/NONE/X9.23PADDING`, `RC2//X923PADDING`, `RC2//X9.23PADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/TBCPADDING` | `RC2/NONE/TBCPADDING`, `RC2//TBCPADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/ZEROBYTEPADDING` | `RC2/NONE/ZEROBYTEPADDING`, `RC2//ZEROBYTEPADDING` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/ECB/WITHCTS` | `RC2/NONE/WITHCTS`, `RC2//WITHCTS` |  | `KeyOwned`, [`Rc2ParamsOwned`](../Rc2.md) | weak, legacy, variable time |
| `RC2/CBC/NOPADDING` |  |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/PKCS7PADDING` | `RC2/CBC/PKCS7`, `RC2/CBC/PKCS5PADDING`, `RC2/CBC/PKCS5`, `RC2/CBC/RAW`, `RC2/CBC/`, `RC2/CBC`, `PBEWITHSHA1ANDRC2-CBC`, `PBEWITHSHA1ANDRC2`, `PBEWITHSHAAND128BITRC2-CBC`, `PBEWITHSHA1AND128BITRC2-CBC`, `PBEWITHSHAAND40BITRC2-CBC`, `PBEWITHSHA1AND40BITRC2-CBC` | `1.2.840.113549.3.2`, `1.2.840.113549.1.5.11`, `1.2.840.113549.1.12.1.5`, `1.2.840.113549.1.12.1.6` | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/ISO10126PADDING` | `RC2/CBC/ISO10126D2PADDING`, `RC2/CBC/ISO10126-2PADDING` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/ISO7816-4PADDING` | `RC2/CBC/ISO9797-1PADDING` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/X923PADDING` | `RC2/CBC/X9.23PADDING` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/TBCPADDING` |  |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/ZEROBYTEPADDING` |  |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CBC/WITHCTS` | `RC2/CTS/NOPADDING`, `RC2/CTS/RAW`, `RC2/CTS/`, `RC2/CTS` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CFB/NOPADDING` | `RC2/CFB/RAW`, `RC2/CFB/`, `RC2/CFB`, `RC2/CFB{8..64}/NOPADDING`, `RC2/CFB{8..64}/RAW`, `RC2/CFB{8..64}/`, `RC2/CFB{8..64}` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/OFB/NOPADDING` | `RC2/OFB/RAW`, `RC2/OFB/`, `RC2/OFB`, `RC2/OFB{8..64}/NOPADDING`, `RC2/OFB{8..64}/RAW`, `RC2/OFB{8..64}/`, `RC2/OFB{8..64}` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/CTR/NOPADDING` | `RC2/SIC/NOPADDING`, `RC2/CTR/RAW`, `RC2/CTR/`, `RC2/CTR`, `RC2/SIC/RAW`, `RC2/SIC/`, `RC2/SIC` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/GOFB/NOPADDING` | `RC2/GOFB/RAW`, `RC2/GOFB/`, `RC2/GOFB` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |
| `RC2/OPENPGPCFB/NOPADDING` | `RC2/OPENPGPCFB/RAW`, `RC2/OPENPGPCFB/`, `RC2/OPENPGPCFB` |  | `KeyWithIvOwned`, [`ParamsWithIvOwned<Rc2ParamsOwned>`](../Rc2.md) | legacy, variable time |

The OID is RSA's, and means CBC with PKCS#7 padding. Its parameters in a certificate or CMS can name
another effective key size, which these rows take in a `ParamsWithIvOwned<Rc2ParamsOwned>`; see
[RC2](../Rc2.md#the-effective-key-size-in-cms).
