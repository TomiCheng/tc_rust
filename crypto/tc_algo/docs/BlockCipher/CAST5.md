# CAST5

The `cast` feature has the rows. A block of 8 bytes and a key of 5 to 16 bytes; also called
CAST-128.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `CAST5/ECB/NOPADDING` | `CAST5/NONE/NOPADDING`, `CAST5//NOPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/ISO10126PADDING` | `CAST5/ECB/ISO10126D2PADDING`, `CAST5/ECB/ISO10126-2PADDING`, `CAST5/NONE/ISO10126PADDING`, `CAST5/NONE/ISO10126D2PADDING`, `CAST5/NONE/ISO10126-2PADDING`, `CAST5//ISO10126PADDING`, `CAST5//ISO10126D2PADDING`, `CAST5//ISO10126-2PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/ISO7816-4PADDING` | `CAST5/ECB/ISO9797-1PADDING`, `CAST5/NONE/ISO7816-4PADDING`, `CAST5/NONE/ISO9797-1PADDING`, `CAST5//ISO7816-4PADDING`, `CAST5//ISO9797-1PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/X923PADDING` | `CAST5/ECB/X9.23PADDING`, `CAST5/NONE/X923PADDING`, `CAST5/NONE/X9.23PADDING`, `CAST5//X923PADDING`, `CAST5//X9.23PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/TBCPADDING` | `CAST5/NONE/TBCPADDING`, `CAST5//TBCPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/ZEROBYTEPADDING` | `CAST5/NONE/ZEROBYTEPADDING`, `CAST5//ZEROBYTEPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/ECB/WITHCTS` | `CAST5/NONE/WITHCTS`, `CAST5//WITHCTS` |  | `KeyOwned` | weak, legacy, variable time |
| `CAST5/CBC/NOPADDING` |  |  | \*P1 | legacy, variable time |
| `CAST5/CBC/PKCS7PADDING` | \*P2 | `1.2.840.113533.7.66.10` | \*P1 | legacy, variable time |
| `CAST5/CBC/ISO10126PADDING` | `CAST5/CBC/ISO10126D2PADDING`, `CAST5/CBC/ISO10126-2PADDING` |  | \*P1 | legacy, variable time |
| `CAST5/CBC/ISO7816-4PADDING` | `CAST5/CBC/ISO9797-1PADDING` |  | \*P1 | legacy, variable time |
| `CAST5/CBC/X923PADDING` | `CAST5/CBC/X9.23PADDING` |  | \*P1 | legacy, variable time |
| `CAST5/CBC/TBCPADDING` |  |  | \*P1 | legacy, variable time |
| `CAST5/CBC/ZEROBYTEPADDING` |  |  | \*P1 | legacy, variable time |
| `CAST5/CBC/WITHCTS` | `CAST5/CTS/NOPADDING`, `CAST5/CTS/RAW`, `CAST5/CTS/`, `CAST5/CTS` |  | \*P1 | legacy, variable time |
| `CAST5/CFB/NOPADDING` | `CAST5/CFB/RAW`, `CAST5/CFB/`, `CAST5/CFB`, `CAST5/CFB{8..64}/NOPADDING`, `CAST5/CFB{8..64}/RAW`, `CAST5/CFB{8..64}/`, `CAST5/CFB{8..64}` |  | \*P1 | legacy, variable time |
| `CAST5/OFB/NOPADDING` | `CAST5/OFB/RAW`, `CAST5/OFB/`, `CAST5/OFB`, `CAST5/OFB{8..64}/NOPADDING`, `CAST5/OFB{8..64}/RAW`, `CAST5/OFB{8..64}/`, `CAST5/OFB{8..64}` |  | \*P1 | legacy, variable time |
| `CAST5/CTR/NOPADDING` | `CAST5/SIC/NOPADDING`, `CAST5/CTR/RAW`, `CAST5/CTR/`, `CAST5/CTR`, `CAST5/SIC/RAW`, `CAST5/SIC/`, `CAST5/SIC` |  | \*P1 | legacy, variable time |
| `CAST5/GOFB/NOPADDING` | `CAST5/GOFB/RAW`, `CAST5/GOFB/`, `CAST5/GOFB` |  | \*P1 | legacy, variable time |
| `CAST5/OPENPGPCFB/NOPADDING` | `CAST5/OPENPGPCFB/RAW`, `CAST5/OPENPGPCFB/`, `CAST5/OPENPGPCFB` |  | \*P1 | legacy, variable time |

The OID is Entrust's, and means CBC with PKCS#7 padding.

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `CAST5`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `CAST5/CBC/PKCS7`, `CAST5/CBC/PKCS5PADDING`, `CAST5/CBC/PKCS5`, `CAST5/CBC/RAW`, `CAST5/CBC/`,
`CAST5/CBC`

P3: `CAST5/ECB/PKCS7`, `CAST5/ECB/PKCS5PADDING`, `CAST5/ECB/PKCS5`, `CAST5/NONE/PKCS7PADDING`,
`CAST5/NONE/PKCS7`, `CAST5/NONE/PKCS5PADDING`, `CAST5/NONE/PKCS5`, `CAST5//PKCS7PADDING`,
`CAST5//PKCS7`, `CAST5//PKCS5PADDING`, `CAST5//PKCS5`, `CAST5/ECB/RAW`, `CAST5/ECB/`, `CAST5/ECB`,
`CAST5/NONE/RAW`, `CAST5/NONE/`, `CAST5/NONE`, `CAST5//RAW`, `CAST5//`, `CAST5/`, `CAST5`
