# SEED

The `seed` feature has the rows. A block of 16 bytes and a key of 16; a Korean standard.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `SEED/ECB/NOPADDING` | `SEED/NONE/NOPADDING`, `SEED//NOPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ISO10126PADDING` | `SEED/ECB/ISO10126D2PADDING`, `SEED/ECB/ISO10126-2PADDING`, `SEED/NONE/ISO10126PADDING`, `SEED/NONE/ISO10126D2PADDING`, `SEED/NONE/ISO10126-2PADDING`, `SEED//ISO10126PADDING`, `SEED//ISO10126D2PADDING`, `SEED//ISO10126-2PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ISO7816-4PADDING` | `SEED/ECB/ISO9797-1PADDING`, `SEED/NONE/ISO7816-4PADDING`, `SEED/NONE/ISO9797-1PADDING`, `SEED//ISO7816-4PADDING`, `SEED//ISO9797-1PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/X923PADDING` | `SEED/ECB/X9.23PADDING`, `SEED/NONE/X923PADDING`, `SEED/NONE/X9.23PADDING`, `SEED//X923PADDING`, `SEED//X9.23PADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/TBCPADDING` | `SEED/NONE/TBCPADDING`, `SEED//TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/ZEROBYTEPADDING` | `SEED/NONE/ZEROBYTEPADDING`, `SEED//ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `SEED/ECB/WITHCTS` | `SEED/NONE/WITHCTS`, `SEED//WITHCTS` |  | `KeyOwned` | weak, variable time |
| `SEED/CBC/NOPADDING` |  |  | \*P1 | variable time |
| `SEED/CBC/PKCS7PADDING` | \*P2 | `1.2.410.200004.1.4` | \*P1 | variable time |
| `SEED/CBC/ISO10126PADDING` | `SEED/CBC/ISO10126D2PADDING`, `SEED/CBC/ISO10126-2PADDING` |  | \*P1 | variable time |
| `SEED/CBC/ISO7816-4PADDING` | `SEED/CBC/ISO9797-1PADDING` |  | \*P1 | variable time |
| `SEED/CBC/X923PADDING` | `SEED/CBC/X9.23PADDING` |  | \*P1 | variable time |
| `SEED/CBC/TBCPADDING` |  |  | \*P1 | variable time |
| `SEED/CBC/ZEROBYTEPADDING` |  |  | \*P1 | variable time |
| `SEED/CBC/WITHCTS` | `SEED/CTS/NOPADDING`, `SEED/CTS/RAW`, `SEED/CTS/`, `SEED/CTS` |  | \*P1 | variable time |
| `SEED/CFB/NOPADDING` | `SEED/CFB/RAW`, `SEED/CFB/`, `SEED/CFB`, `SEED/CFB{8..128}/NOPADDING`, `SEED/CFB{8..128}/RAW`, `SEED/CFB{8..128}/`, `SEED/CFB{8..128}` |  | \*P1 | variable time |
| `SEED/OFB/NOPADDING` | `SEED/OFB/RAW`, `SEED/OFB/`, `SEED/OFB`, `SEED/OFB{8..128}/NOPADDING`, `SEED/OFB{8..128}/RAW`, `SEED/OFB{8..128}/`, `SEED/OFB{8..128}` |  | \*P1 | variable time |
| `SEED/CTR/NOPADDING` | `SEED/SIC/NOPADDING`, `SEED/CTR/RAW`, `SEED/CTR/`, `SEED/CTR`, `SEED/SIC/RAW`, `SEED/SIC/`, `SEED/SIC` |  | \*P1 | variable time |
| `SEED/OPENPGPCFB/NOPADDING` | `SEED/OPENPGPCFB/RAW`, `SEED/OPENPGPCFB/`, `SEED/OPENPGPCFB` |  | \*P1 | variable time |

The OID is KISA's, and means CBC with PKCS#7 padding.

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `SEED`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `SEED/CBC/PKCS7`, `SEED/CBC/PKCS5PADDING`, `SEED/CBC/PKCS5`, `SEED/CBC/RAW`, `SEED/CBC/`,
`SEED/CBC`

P3: `SEED/ECB/PKCS7`, `SEED/ECB/PKCS5PADDING`, `SEED/ECB/PKCS5`, `SEED/NONE/PKCS7PADDING`,
`SEED/NONE/PKCS7`, `SEED/NONE/PKCS5PADDING`, `SEED/NONE/PKCS5`, `SEED//PKCS7PADDING`, `SEED//PKCS7`,
`SEED//PKCS5PADDING`, `SEED//PKCS5`, `SEED/ECB/RAW`, `SEED/ECB/`, `SEED/ECB`, `SEED/NONE/RAW`,
`SEED/NONE/`, `SEED/NONE`, `SEED//RAW`, `SEED//`, `SEED/`, `SEED`
