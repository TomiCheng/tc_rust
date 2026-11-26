# CAST6

The `cast` feature has the rows. A block of 16 bytes and a key of 16 to 32 bytes, in steps of 4;
also called CAST-256.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `CAST6/ECB/NOPADDING` | `CAST6/NONE/NOPADDING`, `CAST6//NOPADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/ISO10126PADDING` | `CAST6/ECB/ISO10126D2PADDING`, `CAST6/ECB/ISO10126-2PADDING`, `CAST6/NONE/ISO10126PADDING`, `CAST6/NONE/ISO10126D2PADDING`, `CAST6/NONE/ISO10126-2PADDING`, `CAST6//ISO10126PADDING`, `CAST6//ISO10126D2PADDING`, `CAST6//ISO10126-2PADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/ISO7816-4PADDING` | `CAST6/ECB/ISO9797-1PADDING`, `CAST6/NONE/ISO7816-4PADDING`, `CAST6/NONE/ISO9797-1PADDING`, `CAST6//ISO7816-4PADDING`, `CAST6//ISO9797-1PADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/X923PADDING` | `CAST6/ECB/X9.23PADDING`, `CAST6/NONE/X923PADDING`, `CAST6/NONE/X9.23PADDING`, `CAST6//X923PADDING`, `CAST6//X9.23PADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/TBCPADDING` | `CAST6/NONE/TBCPADDING`, `CAST6//TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/ZEROBYTEPADDING` | `CAST6/NONE/ZEROBYTEPADDING`, `CAST6//ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `CAST6/ECB/WITHCTS` | `CAST6/NONE/WITHCTS`, `CAST6//WITHCTS` |  | `KeyOwned` | weak, variable time |
| `CAST6/CBC/NOPADDING` |  |  | \*P1 | variable time |
| `CAST6/CBC/PKCS7PADDING` | \*P2 |  | \*P1 | variable time |
| `CAST6/CBC/ISO10126PADDING` | `CAST6/CBC/ISO10126D2PADDING`, `CAST6/CBC/ISO10126-2PADDING` |  | \*P1 | variable time |
| `CAST6/CBC/ISO7816-4PADDING` | `CAST6/CBC/ISO9797-1PADDING` |  | \*P1 | variable time |
| `CAST6/CBC/X923PADDING` | `CAST6/CBC/X9.23PADDING` |  | \*P1 | variable time |
| `CAST6/CBC/TBCPADDING` |  |  | \*P1 | variable time |
| `CAST6/CBC/ZEROBYTEPADDING` |  |  | \*P1 | variable time |
| `CAST6/CBC/WITHCTS` | `CAST6/CTS/NOPADDING`, `CAST6/CTS/RAW`, `CAST6/CTS/`, `CAST6/CTS` |  | \*P1 | variable time |
| `CAST6/CFB/NOPADDING` | `CAST6/CFB/RAW`, `CAST6/CFB/`, `CAST6/CFB`, `CAST6/CFB{8..128}/NOPADDING`, `CAST6/CFB{8..128}/RAW`, `CAST6/CFB{8..128}/`, `CAST6/CFB{8..128}` |  | \*P1 | variable time |
| `CAST6/OFB/NOPADDING` | `CAST6/OFB/RAW`, `CAST6/OFB/`, `CAST6/OFB`, `CAST6/OFB{8..128}/NOPADDING`, `CAST6/OFB{8..128}/RAW`, `CAST6/OFB{8..128}/`, `CAST6/OFB{8..128}` |  | \*P1 | variable time |
| `CAST6/CTR/NOPADDING` | `CAST6/SIC/NOPADDING`, `CAST6/CTR/RAW`, `CAST6/CTR/`, `CAST6/CTR`, `CAST6/SIC/RAW`, `CAST6/SIC/`, `CAST6/SIC` |  | \*P1 | variable time |
| `CAST6/OPENPGPCFB/NOPADDING` | `CAST6/OPENPGPCFB/RAW`, `CAST6/OPENPGPCFB/`, `CAST6/OPENPGPCFB` |  | \*P1 | variable time |

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `CAST6`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `CAST6/CBC/PKCS7`, `CAST6/CBC/PKCS5PADDING`, `CAST6/CBC/PKCS5`, `CAST6/CBC/RAW`, `CAST6/CBC/`,
`CAST6/CBC`

P3: `CAST6/ECB/PKCS7`, `CAST6/ECB/PKCS5PADDING`, `CAST6/ECB/PKCS5`, `CAST6/NONE/PKCS7PADDING`,
`CAST6/NONE/PKCS7`, `CAST6/NONE/PKCS5PADDING`, `CAST6/NONE/PKCS5`, `CAST6//PKCS7PADDING`,
`CAST6//PKCS7`, `CAST6//PKCS5PADDING`, `CAST6//PKCS5`, `CAST6/ECB/RAW`, `CAST6/ECB/`, `CAST6/ECB`,
`CAST6/NONE/RAW`, `CAST6/NONE/`, `CAST6/NONE`, `CAST6//RAW`, `CAST6//`, `CAST6/`, `CAST6`
