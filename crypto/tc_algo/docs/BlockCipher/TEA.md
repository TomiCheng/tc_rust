# TEA

The `misc-block-cipher` feature has the rows. A block of 8 bytes and a key of 16 bytes.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `TEA/ECB/NOPADDING` | `TEA/NONE/NOPADDING`, `TEA//NOPADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/ISO10126PADDING` | `TEA/ECB/ISO10126D2PADDING`, `TEA/ECB/ISO10126-2PADDING`, `TEA/NONE/ISO10126PADDING`, `TEA/NONE/ISO10126D2PADDING`, `TEA/NONE/ISO10126-2PADDING`, `TEA//ISO10126PADDING`, `TEA//ISO10126D2PADDING`, `TEA//ISO10126-2PADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/ISO7816-4PADDING` | `TEA/ECB/ISO9797-1PADDING`, `TEA/NONE/ISO7816-4PADDING`, `TEA/NONE/ISO9797-1PADDING`, `TEA//ISO7816-4PADDING`, `TEA//ISO9797-1PADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/X923PADDING` | `TEA/ECB/X9.23PADDING`, `TEA/NONE/X923PADDING`, `TEA/NONE/X9.23PADDING`, `TEA//X923PADDING`, `TEA//X9.23PADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/TBCPADDING` | `TEA/NONE/TBCPADDING`, `TEA//TBCPADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/ZEROBYTEPADDING` | `TEA/NONE/ZEROBYTEPADDING`, `TEA//ZEROBYTEPADDING` |  | `KeyOwned` | weak, legacy |
| `TEA/ECB/WITHCTS` | `TEA/NONE/WITHCTS`, `TEA//WITHCTS` |  | `KeyOwned` | weak, legacy |
| `TEA/CBC/NOPADDING` |  |  | \*P1 | legacy |
| `TEA/CBC/PKCS7PADDING` | \*P2 |  | \*P1 | legacy |
| `TEA/CBC/ISO10126PADDING` | `TEA/CBC/ISO10126D2PADDING`, `TEA/CBC/ISO10126-2PADDING` |  | \*P1 | legacy |
| `TEA/CBC/ISO7816-4PADDING` | `TEA/CBC/ISO9797-1PADDING` |  | \*P1 | legacy |
| `TEA/CBC/X923PADDING` | `TEA/CBC/X9.23PADDING` |  | \*P1 | legacy |
| `TEA/CBC/TBCPADDING` |  |  | \*P1 | legacy |
| `TEA/CBC/ZEROBYTEPADDING` |  |  | \*P1 | legacy |
| `TEA/CBC/WITHCTS` | `TEA/CTS/NOPADDING`, `TEA/CTS/RAW`, `TEA/CTS/`, `TEA/CTS` |  | \*P1 | legacy |
| `TEA/CFB/NOPADDING` | `TEA/CFB/RAW`, `TEA/CFB/`, `TEA/CFB`, `TEA/CFB{8..64}/NOPADDING`, `TEA/CFB{8..64}/RAW`, `TEA/CFB{8..64}/`, `TEA/CFB{8..64}` |  | \*P1 | legacy |
| `TEA/OFB/NOPADDING` | `TEA/OFB/RAW`, `TEA/OFB/`, `TEA/OFB`, `TEA/OFB{8..64}/NOPADDING`, `TEA/OFB{8..64}/RAW`, `TEA/OFB{8..64}/`, `TEA/OFB{8..64}` |  | \*P1 | legacy |
| `TEA/CTR/NOPADDING` | `TEA/SIC/NOPADDING`, `TEA/CTR/RAW`, `TEA/CTR/`, `TEA/CTR`, `TEA/SIC/RAW`, `TEA/SIC/`, `TEA/SIC` |  | \*P1 | legacy |
| `TEA/GOFB/NOPADDING` | `TEA/GOFB/RAW`, `TEA/GOFB/`, `TEA/GOFB` |  | \*P1 | legacy |
| `TEA/OPENPGPCFB/NOPADDING` | `TEA/OPENPGPCFB/RAW`, `TEA/OPENPGPCFB/`, `TEA/OPENPGPCFB` |  | \*P1 | legacy |

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `TEA`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `TEA/CBC/PKCS7`, `TEA/CBC/PKCS5PADDING`, `TEA/CBC/PKCS5`, `TEA/CBC/RAW`, `TEA/CBC/`, `TEA/CBC`

P3: `TEA/ECB/PKCS7`, `TEA/ECB/PKCS5PADDING`, `TEA/ECB/PKCS5`, `TEA/NONE/PKCS7PADDING`,
`TEA/NONE/PKCS7`, `TEA/NONE/PKCS5PADDING`, `TEA/NONE/PKCS5`, `TEA//PKCS7PADDING`, `TEA//PKCS7`,
`TEA//PKCS5PADDING`, `TEA//PKCS5`, `TEA/ECB/RAW`, `TEA/ECB/`, `TEA/ECB`, `TEA/NONE/RAW`,
`TEA/NONE/`, `TEA/NONE`, `TEA//RAW`, `TEA//`, `TEA/`, `TEA`
