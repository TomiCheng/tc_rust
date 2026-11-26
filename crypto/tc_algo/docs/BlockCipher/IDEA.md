# IDEA

The `misc-block-cipher` feature has the rows. A block of 8 bytes and a key of 16 bytes.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `IDEA/ECB/NOPADDING` | `IDEA/NONE/NOPADDING`, `IDEA//NOPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/ISO10126PADDING` | `IDEA/ECB/ISO10126D2PADDING`, `IDEA/ECB/ISO10126-2PADDING`, `IDEA/NONE/ISO10126PADDING`, `IDEA/NONE/ISO10126D2PADDING`, `IDEA/NONE/ISO10126-2PADDING`, `IDEA//ISO10126PADDING`, `IDEA//ISO10126D2PADDING`, `IDEA//ISO10126-2PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/ISO7816-4PADDING` | `IDEA/ECB/ISO9797-1PADDING`, `IDEA/NONE/ISO7816-4PADDING`, `IDEA/NONE/ISO9797-1PADDING`, `IDEA//ISO7816-4PADDING`, `IDEA//ISO9797-1PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/X923PADDING` | `IDEA/ECB/X9.23PADDING`, `IDEA/NONE/X923PADDING`, `IDEA/NONE/X9.23PADDING`, `IDEA//X923PADDING`, `IDEA//X9.23PADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/TBCPADDING` | `IDEA/NONE/TBCPADDING`, `IDEA//TBCPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/ZEROBYTEPADDING` | `IDEA/NONE/ZEROBYTEPADDING`, `IDEA//ZEROBYTEPADDING` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/ECB/WITHCTS` | `IDEA/NONE/WITHCTS`, `IDEA//WITHCTS` |  | `KeyOwned` | weak, legacy, variable time |
| `IDEA/CBC/NOPADDING` |  |  | \*P1 | legacy, variable time |
| `IDEA/CBC/PKCS7PADDING` | \*P2 | `1.3.6.1.4.1.188.7.1.1.2` | \*P1 | legacy, variable time |
| `IDEA/CBC/ISO10126PADDING` | `IDEA/CBC/ISO10126D2PADDING`, `IDEA/CBC/ISO10126-2PADDING` |  | \*P1 | legacy, variable time |
| `IDEA/CBC/ISO7816-4PADDING` | `IDEA/CBC/ISO9797-1PADDING` |  | \*P1 | legacy, variable time |
| `IDEA/CBC/X923PADDING` | `IDEA/CBC/X9.23PADDING` |  | \*P1 | legacy, variable time |
| `IDEA/CBC/TBCPADDING` |  |  | \*P1 | legacy, variable time |
| `IDEA/CBC/ZEROBYTEPADDING` |  |  | \*P1 | legacy, variable time |
| `IDEA/CBC/WITHCTS` | `IDEA/CTS/NOPADDING`, `IDEA/CTS/RAW`, `IDEA/CTS/`, `IDEA/CTS` |  | \*P1 | legacy, variable time |
| `IDEA/CFB/NOPADDING` | `IDEA/CFB/RAW`, `IDEA/CFB/`, `IDEA/CFB`, `IDEA/CFB{8..64}/NOPADDING`, `IDEA/CFB{8..64}/RAW`, `IDEA/CFB{8..64}/`, `IDEA/CFB{8..64}` |  | \*P1 | legacy, variable time |
| `IDEA/OFB/NOPADDING` | `IDEA/OFB/RAW`, `IDEA/OFB/`, `IDEA/OFB`, `IDEA/OFB{8..64}/NOPADDING`, `IDEA/OFB{8..64}/RAW`, `IDEA/OFB{8..64}/`, `IDEA/OFB{8..64}` |  | \*P1 | legacy, variable time |
| `IDEA/CTR/NOPADDING` | `IDEA/SIC/NOPADDING`, `IDEA/CTR/RAW`, `IDEA/CTR/`, `IDEA/CTR`, `IDEA/SIC/RAW`, `IDEA/SIC/`, `IDEA/SIC` |  | \*P1 | legacy, variable time |
| `IDEA/GOFB/NOPADDING` | `IDEA/GOFB/RAW`, `IDEA/GOFB/`, `IDEA/GOFB` |  | \*P1 | legacy, variable time |
| `IDEA/OPENPGPCFB/NOPADDING` | `IDEA/OPENPGPCFB/RAW`, `IDEA/OPENPGPCFB/`, `IDEA/OPENPGPCFB` |  | \*P1 | legacy, variable time |

The OID is Ascom's, and means CBC with PKCS#7 padding.

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `IDEA`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `IDEA/CBC/PKCS7`, `IDEA/CBC/PKCS5PADDING`, `IDEA/CBC/PKCS5`, `IDEA/CBC/RAW`, `IDEA/CBC/`,
`IDEA/CBC`

P3: `IDEA/ECB/PKCS7`, `IDEA/ECB/PKCS5PADDING`, `IDEA/ECB/PKCS5`, `IDEA/NONE/PKCS7PADDING`,
`IDEA/NONE/PKCS7`, `IDEA/NONE/PKCS5PADDING`, `IDEA/NONE/PKCS5`, `IDEA//PKCS7PADDING`, `IDEA//PKCS7`,
`IDEA//PKCS5PADDING`, `IDEA//PKCS5`, `IDEA/ECB/RAW`, `IDEA/ECB/`, `IDEA/ECB`, `IDEA/NONE/RAW`,
`IDEA/NONE/`, `IDEA/NONE`, `IDEA//RAW`, `IDEA//`, `IDEA/`, `IDEA`
