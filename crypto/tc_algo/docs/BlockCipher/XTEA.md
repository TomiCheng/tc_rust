# XTEA

The `misc-block-cipher` feature has the rows. A block of 8 bytes and a key of 16 bytes; TEA with its
key schedule
repaired. Bouncy Castle has it as an engine, not in its CipherUtilities.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `XTEA/ECB/NOPADDING` | `XTEA/NONE/NOPADDING`, `XTEA//NOPADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/PKCS7PADDING` | \*P3 |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/ISO10126PADDING` | `XTEA/ECB/ISO10126D2PADDING`, `XTEA/ECB/ISO10126-2PADDING`, `XTEA/NONE/ISO10126PADDING`, `XTEA/NONE/ISO10126D2PADDING`, `XTEA/NONE/ISO10126-2PADDING`, `XTEA//ISO10126PADDING`, `XTEA//ISO10126D2PADDING`, `XTEA//ISO10126-2PADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/ISO7816-4PADDING` | `XTEA/ECB/ISO9797-1PADDING`, `XTEA/NONE/ISO7816-4PADDING`, `XTEA/NONE/ISO9797-1PADDING`, `XTEA//ISO7816-4PADDING`, `XTEA//ISO9797-1PADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/X923PADDING` | `XTEA/ECB/X9.23PADDING`, `XTEA/NONE/X923PADDING`, `XTEA/NONE/X9.23PADDING`, `XTEA//X923PADDING`, `XTEA//X9.23PADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/TBCPADDING` | `XTEA/NONE/TBCPADDING`, `XTEA//TBCPADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/ZEROBYTEPADDING` | `XTEA/NONE/ZEROBYTEPADDING`, `XTEA//ZEROBYTEPADDING` |  | `KeyOwned` | weak, legacy |
| `XTEA/ECB/WITHCTS` | `XTEA/NONE/WITHCTS`, `XTEA//WITHCTS` |  | `KeyOwned` | weak, legacy |
| `XTEA/CBC/NOPADDING` |  |  | \*P1 | legacy |
| `XTEA/CBC/PKCS7PADDING` | \*P2 |  | \*P1 | legacy |
| `XTEA/CBC/ISO10126PADDING` | `XTEA/CBC/ISO10126D2PADDING`, `XTEA/CBC/ISO10126-2PADDING` |  | \*P1 | legacy |
| `XTEA/CBC/ISO7816-4PADDING` | `XTEA/CBC/ISO9797-1PADDING` |  | \*P1 | legacy |
| `XTEA/CBC/X923PADDING` | `XTEA/CBC/X9.23PADDING` |  | \*P1 | legacy |
| `XTEA/CBC/TBCPADDING` |  |  | \*P1 | legacy |
| `XTEA/CBC/ZEROBYTEPADDING` |  |  | \*P1 | legacy |
| `XTEA/CBC/WITHCTS` | `XTEA/CTS/NOPADDING`, `XTEA/CTS/RAW`, `XTEA/CTS/`, `XTEA/CTS` |  | \*P1 | legacy |
| `XTEA/CFB/NOPADDING` | `XTEA/CFB/RAW`, `XTEA/CFB/`, `XTEA/CFB`, `XTEA/CFB{8..64}/NOPADDING`, `XTEA/CFB{8..64}/RAW`, `XTEA/CFB{8..64}/`, `XTEA/CFB{8..64}` |  | \*P1 | legacy |
| `XTEA/OFB/NOPADDING` | `XTEA/OFB/RAW`, `XTEA/OFB/`, `XTEA/OFB`, `XTEA/OFB{8..64}/NOPADDING`, `XTEA/OFB{8..64}/RAW`, `XTEA/OFB{8..64}/`, `XTEA/OFB{8..64}` |  | \*P1 | legacy |
| `XTEA/CTR/NOPADDING` | `XTEA/SIC/NOPADDING`, `XTEA/CTR/RAW`, `XTEA/CTR/`, `XTEA/CTR`, `XTEA/SIC/RAW`, `XTEA/SIC/`, `XTEA/SIC` |  | \*P1 | legacy |
| `XTEA/GOFB/NOPADDING` | `XTEA/GOFB/RAW`, `XTEA/GOFB/`, `XTEA/GOFB` |  | \*P1 | legacy |
| `XTEA/OPENPGPCFB/NOPADDING` | `XTEA/OPENPGPCFB/RAW`, `XTEA/OPENPGPCFB/`, `XTEA/OPENPGPCFB` |  | \*P1 | legacy |

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `XTEA`
generates a `KeyOwned`. The `Box` goes with one message. An `Arc` lets one key serve many messages,
each with a fresh IV, without copying the key.

P2: `XTEA/CBC/PKCS7`, `XTEA/CBC/PKCS5PADDING`, `XTEA/CBC/PKCS5`, `XTEA/CBC/RAW`, `XTEA/CBC/`,
`XTEA/CBC`

P3: `XTEA/ECB/PKCS7`, `XTEA/ECB/PKCS5PADDING`, `XTEA/ECB/PKCS5`, `XTEA/NONE/PKCS7PADDING`,
`XTEA/NONE/PKCS7`, `XTEA/NONE/PKCS5PADDING`, `XTEA/NONE/PKCS5`, `XTEA//PKCS7PADDING`, `XTEA//PKCS7`,
`XTEA//PKCS5PADDING`, `XTEA//PKCS5`, `XTEA/ECB/RAW`, `XTEA/ECB/`, `XTEA/ECB`, `XTEA/NONE/RAW`,
`XTEA/NONE/`, `XTEA/NONE`, `XTEA//RAW`, `XTEA//`, `XTEA/`, `XTEA`
