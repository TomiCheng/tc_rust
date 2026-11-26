# SM4

The `sm4` feature has the rows. A block of 16 bytes and a key of 16; the Chinese standard.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `SM4/ECB/NOPADDING` | `SM4/NONE/NOPADDING`, `SM4//NOPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/PKCS7PADDING` | `SM4/ECB/PKCS7`, `SM4/ECB/PKCS5PADDING`, `SM4/ECB/PKCS5`, `SM4/NONE/PKCS7PADDING`, `SM4/NONE/PKCS7`, `SM4/NONE/PKCS5PADDING`, `SM4/NONE/PKCS5`, `SM4//PKCS7PADDING`, `SM4//PKCS7`, `SM4//PKCS5PADDING`, `SM4//PKCS5`, `SM4/ECB/RAW`, `SM4/ECB/`, `SM4/ECB`, `SM4/NONE/RAW`, `SM4/NONE/`, `SM4/NONE`, `SM4//RAW`, `SM4//`, `SM4/`, `SM4` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ISO10126PADDING` | `SM4/ECB/ISO10126D2PADDING`, `SM4/ECB/ISO10126-2PADDING`, `SM4/NONE/ISO10126PADDING`, `SM4/NONE/ISO10126D2PADDING`, `SM4/NONE/ISO10126-2PADDING`, `SM4//ISO10126PADDING`, `SM4//ISO10126D2PADDING`, `SM4//ISO10126-2PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ISO7816-4PADDING` | `SM4/ECB/ISO9797-1PADDING`, `SM4/NONE/ISO7816-4PADDING`, `SM4/NONE/ISO9797-1PADDING`, `SM4//ISO7816-4PADDING`, `SM4//ISO9797-1PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/X923PADDING` | `SM4/ECB/X9.23PADDING`, `SM4/NONE/X923PADDING`, `SM4/NONE/X9.23PADDING`, `SM4//X923PADDING`, `SM4//X9.23PADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/TBCPADDING` | `SM4/NONE/TBCPADDING`, `SM4//TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/ZEROBYTEPADDING` | `SM4/NONE/ZEROBYTEPADDING`, `SM4//ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `SM4/ECB/WITHCTS` | `SM4/NONE/WITHCTS`, `SM4//WITHCTS` |  | `KeyOwned` | weak, variable time |
| `SM4/CBC/NOPADDING` |  |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/PKCS7PADDING` | `SM4/CBC/PKCS7`, `SM4/CBC/PKCS5PADDING`, `SM4/CBC/PKCS5`, `SM4/CBC/RAW`, `SM4/CBC/`, `SM4/CBC` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ISO10126PADDING` | `SM4/CBC/ISO10126D2PADDING`, `SM4/CBC/ISO10126-2PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ISO7816-4PADDING` | `SM4/CBC/ISO9797-1PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/X923PADDING` | `SM4/CBC/X9.23PADDING` |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/TBCPADDING` |  |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/ZEROBYTEPADDING` |  |  | `KeyWithIvOwned` | variable time |
| `SM4/CBC/WITHCTS` | `SM4/CTS/NOPADDING`, `SM4/CTS/RAW`, `SM4/CTS/`, `SM4/CTS` |  | `KeyWithIvOwned` | variable time |
| `SM4/CFB/NOPADDING` | `SM4/CFB/RAW`, `SM4/CFB/`, `SM4/CFB`, `SM4/CFB{8..128}/NOPADDING`, `SM4/CFB{8..128}/RAW`, `SM4/CFB{8..128}/`, `SM4/CFB{8..128}` |  | `KeyWithIvOwned` | variable time |
| `SM4/OFB/NOPADDING` | `SM4/OFB/RAW`, `SM4/OFB/`, `SM4/OFB`, `SM4/OFB{8..128}/NOPADDING`, `SM4/OFB{8..128}/RAW`, `SM4/OFB{8..128}/`, `SM4/OFB{8..128}` |  | `KeyWithIvOwned` | variable time |
| `SM4/CTR/NOPADDING` | `SM4/SIC/NOPADDING`, `SM4/CTR/RAW`, `SM4/CTR/`, `SM4/CTR`, `SM4/SIC/RAW`, `SM4/SIC/`, `SM4/SIC` |  | `KeyWithIvOwned` | variable time |
| `SM4/OPENPGPCFB/NOPADDING` | `SM4/OPENPGPCFB/RAW`, `SM4/OPENPGPCFB/`, `SM4/OPENPGPCFB` |  | `KeyWithIvOwned` | variable time |

Bouncy Castle gives SM4 no OID here.
