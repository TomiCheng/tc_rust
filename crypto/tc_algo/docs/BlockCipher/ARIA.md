# ARIA

The `aria` feature has the rows. A block of 16 bytes and a key of 16, 24 or 32, as AES; the Korean
standard.

| Name | Aliases | OIDs | Params | Note |
|---|---|---|---|---|
| `ARIA/ECB/NOPADDING` | `ARIA/NONE/NOPADDING`, `ARIA//NOPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/PKCS7PADDING` | \*P3 | `1.2.410.200046.1.1.1`, `.6`, `.11` | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ISO10126PADDING` | `ARIA/ECB/ISO10126D2PADDING`, `ARIA/ECB/ISO10126-2PADDING`, `ARIA/NONE/ISO10126PADDING`, `ARIA/NONE/ISO10126D2PADDING`, `ARIA/NONE/ISO10126-2PADDING`, `ARIA//ISO10126PADDING`, `ARIA//ISO10126D2PADDING`, `ARIA//ISO10126-2PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ISO7816-4PADDING` | `ARIA/ECB/ISO9797-1PADDING`, `ARIA/NONE/ISO7816-4PADDING`, `ARIA/NONE/ISO9797-1PADDING`, `ARIA//ISO7816-4PADDING`, `ARIA//ISO9797-1PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/X923PADDING` | `ARIA/ECB/X9.23PADDING`, `ARIA/NONE/X923PADDING`, `ARIA/NONE/X9.23PADDING`, `ARIA//X923PADDING`, `ARIA//X9.23PADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/TBCPADDING` | `ARIA/NONE/TBCPADDING`, `ARIA//TBCPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/ZEROBYTEPADDING` | `ARIA/NONE/ZEROBYTEPADDING`, `ARIA//ZEROBYTEPADDING` |  | `KeyOwned` | weak, variable time |
| `ARIA/ECB/WITHCTS` | `ARIA/NONE/WITHCTS`, `ARIA//WITHCTS` |  | `KeyOwned` | weak, variable time |
| `ARIA/CBC/NOPADDING` |  |  | \*P1 | variable time |
| `ARIA/CBC/PKCS7PADDING` | \*P2 | `1.2.410.200046.1.1.2`, `.7`, `.12` | \*P1 | variable time |
| `ARIA/CBC/ISO10126PADDING` | `ARIA/CBC/ISO10126D2PADDING`, `ARIA/CBC/ISO10126-2PADDING` |  | \*P1 | variable time |
| `ARIA/CBC/ISO7816-4PADDING` | `ARIA/CBC/ISO9797-1PADDING` |  | \*P1 | variable time |
| `ARIA/CBC/X923PADDING` | `ARIA/CBC/X9.23PADDING` |  | \*P1 | variable time |
| `ARIA/CBC/TBCPADDING` |  |  | \*P1 | variable time |
| `ARIA/CBC/ZEROBYTEPADDING` |  |  | \*P1 | variable time |
| `ARIA/CBC/WITHCTS` | `ARIA/CTS/NOPADDING`, `ARIA/CTS/RAW`, `ARIA/CTS/`, `ARIA/CTS` |  | \*P1 | variable time |
| `ARIA/CFB/NOPADDING` | `ARIA/CFB/RAW`, `ARIA/CFB/`, `ARIA/CFB`, `ARIA/CFB{8..128}/NOPADDING`, `ARIA/CFB{8..128}/RAW`, `ARIA/CFB{8..128}/`, `ARIA/CFB{8..128}` | `1.2.410.200046.1.1.3`, `.8`, `.13` | \*P1 | variable time |
| `ARIA/OFB/NOPADDING` | `ARIA/OFB/RAW`, `ARIA/OFB/`, `ARIA/OFB`, `ARIA/OFB{8..128}/NOPADDING`, `ARIA/OFB{8..128}/RAW`, `ARIA/OFB{8..128}/`, `ARIA/OFB{8..128}` | `1.2.410.200046.1.1.4`, `.9`, `.14` | \*P1 | variable time |
| `ARIA/CTR/NOPADDING` | `ARIA/SIC/NOPADDING`, `ARIA/CTR/RAW`, `ARIA/CTR/`, `ARIA/CTR`, `ARIA/SIC/RAW`, `ARIA/SIC/`, `ARIA/SIC` | `1.2.410.200046.1.1.5`, `.10`, `.15` | \*P1 | variable time |
| `ARIA/OPENPGPCFB/NOPADDING` | `ARIA/OPENPGPCFB/RAW`, `ARIA/OPENPGPCFB/`, `ARIA/OPENPGPCFB` |  | \*P1 | variable time |

The OIDs are NSRI's for 128-, 192- and 256-bit keys in each mode; those of GCM and CCM are on
[AEAD ciphers](../AeadCipher.md).

P1: The modes with an IV accept `KeyWithIvOwned`, `ParamsWithIvOwned<KeyOwned>`, or
`ParamsWithIvOwned` holding a `Box<dyn Params>` or `Arc<dyn Params>` containing `KeyOwned`. `ARIA`,
`ARIA128`, `ARIA192`, and `ARIA256` generate a `KeyOwned`. The `Box` goes with one message. An `Arc`
lets one key serve many messages, each with a fresh IV, without copying the key.

P2: `ARIA/CBC/PKCS7`, `ARIA/CBC/PKCS5PADDING`, `ARIA/CBC/PKCS5`, `ARIA/CBC/RAW`, `ARIA/CBC/`,
`ARIA/CBC`

P3: `ARIA/ECB/PKCS7`, `ARIA/ECB/PKCS5PADDING`, `ARIA/ECB/PKCS5`, `ARIA/NONE/PKCS7PADDING`,
`ARIA/NONE/PKCS7`, `ARIA/NONE/PKCS5PADDING`, `ARIA/NONE/PKCS5`, `ARIA//PKCS7PADDING`, `ARIA//PKCS7`,
`ARIA//PKCS5PADDING`, `ARIA//PKCS5`, `ARIA/ECB/RAW`, `ARIA/ECB/`, `ARIA/ECB`, `ARIA/NONE/RAW`,
`ARIA/NONE/`, `ARIA/NONE`, `ARIA//RAW`, `ARIA//`, `ARIA/`, `ARIA`
