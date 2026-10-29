# Test vectors

Compressed with Python's `bz2` module (libbzip2), so they check this port
against the reference implementation rather than against itself.

| File | Contents | Block size |
| --- | --- | --- |
| `hello_level9.bz2` | `Hello, world!` | 9 |
| `bytes_level9.bz2` | bytes 0 to 255, three times | 9 |
| `runs_level9.bz2` | runs of 4, 5, 259 and 1000 bytes | 9 |
| `text_level1.bz2` | a pangram repeated 5000 times, over several blocks | 1 |
| `text_level9.bz2` | the same text | 9 |
