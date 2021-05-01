# rust-cryptopals TODO

## Refactor

- ~~`static`s generation in tests, like base64 directly on compile-time~~ *(needs CTFE)*
- Remove `pub enum Mode` or integrate into `encrypt`/`decrypt`
- Fix matasano_18 keystream hack (wut? is it being pub?)
- Use `Block`, `Key`, etc. instead of `&[u8]` in `stream` and `block` modules (requires full `const_generics`)
- Lots of doc-comments and doc-tests lost :/
- Make padding and mode parameters for block cipher

## Bugs

- set2::challenge12_14_ecb_decrypt::test::test_discover_prepended_length_repeated fails randomly
