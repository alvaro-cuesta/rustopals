# rust-cryptopals TODO

## Refactor

- Check if static should be const
- ~~`static`s generation in tests, like base64 directly on compile-time~~
  *(needs CTFE)*
- ~~Fix HACK in Scorer~~ *(needs UFCS)*
- crypto and util different crates?
- Remove pub enum Mode
- Fix matasano_18 keystream hack
- Integration tests as http://doc.rust-lang.org/rustdoc.html#standalone-markdown-files ?
- **stream** don't depend on `&[u8]`
- **block** remove dependency on `&[u8]` and use Key, Block, etc. instead
