# Rustopals

[![Rust](https://github.com/alvaro-cuesta/rustopals/actions/workflows/rust.yml/badge.svg)](https://github.com/alvaro-cuesta/rustopals/actions/workflows/rust.yml) [![Rust docs](https://img.shields.io/badge/Rust-docs-blue)](https://alvaro-cuesta.github.io/rustopals/rustopals/)

Solutions for [Cryptopals Crypto Challenges](https://cryptopals.com/)
implemented in [Rust](https://www.rust-lang.org/).

The final product should be a library of cryptographic primitives (see
[documentation](https://alvaro-cuesta.github.io/rustopals/rustopals/)),
implementing as much crypto as possible (instead of using libraries). Code
should be as generic as possible. Usage of traits and generics instead of
concrete types is encouraged.

The challenges will serve only as integration tests cases: the actual library
code is not organized around sets. If you want to review a specific challenge,
find it under the [`/tests/`](/tests/) folder and explore the used functions.

This is **not** a crypto library _(don't roll your own crypto!)_ but it should
serve as a real-world exercise.

## Running

- Run all tests:

    ```sh
    cargo test
    ```

    You can also run tests only for specific sets/tests. E.g. for set 1, challenge 2:

    ```sh
    cargo test set1::challenge2
    ```

    Or run the documentation tests:

    ```sh
    cargo test --doc
    ```

- Generate and open documentation:

    ```sh
    cargo doc --open
    ```

## Progress (42/64)

### [Set 1: Basics](https://cryptopals.com/sets/1)

- ✅ [Convert hex to base64](https://cryptopals.com/sets/1/challenges/1)
- ✅ [Fixed XOR](https://cryptopals.com/sets/1/challenges/2)
- ✅ [Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3)
- ✅ [Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4)
- ✅ [Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5)
- ✅ [Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6)
- ✅ [AES in ECB mode](https://cryptopals.com/sets/1/challenges/7)
- ✅ [Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8)

### [Set 2: Block crypto](https://cryptopals.com/sets/2)

- ✅ [Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9)
- ✅ [Implement CBC mode](https://cryptopals.com/sets/2/challenges/10)
- ✅ [An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11)
- 🟨 [Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12)
  - Tests sometimes fail due to randomness.
- ✅ [ECB cut-and-paste](https://cryptopals.com/sets/2/challenges/13)
- 🟨 [Byte-at-a-time ECB decryption (Harder)](https://cryptopals.com/sets/2/challenges/14)
  - Tests sometimes fail due to randomness.
- ✅ [PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15)
- ✅ [CBC bitflipping attacks](https://cryptopals.com/sets/2/challenges/16)

### [Set 3: Block & stream crypto](https://cryptopals.com/sets/3)

- ✅ [The CBC padding oracle](https://cryptopals.com/sets/3/challenges/17)
- ✅ [Implement CTR, the stream cipher mode](https://cryptopals.com/sets/3/challenges/18)
- ⬛ [Break fixed-nonce CTR mode using substitions](https://cryptopals.com/sets/3/challenges/19)
- ⬛ [Break fixed-nonce CTR statistically](https://cryptopals.com/sets/3/challenges/20)
- ✅ [Implement the MT19937 Mersenne Twister RNG](https://cryptopals.com/sets/3/challenges/21)
- ✅ [Crack an MT19937 seed](https://cryptopals.com/sets/3/challenges/22)
- ✅ [Clone an MT19937 RNG from its output](https://cryptopals.com/sets/3/challenges/23)
- ✅ [Create the MT19937 stream cipher and break it](https://cryptopals.com/sets/3/challenges/24)

### [Set 4: Stream crypto and randomness](https://cryptopals.com/sets/4)

- ✅ [Break "random access read/write" AES CTR](https://cryptopals.com/sets/4/challenges/25)
- ✅ [CTR bitflipping](https://cryptopals.com/sets/4/challenges/26)
- ✅ [Recover the key from CBC with IV=Key](https://cryptopals.com/sets/4/challenges/27)
- ✅ [Implement a SHA-1 keyed MAC](https://cryptopals.com/sets/4/challenges/28)
- ✅ [Break a SHA-1 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/29)
- ✅ [Break an MD4 keyed MAC using length extension](https://cryptopals.com/sets/4/challenges/30)
- ⬛ [Implement and break HMAC-SHA1 with an artificial timing leak](https://cryptopals.com/sets/4/challenges/31)
- ⬛ [Break HMAC-SHA1 with a slightly less artificial timing leak](https://cryptopals.com/sets/4/challenges/32)

### [Set 5: Diffie-Hellman and friends](https://cryptopals.com/sets/5)

- ✅ [Implement Diffie-Hellman](https://cryptopals.com/sets/5/challenges/33)
- ✅ [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](https://cryptopals.com/sets/5/challenges/34)
- 🟨 [Implement DH with negotiated groups, and break with malicious "g" parameters](https://cryptopals.com/sets/5/challenges/35)
  - See `HACK` comments on [./tests/set5/challenge35_dh_negotiated_groups.rs](./tests/set5/challenge35_dh_negotiated_groups.rs)
- ✅ [Implement Secure Remote Password (SRP)](https://cryptopals.com/sets/5/challenges/36)
- ✅ [Break SRP with a zero key](https://cryptopals.com/sets/5/challenges/37)
- ✅ [Offline dictionary attack on simplified SRP](https://cryptopals.com/sets/5/challenges/38)
- ✅ [Implement RSA](https://cryptopals.com/sets/5/challenges/39)
- ✅ [Implement an E=3 RSA Broadcast attack](https://cryptopals.com/sets/5/challenges/40)

### [Set 6: RSA and DSA](https://cryptopals.com/sets/6)

- ✅ [Implement unpadded message recovery oracle](https://cryptopals.com/sets/6/challenges/41)
- ✅ [Bleichenbacher's e=3 RSA Attack](https://cryptopals.com/sets/6/challenges/42)
- 🟨 [DSA key recovery from nonce](https://cryptopals.com/sets/6/challenges/43)
  - Pending: DSA parameter generation.
- ✅ [DSA nonce recovery from repeated nonce](https://cryptopals.com/sets/6/challenges/44)
- ✅ [DSA parameter tampering](https://cryptopals.com/sets/6/challenges/45)
- ✅ [RSA parity oracle](https://cryptopals.com/sets/6/challenges/46)
- ⬛ [Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](https://cryptopals.com/sets/6/challenges/47)
- ⬛ [Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](https://cryptopals.com/sets/6/challenges/48)

### [Set 7: Hashes](https://cryptopals.com/sets/7)

- ⬛ [CBC-MAC Message Forgery](https://cryptopals.com/sets/7/challenges/49)
- ⬛ [Hashing with CBC-MAC](https://cryptopals.com/sets/7/challenges/50)
- ⬛ [Compression Ratio Side-Channel Attacks](https://cryptopals.com/sets/7/challenges/51)
- ⬛ [Iterated Hash Function Multicollisions](https://cryptopals.com/sets/7/challenges/52)
- ⬛ [Kelsey and Schneier's Expandable Messages](https://cryptopals.com/sets/7/challenges/53)
- ⬛ [Kelsey and Kohno's Nostradamus Attack](https://cryptopals.com/sets/7/challenges/54)
- ⬛ [MD4 Collisions](https://cryptopals.com/sets/7/challenges/55)
- ⬛ [RC4 Single-Byte Biases](https://cryptopals.com/sets/7/challenges/56)

### [Set 8: Abstract Algebra](https://cryptopals.com/sets/8) (Not publicly released!)

- ⬛ Diffie-Hellman Revisited: Small Subgroup Confinement
- ⬛ Pollard's Method for Catching Kangaroos
- ⬛ Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
- ⬛ Single-Coordinate Ladders and Insecure Twists
- ⬛ Duplicate-Signature Key Selection in ECDSA (and RSA)
- ⬛ Key-Recovery Attacks on ECDSA with Biased Nonces
- ⬛ Key-Recovery Attacks on GCM with Repeated Nonces
- ⬛ Key-Recovery Attacks on GCM with a Truncated MAC

## License

**To be done (sorry!).** Need to review licenses compatible with dependencies.
