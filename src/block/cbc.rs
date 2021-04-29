//! [CBC block mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_\(CBC\)),
//! where each block of plaintext is XORed with the previous ciphertext block
//! before being encrypted.
//!
//! Each ciphertext block depends on all previous blocks. An IV (initialization
//! vector) is used as a pseudo-0th-block to make each message unique.

use itertools::Itertools;
use std::iter;

use crate::block;
use crate::util::iter::Xorable;

/// Encrypt `plaintext` in CBC mode with `key` and initialization vector `iv`
/// using `block::Cipher`.
pub fn encrypt<C: block::Cipher>(cipher: &C, plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), C::BLOCK_SIZE);

    let mut accum = Vec::new();

    for block in plaintext.chunks(C::BLOCK_SIZE) {
        let xored = {
            let prev = if !accum.is_empty() {
                &accum[accum.len() - C::BLOCK_SIZE..]
            } else {
                iv
            };

            block.xor_repeating(prev).collect::<Vec<_>>()
        };

        accum.append(&mut cipher.encrypt(&xored, key));
    }

    accum
}

/// Decrypt `ciphertext` in CBC mode with `key` and initialization vector `iv`
/// using `block::Cipher`.
pub fn decrypt<C: block::Cipher>(cipher: &C, ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(iv.len(), C::BLOCK_SIZE);

    iter::once(iv)
        .chain(ciphertext.chunks(C::BLOCK_SIZE))
        .tuple_windows()
        .map(|(prev, block)| cipher.decrypt(block, key).xor_repeating(prev))
        .flatten()
        .collect()
}
