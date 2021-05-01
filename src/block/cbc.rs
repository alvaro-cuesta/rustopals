//! [CBC block mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_\(CBC\)),
//! where each block of plaintext is XORed with the previous ciphertext block
//! before being encrypted.
//!
//! Each ciphertext block depends on all previous blocks. An IV (initialization
//! vector) is used as a pseudo-0th-block to make each message unique.

use itertools::Itertools;
use std::iter;

use crate::block::{BlockCipher, BlockMode};
use crate::util::iter::Xorable;

/// [CBC block mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_\(CBC\)).
pub struct CBC<'a> {
    /// Initialization vector
    iv: &'a [u8],
}

impl<'a> CBC<'a> {
    /// Create a [CBC block mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_\(CBC\))
    /// with initialization vector `iv`.
    pub fn new(iv: &'a [u8]) -> CBC<'a> {
        CBC { iv }
    }
}

impl<'a> BlockMode for CBC<'a> {
    /// Encrypt `plaintext` in CBC mode with `key` and initialization vector `iv`
    /// using `BlockCipher`.
    ///
    /// # Panics
    ///
    /// - If `iv.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE).
    fn encrypt_impl<C: BlockCipher>(&self, cipher: &C, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(self.iv.len(), C::BLOCK_SIZE);

        let mut accum = Vec::new();

        for block in plaintext.chunks(C::BLOCK_SIZE) {
            let xored = {
                let prev = if !accum.is_empty() {
                    &accum[accum.len() - C::BLOCK_SIZE..]
                } else {
                    self.iv
                };

                block.xor_repeating(prev).collect::<Vec<_>>()
            };

            accum.append(&mut cipher.encrypt_block(&xored, key));
        }

        accum
    }

    /// Decrypt `ciphertext` in CBC mode with `key` and initialization vector `iv`
    /// using `BlockCipher`.
    ///
    /// # Panics
    ///
    /// - If `iv.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE).
    fn decrypt_impl<C: BlockCipher>(&self, cipher: &C, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(self.iv.len(), C::BLOCK_SIZE);

        iter::once(self.iv)
            .chain(ciphertext.chunks(C::BLOCK_SIZE))
            .tuple_windows()
            .map(|(prev, block)| cipher.decrypt_block(block, key).xor_repeating(prev))
            .flatten()
            .collect()
    }
}
