//! [ECB block mode](https://en.wikipedi.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_\(ECB\)),
//! where each block is encrypted separately.

use itertools::Itertools;

use crate::block::{BlockCipher, BlockMode};
use crate::util::Probability;

/// [ECB block mode](https://en.wikipedi.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_\(ECB\))
pub struct ECB;

impl ECB {
    /// Given `data` and `block_size`, score in [0.0, 1.0] how likely it is to be
    /// encrypted using ECB.
    pub fn score(data: &[u8], block_size: usize) -> Probability {
        let unique = data.chunks(block_size).unique().count();

        Probability(1. - (unique as f32 / (data.len() as f32 / block_size as f32)))
    }
}

impl<'a> BlockMode for ECB {
    /// Encrypt `plaintext` in ECB mode with `key` using `BlockCipher`.
    fn encrypt_impl<C: BlockCipher>(&self, cipher: &C, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        plaintext
            .chunks(C::BLOCK_SIZE)
            .flat_map(|chunk| cipher.encrypt_block(chunk, key))
            .collect()
    }

    /// Decrypt `ciphertext` in ECB mode with `key` using `BlockCipher`.
    fn decrypt_impl<C: BlockCipher>(&self, cipher: &C, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        ciphertext
            .chunks(C::BLOCK_SIZE)
            .flat_map(|chunk| cipher.decrypt_block(chunk, key))
            .collect()
    }
}
