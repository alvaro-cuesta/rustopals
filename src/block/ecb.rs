//! [ECB block mode](https://en.wikipedi.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_\(ECB\)),
//! where each block is encrypted separately.

use crate::util::Probability;
use crate::BlockCipher;
use itertools::Itertools;

/// Encrypt `plaintext` in ECB mode with `key` using `BlockCipher`.
pub fn encrypt<C: BlockCipher>(cipher: &C, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext
        .chunks(C::BLOCK_SIZE)
        .map(|chunk| cipher.encrypt(chunk, key))
        .flatten()
        .collect()
}

/// Decrypt `ciphertext` in ECB mode with `key` using `BlockCipher`.
pub fn decrypt<C: BlockCipher>(cipher: &C, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    ciphertext
        .chunks(C::BLOCK_SIZE)
        .map(|chunk| cipher.decrypt(chunk, key))
        .flatten()
        .collect()
}

/// Given `data` and `block_size`, score in [0.0, 1.0] how likely it is to be
/// encrypted using ECB.
pub fn score(data: &[u8], block_size: usize) -> Probability {
    let unique = data.chunks(block_size).unique().count();

    Probability(1. - (unique as f32 / (data.len() as f32 / block_size as f32)))
}
