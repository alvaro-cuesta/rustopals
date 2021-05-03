//! [Block ciphers](https://en.wikipedia.org/wiki/Block_cipher) implementations
//! and related utilities.

pub mod aes128;
pub mod cbc;
pub mod ecb;
pub mod pkcs7;

pub use aes128::AES128;
pub use cbc::CBC;
pub use ecb::ECB;
pub use pkcs7::PKCS7Error;

/// Trait for block ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait BlockCipher {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;

    /// The actual encryption implementation.
    ///
    /// Takes a `plaintext` block of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE) length
    /// and returns the ciphertext.
    fn encrypt_impl(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8>;

    /// The actual decryption implementation.
    ///
    /// Takes a `ciphertext` block of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE) length
    /// and returns the plaintext.
    fn decrypt_impl(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8>;

    /// Encrypt a block.
    ///
    /// Takes a `plaintext` block of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE) length
    /// and returns the ciphertext.
    ///
    /// # Panics
    ///
    /// - If `plaintext.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    fn encrypt_block(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(plaintext.len(), Self::BLOCK_SIZE);
        assert_eq!(key.len(), Self::KEY_SIZE);

        self.encrypt_impl(plaintext, key)
    }

    /// Decrypt a block.
    ///
    /// Takes a `ciphertext` block of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE) length
    /// and returns the plaintext.
    ///
    /// # Panics
    ///
    /// - If `plaintext.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    fn decrypt_block(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len(), Self::BLOCK_SIZE);
        assert_eq!(key.len(), Self::KEY_SIZE);

        self.decrypt_impl(ciphertext, key)
    }
}

/// Trait for [block-cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
pub trait BlockMode {
    /// The actual block-mode implementation.
    ///
    /// Encrypt `plaintext` with `key` using `BlockCipher`.
    fn encrypt_impl<C: BlockCipher>(&self, cipher: &C, plaintext: &[u8], key: &[u8]) -> Vec<u8>;

    /// The actual block-mode implementation.
    ///
    /// Decrypt `ciphertext` in ECB mode with `key` using `BlockCipher`.
    fn decrypt_impl<C: BlockCipher>(&self, cipher: &C, ciphertext: &[u8], key: &[u8]) -> Vec<u8>;

    /// Encrypt `plaintext` with `key` using `BlockCipher`.
    fn encrypt<C: BlockCipher>(&self, cipher: &C, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        self.encrypt_impl(cipher, &pkcs7::pad(plaintext, C::BLOCK_SIZE as u8), key)
    }

    /// Decrypt `ciphertext` in ECB mode with `key` using `BlockCipher`.
    ///
    /// # Errors
    ///
    /// Only due to wrong padding. See `PKCS7Error`.
    fn decrypt<C: BlockCipher>(
        &self,
        cipher: &C,
        ciphertext: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, PKCS7Error> {
        let mut decrypted = self.decrypt_impl(cipher, ciphertext, key);

        pkcs7::unpad_vec(&mut decrypted, C::BLOCK_SIZE as u8)?;

        Ok(decrypted)
    }
}

/// Block-cipher [mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).
#[derive(PartialEq, Debug)]
pub enum Mode {
    ECB,
    CBC,
}

impl Mode {
    /// Given a encryption oracle (possibly appending/prepending data), detect
    /// if it is ECB or CBC mode.
    pub fn detect<O>(mut oracle: O, block_size: usize) -> Mode
    where
        O: FnMut(&[u8]) -> Vec<u8>,
    {
        use std::iter;

        use crate::util::Probability;

        let empty_blocks = 1 + oracle(b"").len() / block_size;

        let x = iter::repeat(0)
            .take(block_size * empty_blocks * 9)
            .collect::<Vec<_>>();

        let encrypted = oracle(&x);

        if ECB::score(&encrypted, block_size) >= Probability(0.8) {
            Mode::ECB
        } else {
            Mode::CBC
        }
    }
}

/// Count repeated `block_size` bocks in `data`.
#[must_use]
pub fn count_repeated(data: &[u8], block_size: usize) -> usize {
    let mut chunks: Vec<&[u8]> = data.chunks(block_size).collect();

    let total_len = chunks.len();

    chunks.sort();
    chunks.dedup();

    total_len - chunks.len()
}
