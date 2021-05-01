//! Block ciphers and utilities.

pub mod aes128;
pub mod cbc;
pub mod ecb;
pub mod pkcs7;

pub use aes128::AES128;
pub use pkcs7::PKCS7Error;

/// Trait for block ciphers.
///
/// See [implementors](#implementors) for examples.
pub trait BlockCipher: Sized {
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
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
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
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len(), Self::BLOCK_SIZE);
        assert_eq!(key.len(), Self::KEY_SIZE);

        self.decrypt_impl(ciphertext, key)
    }

    /// Encrypt plaintext using [ECB mode](./ecb/index.html) and
    /// [PKCS7 padding](./pkcs7/index.html).
    ///
    /// Takes a `plaintext` and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE)
    /// length and returns the ciphertext.
    ///
    /// # Panics
    ///
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    fn encrypt_ecb_pkcs7(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        assert!(Self::BLOCK_SIZE < 256);

        ecb::encrypt(self, &pkcs7::pad(plaintext, Self::BLOCK_SIZE as u8), key)
    }

    /// Decrypt ciphertext using [ECB mode](./ecb/index.html) and
    /// [PKCS7 padding](./pkcs7/index.html).
    ///
    /// Takes a `ciphertext` and a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE)
    /// length and returns either the ciphertext or a [PKCS7 error](./pkcs7/enum.PKCS7Error.html).
    ///
    /// # Panics
    ///
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    fn decrypt_ecb_pkcs7(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, PKCS7Error> {
        assert!(Self::BLOCK_SIZE < 256);

        let mut decrypted = ecb::decrypt(self, ciphertext, key);
        pkcs7::unpad_vec(&mut decrypted, Self::BLOCK_SIZE as u8)?;

        Ok(decrypted)
    }

    /// Encrypt plaintext using [CBC mode](./cbc/index.html) and
    /// [PKCS7 padding](./pkcs7/index.html).
    ///
    /// Takes a `plaintext`, a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE)
    /// length and an initialization vector `iv` of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and returns the ciphertext.
    ///
    /// # Panics
    ///
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    /// - If `iv.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE).
    fn encrypt_cbc_pkcs7(&self, plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        assert!(Self::BLOCK_SIZE < 256);

        cbc::encrypt(
            self,
            &pkcs7::pad(plaintext, Self::BLOCK_SIZE as u8),
            key,
            iv,
        )
    }

    /// Decrypt ciphertext using [CBC mode](./cbc/index.html) and
    /// [PKCS7 padding](./pkcs7/index.html).
    ///
    /// Takes a `ciphertext`, a `key` of [`KEY_SIZE`](#associatedconstant.KEY_SIZE)
    /// length and an initialization vector `iv` of [`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE)
    /// length and returns either the plaintext or a [PKCS7 error](./pkcs7/enum.PKCS7Error.html).
    ///
    /// # Panics
    ///
    /// - If `key.len() != `[`KEY_SIZE`](#associatedconstant.KEY_SIZE).
    /// - If `iv.len() != `[`BLOCK_SIZE`](#associatedconstant.BLOCK_SIZE).
    fn decrypt_cbc_pkcs7(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, PKCS7Error> {
        assert!(Self::BLOCK_SIZE < 256);

        let mut decrypted = cbc::decrypt(self, ciphertext, key, iv);
        pkcs7::unpad_vec(&mut decrypted, Self::BLOCK_SIZE as u8)?;

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
        use crate::util::Probability;
        use std::iter;

        let empty_blocks = 1 + oracle(b"").len() / block_size;

        let x = iter::repeat(0)
            .take(block_size * empty_blocks * 9)
            .collect::<Vec<_>>();

        let encrypted = oracle(&x);

        if ecb::score(&encrypted, block_size) >= Probability(0.8) {
            Mode::ECB
        } else {
            Mode::CBC
        }
    }
}

/// Count repeated `block_size` bocks in `data`.
pub fn count_repeated(data: &[u8], block_size: usize) -> usize {
    let mut chunks: Vec<&[u8]> = data.chunks(block_size).collect();

    let total_len = chunks.len();

    chunks.sort();
    chunks.dedup();

    total_len - chunks.len()
}
