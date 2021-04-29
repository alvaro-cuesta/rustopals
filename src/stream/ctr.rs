//! CTR-based stream cipher.
use crate::{block, stream};

/// CTR-based stream cipher.
///
/// Generate a stream cipher from any block cipher.
pub struct Cipher<'k, 'c, C: block::Cipher + 'c> {
    block_cipher: &'c C,
    key: &'k [u8],
    nonce: Vec<u8>,
}

impl<'k, 'c, C: block::Cipher + 'c> Cipher<'k, 'c, C> {
    /// Generate a stream cipher from any block cipher in CTR mode.
    pub fn new(cipher: &'c C, key: &'k [u8]) -> Cipher<'k, 'c, C> {
        use crate::util::generate_bytes;

        Cipher {
            block_cipher: cipher,
            key: key,
            nonce: generate_bytes(C::BLOCK_SIZE / 2),
        }
    }

    /// Allows specifying the initial CTR nonce.
    pub fn from_nonce(cipher: &'c C, key: &'k [u8], nonce: &[u8]) -> Cipher<'k, 'c, C> {
        Cipher {
            block_cipher: cipher,
            key: key,
            nonce: nonce.to_vec(),
        }
    }
}

impl<'k, 'c, C: block::Cipher> stream::Cipher<u8, KeyStream<'k, 'c, C>> for Cipher<'k, 'c, C> {
    fn keystream(self) -> KeyStream<'k, 'c, C> {
        KeyStream::new(self.block_cipher, self.key, self.nonce.clone())
    }
}

/*
 *
 */

pub struct KeyStream<'k, 'c, C: block::Cipher + 'c> {
    cipher: &'c C,
    key: &'k [u8],
    nonce: Vec<u8>,
    counter: u64,

    // iterator cache
    current_block: Vec<u8>,
    cursor: usize,
}

impl<'k, 'c, C: block::Cipher> KeyStream<'k, 'c, C> {
    pub fn new(cipher: &'c C, key: &'k [u8], nonce: Vec<u8>) -> KeyStream<'k, 'c, C> {
        KeyStream {
            cipher: cipher,
            key: key,
            nonce: nonce,
            current_block: vec![],
            cursor: 16,
            counter: 0,
        }
    }
}

impl<'k, 'c, C: block::Cipher> Iterator for KeyStream<'k, 'c, C> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        use byteorder::{ByteOrder, LittleEndian};
        use num_traits::Bounded;

        if self.counter == Bounded::max_value() {
            return None;
        }

        if self.cursor == C::BLOCK_SIZE {
            //let bytes = as_bytes_le!(u64, self.counter);
            let mut bytes = [0; 8];
            LittleEndian::write_u64(&mut bytes, self.counter);
            let bytes = bytes;

            let block: Vec<u8> = self.nonce.iter().chain(&bytes).cloned().collect();

            self.current_block = self.cipher.encrypt_ecb_pkcs7(&block, self.key);
            self.cursor = 1;
            self.counter += 1;
            Some(self.current_block[0])
        } else {
            let val = self.current_block[self.cursor];
            self.cursor += 1;
            Some(val)
        }
    }
}
