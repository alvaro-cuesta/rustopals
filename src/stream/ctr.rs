//! CTR-based stream cipher.
use crate::block::{BlockCipher, BlockMode, ECB};
use crate::stream::{SeekableStreamCipher, StreamCipher};

/// CTR-based stream cipher.
///
/// Generate a stream cipher from any block cipher.
pub struct CTR<'k, 'c, C: BlockCipher + 'c> {
    block_cipher: &'c C,
    key: &'k [u8],
    nonce: Vec<u8>,
}

impl<'k, 'c, C: BlockCipher + 'c> CTR<'k, 'c, C> {
    /// Generate a stream cipher from any block cipher in CTR mode.
    pub fn new(cipher: &'c C, key: &'k [u8]) -> CTR<'k, 'c, C> {
        use crate::util::generate_bytes;

        CTR {
            block_cipher: cipher,
            key: key,
            nonce: generate_bytes(C::BLOCK_SIZE / 2),
        }
    }

    /// Allows specifying the initial CTR nonce.
    pub fn from_nonce(cipher: &'c C, key: &'k [u8], nonce: &[u8]) -> CTR<'k, 'c, C> {
        CTR {
            block_cipher: cipher,
            key: key,
            nonce: nonce.to_vec(),
        }
    }
}

impl<'k, 'c, C: BlockCipher> StreamCipher<u8, KeyStream<'k, 'c, C>> for CTR<'k, 'c, C> {
    fn keystream(self) -> KeyStream<'k, 'c, C> {
        KeyStream::new(self.block_cipher, self.key, self.nonce.clone())
    }
}

impl<'k, 'c, C: BlockCipher> SeekableStreamCipher<u8, KeyStream<'k, 'c, C>> for CTR<'k, 'c, C> {
    fn keystream_from(self, offset: usize) -> KeyStream<'k, 'c, C> {
        KeyStream::new_from(self.block_cipher, self.key, self.nonce.clone(), offset)
    }
}

/*
 *
 */

pub struct KeyStream<'k, 'c, C: BlockCipher + 'c> {
    cipher: &'c C,
    key: &'k [u8],
    nonce: Vec<u8>,
    /// Index of current block
    counter: u64,

    /// Cached current block (cache for iterator)
    current_block: Option<Vec<u8>>,
    /// Byte in current block
    current_block_byte: usize,
}

impl<'k, 'c, C: BlockCipher> KeyStream<'k, 'c, C> {
    pub fn new(cipher: &'c C, key: &'k [u8], nonce: Vec<u8>) -> KeyStream<'k, 'c, C> {
        KeyStream {
            cipher: cipher,
            key: key,
            nonce: nonce,
            counter: 0,
            current_block: None,
            current_block_byte: 0,
        }
    }

    pub fn new_from(
        cipher: &'c C,
        key: &'k [u8],
        nonce: Vec<u8>,
        offset: usize,
    ) -> KeyStream<'k, 'c, C> {
        KeyStream {
            cipher: cipher,
            key: key,
            nonce: nonce,
            counter: (offset / C::BLOCK_SIZE) as u64,
            current_block: None,
            current_block_byte: offset % C::BLOCK_SIZE,
        }
    }
}

impl<'k, 'c, C: BlockCipher> Iterator for KeyStream<'k, 'c, C> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        use byteorder::{ByteOrder, LittleEndian};
        use num_traits::Bounded;

        if self.counter == Bounded::max_value() {
            return None;
        }

        if self.current_block.is_none() || self.current_block_byte == 0 {
            let mut counter_bytes = [0; 8];
            LittleEndian::write_u64(&mut counter_bytes, self.counter);

            let plaintext_block: Vec<u8> = [self.nonce.as_slice(), &counter_bytes].concat();
            let block = ECB.encrypt(self.cipher, &plaintext_block, self.key);
            self.current_block = Some(block);
        }

        let current_block = self.current_block.as_ref().unwrap();
        let val = current_block[self.current_block_byte];

        if self.current_block_byte == C::BLOCK_SIZE - 1 {
            self.current_block_byte = 0;
            self.counter += 1;
        } else {
            self.current_block_byte += 1;
        };

        Some(val)
    }
}
