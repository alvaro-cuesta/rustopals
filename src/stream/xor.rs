//! XOR-based streaming ciphers.
//!
//! **TODO:**
//! - Do not depend on `u8` scoring.
//! - Try removing `Clone`s.

use num_traits::Bounded;
use std::{iter, ops};

use crate::stream;
use stream::Cipher;

/// XOR cipher with a single-item key (`AAAAAAAAAAAA...`)
///
/// # Example
///
/// ```
/// use rustopals::stream::{ Cipher, xor };
///
/// static KEY: u8 = 1;
/// static PLAINTEXT: &[u8] = &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
/// static EXPECTED_CIPHERTEXT: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
///
/// let result = xor::SingleCipher(KEY)
///     .process(PLAINTEXT)
///     .collect::<Vec<_>>();
///
/// assert_eq!(result, EXPECTED_CIPHERTEXT)
/// ```
pub struct SingleCipher<K>(pub K);

impl<K> stream::Cipher<K, iter::Repeat<K>> for SingleCipher<K>
where
    K: Clone,
{
    fn keystream(self) -> iter::Repeat<K> {
        iter::repeat(self.0.clone())
    }
}

/// Single-item key XOR cipher cracking.
impl<K> SingleCipher<K> {
    /// Brute-force single-item key XOR ciphered `ciphertext` by frequency
    /// analysis.
    ///
    /// Returns `Some<(key, plaintext)>` if cracked successfully, `None` otherwise.
    pub fn crack<'t, T>(ciphertext: &'t [T]) -> Option<(K, String)>
    where
        &'t T: ops::BitXor<K, Output = u8>,
        K: Bounded + iter::Step,
    {
        (K::min_value()..=K::max_value())
            .filter_map(|key| {
                let xored = SingleCipher(key.clone())
                    .process(ciphertext)
                    .collect::<Vec<_>>();

                String::from_utf8(xored)
                    .ok()
                    .map(|plaintext| (key, crate::util::score_string(&plaintext), plaintext))
            })
            .max_by(|(_, a_score, _), (_, b_score, _)| a_score.partial_cmp(b_score).unwrap())
            .map(|(key, _, plaintext)| (key, plaintext))
    }

    /// Detect single-item key XOR cipher by frequency analysis in a list of
    /// encrypted `ciphertexts`.
    ///
    /// Returns `Some(index, key, plaintext)` if cracked successfully, `None`
    /// otherwise.
    pub fn detect<'t, T>(ciphertexts: &[&'t [T]]) -> Option<(usize, K, String)>
    where
        &'t T: ops::BitXor<K, Output = u8>,
        K: Bounded + iter::Step,
    {
        ciphertexts
            .into_iter()
            .enumerate()
            .filter_map(|(pos, ciphertext)| {
                Self::crack(&ciphertext).map(|(key, plaintext)| (pos, key, plaintext))
            })
            .map(|(pos, key, plaintext)| {
                (pos, key, crate::util::score_string(&plaintext), plaintext)
            })
            .max_by(|(_, _, a_score, _), (_, _, b_score, _)| a_score.partial_cmp(b_score).unwrap())
            .map(|(pos, key, _, plaintext)| (pos, key, plaintext))
    }
}

/// Xor cipher with a repeating multi-item key (`ABCDABCDABCD...`)
///
/// # Example
///
/// ```
/// use rustopals::stream::{ Cipher, xor };
///
/// static KEY: &[u8] = &[0, 1, 2, 3];
/// static PLAINTEXT: &[u8] = &[0, 1, 2, 3, 0, 1, 2, 3, 0, 1];
/// static EXPECTED_CIPHERTEXT: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
///
/// let result = xor::RepeatingCipher(KEY)
///     .process(PLAINTEXT)
///     .collect::<Vec<_>>();
///
/// assert_eq!(result, EXPECTED_CIPHERTEXT)
/// ```
pub struct RepeatingCipher<'k, K: 'k>(pub &'k [K]);

impl<'k, K> stream::Cipher<&'k K, iter::Cycle<::std::slice::Iter<'k, K>>>
    for RepeatingCipher<'k, K>
{
    fn keystream(self) -> iter::Cycle<::std::slice::Iter<'k, K>> {
        self.0.iter().cycle()
    }
}

impl<'k, K> RepeatingCipher<'k, K> {
    /// Guess key size (up to `max_size`) for a given ciphertext.
    pub fn guess_keysize<'t, T>(ciphertext: &'t [T], max_keysize: usize) -> Option<usize>
    where
        T: 't,
        &'t T: ops::BitXor<&'t T>,
        <&'t T as ops::BitXor<&'t T>>::Output: ::num_traits::PrimInt,
    {
        use crate::util::iter::Hammingable;

        (1..=max_keysize)
            .map(|keysize| {
                let chunks = ciphertext.chunks(keysize).collect::<Vec<_>>();

                let distance = chunks
                    .chunks(2)
                    .filter(|x| x.len() == 2)
                    .map(|pair| pair[0].iter().hamming_distance(pair[1]))
                    .sum::<u32>() as f32
                    / (chunks.len() as f32);

                (keysize, distance as f32 / keysize as f32)
            })
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(keysize, _)| keysize)
    }

    /// Guess key of `guessed_keysize` for a given `ciphertext`.
    pub fn guess_key<T>(ciphertext: &[T], guessed_keysize: usize) -> Vec<K>
    where
        T: Clone,
        for<'t> &'t T: ops::BitXor<K, Output = u8>,
        K: Bounded + iter::Step,
    {
        let chunks = ciphertext
            .chunks(guessed_keysize)
            .filter(|x| x.len() == guessed_keysize)
            .collect::<Vec<_>>();

        (0..guessed_keysize)
            .filter_map(|i| {
                let mut inner_vec = Vec::new();

                for block in chunks.iter() {
                    inner_vec.push(block[i].clone());
                }

                SingleCipher::crack(&inner_vec).map(|(key, _)| key)
            })
            .collect::<Vec<_>>()
    }
}
