//! Utilities that generate or operate on iterators.

use std::collections::HashMap;
use std::{cmp, fmt, hash, iter, num, ops, str};

use iter::{Cycle, IntoIterator, Map, Zip};

/// Iterator generator. Produces bytes (`u8`) from a `hex` string.
pub fn bytes_from_hex(hex: &str) -> impl Iterator<Item = Result<u8, num::ParseIntError>> + '_ {
    hex.as_bytes()
        .chunks(2)
        .map(|b| u8::from_str_radix(unsafe { str::from_utf8_unchecked(b) }, 16))
}

/// Allows applying XOR operation between iterators over items that can be
/// XOR-ed together.
pub trait Xorable<A, B, IA, IB>
where
    A: ops::BitXor<B>,
    IA: IntoIterator<Item = A>,
    IB: IntoIterator<Item = B>,
{
    /// XOR two iterators until one of them exhausts.
    ///
    /// # Example
    ///
    /// ```
    /// use rustopals::util::iter::Xorable;
    ///
    /// const EXPECTED_DISTANCE: u32 = 37;
    ///
    /// const A: &[u8] = &[0u8, 1, 2, 3];
    /// const B: &[u8] = &[1u8, 3, 3, 7];
    /// const EXPECTED: &[u8] = &[1u8, 2, 1, 4];
    ///
    /// let result = A
    ///     .iter()
    ///     .xor(B.iter())
    ///     .collect::<Vec<_>>();
    ///
    /// assert_eq!(result, EXPECTED);
    /// ```
    #[allow(clippy::type_complexity)]
    fn xor(
        self,
        other: IB,
    ) -> Map<
        Zip<<IA as IntoIterator>::IntoIter, <IB as IntoIterator>::IntoIter>,
        fn((A, B)) -> A::Output,
    >;

    /// XOR two iterators, repeating the second one cyclically.
    ///
    /// # Example
    ///
    /// ```
    /// use rustopals::util::iter::Xorable;
    ///
    /// const EXPECTED_DISTANCE: u32 = 37;
    ///
    /// const A: &[u8] = &[0u8, 1, 2, 3, 4];
    /// const B: &[u8] = &[1u8, 3];
    /// const EXPECTED: &[u8] = &[1u8, 2, 3, 0, 5];
    ///
    /// let result = A
    ///     .iter()
    ///     .xor_repeating(B.iter())
    ///     .collect::<Vec<_>>();
    ///
    /// assert_eq!(result, EXPECTED);
    /// ```
    #[allow(clippy::type_complexity)]
    fn xor_repeating(
        self,
        other: IB,
    ) -> Map<
        Zip<<IA as IntoIterator>::IntoIter, Cycle<<IB as IntoIterator>::IntoIter>>,
        fn((A, B)) -> A::Output,
    >
    where
        <IB as IntoIterator>::IntoIter: Clone;
}

fn xor<A: ops::BitXor<B>, B>((a, b): (A, B)) -> A::Output {
    a ^ b
}

impl<A, B, IA, IB> Xorable<A, B, IA, IB> for IA
where
    A: ops::BitXor<B>,
    IA: IntoIterator<Item = A>,
    IB: IntoIterator<Item = B>,
{
    #[allow(clippy::type_complexity)]
    fn xor(
        self,
        other: IB,
    ) -> Map<
        Zip<<IA as IntoIterator>::IntoIter, <IB as IntoIterator>::IntoIter>,
        fn((A, B)) -> A::Output,
    > {
        self.into_iter().zip(other.into_iter()).map(xor)
    }

    #[allow(clippy::type_complexity)]
    fn xor_repeating(
        self,
        other: IB,
    ) -> Map<
        Zip<<IA as IntoIterator>::IntoIter, Cycle<<IB as IntoIterator>::IntoIter>>,
        fn((A, B)) -> A::Output,
    >
    where
        <IB as IntoIterator>::IntoIter: Clone,
    {
        self.into_iter().zip(other.into_iter().cycle()).map(xor)
    }
}

/// Iterator adaptor for Hamming (bit-wise) distance of xor-able iterators.
///
/// # Example
///
/// ```
/// use rustopals::util::iter::Hammingable;
///
/// const EXPECTED_DISTANCE: u32 = 37;
///
/// let distance = "this is a test".as_bytes()
///     .hamming_distance("wokka wokka!!!".as_bytes());
///
/// assert_eq!(distance, EXPECTED_DISTANCE);
/// ```
pub trait Hammingable<A, B, IA, IB>
where
    A: ops::BitXor<B>,
    A::Output: ::num_traits::PrimInt,
    IA: IntoIterator<Item = A>,
    IB: IntoIterator<Item = B>,
{
    fn hamming_distance(self, other: IB) -> u32;
}

impl<A, B, IA, IB> Hammingable<A, B, IA, IB> for IA
where
    A: ops::BitXor<B>,
    A::Output: ::num_traits::PrimInt,
    IA: IntoIterator<Item = A>,
    IB: IntoIterator<Item = B>,
{
    fn hamming_distance(self, other: IB) -> u32 {
        self.xor(other).map(::num_traits::PrimInt::count_ones).sum()
    }
}

/// Allows collecting an iterator over hex-formatteable values into a hex string.
///
/// # Example
///
/// ```
/// use rustopals::util::iter::ToHexable;
///
/// const INPUT: &[u8] = &[0x13, 0x37, 0xde, 0xad, 0xbe, 0xef];
/// const EXPECTED: &str = "1337deadbeef";
///
/// let result = INPUT
///     .iter()
///     .into_hex();
///
/// assert_eq!(result, EXPECTED);
/// ```
pub trait ToHexable {
    fn into_hex(self) -> String;
}

// TODO: {:02x} is only valid for u8. Abstract for any LoweHex type.
impl<A, IA> ToHexable for IA
where
    A: fmt::LowerHex,
    IA: IntoIterator<Item = A>,
{
    fn into_hex(self) -> String {
        self.into_iter().map(|x| format!("{:02x}", x)).collect()
    }
}

/// Allows counting occurrences of items in an iterator.
///
/// # Example
///
/// ```
/// use std::array::IntoIter;
/// use std::collections::HashMap;
/// use std::iter::FromIterator;
/// use rustopals::util::iter::Occurrenceable;
///
/// const INPUT: &str = "Hello world!";
///
/// let expected = [
///     ('H', 1),
///     ('e', 1),
///     ('l', 3),
///     ('o', 2),
///     (' ', 1),
///     ('w', 1),
///     ('r', 1),
///     ('d', 1),
///     ('!', 1),
/// ]
///     .into_iter()
///     .copied()
///     .collect::<HashMap<_, _>>();
///
/// let result = INPUT
///     .chars()
///     .occurrences();
///
/// assert_eq!(result, expected);
/// ```
pub trait Occurrenceable<A, IA>
where
    IA: IntoIterator<Item = A>,
{
    fn occurrences(self) -> HashMap<A, usize>;
}

impl<A, IA> Occurrenceable<A, IA> for IA
where
    A: cmp::Eq + hash::Hash,
    IA: IntoIterator<Item = A>,
{
    fn occurrences(self) -> HashMap<A, usize> {
        let mut map = HashMap::new();

        for item in self {
            *map.entry(item).or_insert(0) += 1;
        }

        map
    }
}
