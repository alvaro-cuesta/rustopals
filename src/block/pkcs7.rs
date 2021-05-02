//! [PKCS7 padding scheme](https://en.wikipedia.org/wiki/Padding_\(cryptography\)#PKCS7).
//! Pads/unpads plaintext/ciphertext to a multiple of the block size.
//!
//! The padding byte value (repeated for each byte of padding) is the number of
//! bytes that are added, (i.e. `N` bytes of value `N` are added). This implies
//! padding values are `<= block_size`.
//!
//! If no padding is needed, a full block (i.e. `block_size` bytes) of value
//! `block_size` is added. This is required to disambiguate padding from an
//! actual ending byte. This implies `0x00` padding is invalid.

/// Possible PKCS7 padding errors.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PKCS7Error {
    /// The payload is empty (i.e. no padding).
    Empty,

    /// Invalid padding byte.
    BadByte,

    /// Wrong padding.
    BadPadding,
}

fn get_padding_length(payload: &[u8], block_length: u8) -> Result<usize, PKCS7Error> {
    let pad_byte = *match payload.last() {
        Some(b) => b,
        None => return Err(PKCS7Error::Empty),
    };

    let pad_len = if pad_byte > 0 && pad_byte <= block_length {
        pad_byte as usize
    } else {
        return Err(PKCS7Error::BadByte);
    };

    let is_valid_padding = payload[payload.len() - pad_len..]
        .iter()
        .all(|x| *x == pad_byte);

    if !is_valid_padding {
        return Err(PKCS7Error::BadPadding);
    }

    Ok(pad_len)
}

/// Immutably pads `payload` to a multiple of `block_length`. Returns a new
/// buffer.
///
/// # Examples
///
/// - Padding 16 bytes for `block_length = 20` adds 4 bytes of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     assert_eq!(
///         pkcs7::pad(b"YELLOW SUBMARINE", 20),
///         b"YELLOW SUBMARINE\x04\x04\x04\x04",
///     );
///     ```
///
/// - Padding 16 bytes for `block_length = 16` adds a new block of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     assert_eq!(
///         pkcs7::pad(b"YELLOW SUBMARINE", 16),
///         b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
///     );
///     ```
#[must_use]
pub fn pad(payload: &[u8], block_length: u8) -> Vec<u8> {
    let pad_byte = block_length - (payload.len() % block_length as usize) as u8;
    let pad_len = if pad_byte == 0 {
        block_length
    } else {
        pad_byte
    } as usize;

    let mut result = payload.to_vec();
    result.resize(payload.len() + pad_len, pad_byte);

    result
}

/// Mutably pads `payload` to a multiple of `block_length`. Modifies the
/// `payload` buffer.
///
/// # Examples
///
/// - Padding 16 bytes for `block_length = 20` adds 4 bytes of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     let mut buffer = b"YELLOW SUBMARINE".to_vec();
///     pkcs7::pad_vec(&mut buffer, 20);
///
///     assert_eq!(
///         buffer,
///         b"YELLOW SUBMARINE\x04\x04\x04\x04",
///     );
///     ```
///
/// - Padding 16 bytes for `block_length = 16` adds a new block of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     let mut buffer = b"YELLOW SUBMARINE".to_vec();
///     pkcs7::pad_vec(&mut buffer, 16);
///
///     assert_eq!(
///         buffer,
///         b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
///     );
///     ```
pub fn pad_vec(payload: &mut Vec<u8>, block_length: u8) {
    let pad_byte = block_length - (payload.len() % block_length as usize) as u8;
    let pad_len = if pad_byte == 0 {
        block_length
    } else {
        pad_byte
    } as usize;
    let length = payload.len();

    payload.resize(length + pad_len, pad_byte);
}

/// Immutably unpads `payload` from a multiple of `block_length`. Returns a
/// slice of the original buffer.
///
/// # Examples
///
/// - Unpadding 20 bytes for `block_length = 16` removes 4 bytes of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     assert_eq!(
///         pkcs7::unpad(b"YELLOW SUBMARINE\x04\x04\x04\x04", 20)
///             .unwrap(),
///         b"YELLOW SUBMARINE",
///     );
///     ```
///
/// - Unpadding 40 bytes for `block_length = 20` removes a block of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     assert_eq!(
///         pkcs7::unpad(b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", 20)
///             .unwrap(),
///         b"YELLOW SUBMARINE",
///     );
///     ```
///
/// # Errors
///
/// - Unpadding an empty string is an error (expects a block of padding).
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     assert_eq!(
///         pkcs7::unpad(b"", 20),
///         Err(PKCS7Error::Empty),
///     );
///     ```
///
/// - Padding byte cannot be `0x00`.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     assert_eq!(
///         pkcs7::unpad(b"YELLOW SUBMARINE\x00\x00\x00\x00", 20),
///         Err(PKCS7Error::BadByte),
///     );
///     ```
///
/// - Padding byte cannot be `>` than `block_length`.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     assert_eq!(
///         pkcs7::unpad(b"YELLOW SUBMARINE\xff\xff\xff\xff", 20),
///         Err(PKCS7Error::BadByte),
///     );
///     ```
///
/// - All padding bytes must be the same.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     assert_eq!(
///         pkcs7::unpad(b"YELLOW SUBMARINE\x01\x02\x03\x04", 20),
///         Err(PKCS7Error::BadPadding),
///     );
///     ```
pub fn unpad(payload: &[u8], block_length: u8) -> Result<&[u8], PKCS7Error> {
    let pad_len = get_padding_length(payload, block_length)?;
    Ok(&payload[..payload.len() - pad_len])
}

/// Mutably unpads `payload` from a multiple of `block_length`. Modifies the
/// `payload` buffer.
///
/// # Examples
///
/// - Unpadding 20 bytes for `block_length = 16` removes 4 bytes of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     let mut buffer = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
///     pkcs7::unpad_vec(&mut buffer, 16).unwrap();
///
///     assert_eq!(buffer, b"YELLOW SUBMARINE");
///     ```
///
/// - Unpadding 40 bytes for `block_length = 20` removes a block of padding.
///
///     ```
///     use rustopals::block::pkcs7;
///
///     let mut buffer = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
///         .to_vec();
///     pkcs7::unpad_vec(&mut buffer, 20).unwrap();
///
///     assert_eq!(buffer, b"YELLOW SUBMARINE");
///     ```
///
/// # Errors
///
/// - Unpadding an empty string is an error (expects a block of padding).
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     let mut buffer = b"".to_vec();
///
///     assert_eq!(
///         pkcs7::unpad_vec(&mut buffer, 20),
///         Err(PKCS7Error::Empty),
///     );
///     ```
///
/// - Padding byte cannot be `0x00`.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     let mut buffer = b"YELLOW SUBMARINE\x00\x00\x00\x00".to_vec();
///
///     assert_eq!(
///         pkcs7::unpad_vec(&mut buffer, 20),
///         Err(PKCS7Error::BadByte),
///     );
///     ```
///
/// - Padding byte cannot be `>` than `block_length`.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///
///     let mut buffer = b"YELLOW SUBMARINE\xff\xff\xff\xff".to_vec();
///
///     assert_eq!(
///         pkcs7::unpad_vec(&mut buffer, 20),
///         Err(PKCS7Error::BadByte),
///     );
///     ```
///
/// - All padding bytes must be the same.
///
///     ```
///     use rustopals::block::{ pkcs7, PKCS7Error };
///     let mut buffer = b"YELLOW SUBMARINE\x01\x02\x03\x04".to_vec();
///
///     assert_eq!(
///         pkcs7::unpad_vec(&mut buffer, 20),
///         Err(PKCS7Error::BadPadding),
///     );
///     ```
pub fn unpad_vec(payload: &mut Vec<u8>, block_length: u8) -> Result<(), PKCS7Error> {
    let pad_len = get_padding_length(payload, block_length)?;

    let length = payload.len();
    payload.truncate(length - pad_len);

    Ok(())
}
