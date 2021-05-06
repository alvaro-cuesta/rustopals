use num_bigint::BigUint;
use rustopals::digest::{Digest, SHA1};
use rustopals::rsa::{BadPKCS1v1_5, RSAPrivateKey, RSAPublicKey};

use crate::RSA_KEYPAIR_0;

fn forge_signature<D: Digest>(block_len: usize, message: &[u8]) -> BigUint {
    let hash = D::digest(message);

    let left_bytes = [
        &vec![0x00, 0x01, 0xff, 0x00],
        D::ASN1_PREFIX,
        hash.as_ref(),
        // Padding for garbage
        &vec![0x00; block_len - 4 - D::ASN1_PREFIX.len() - D::OUTPUT_LENGTH],
    ]
    .concat();

    // We add 1 here because `.cbrt()` rounds down :/
    // This will fail if `left_bytes` is an exact cube but ¯\_(ツ)_/¯
    BigUint::from_bytes_be(&left_bytes).cbrt() + BigUint::from(1_usize)
}

#[test]
fn challenge42_bleichenbacher_e_3_rsa_attack() {
    const MESSAGE: &[u8] = b"hi mom";

    let (public_key, private_key) = &RSA_KEYPAIR_0 as &(RSAPublicKey, RSAPrivateKey);

    let signature = private_key.sign::<BadPKCS1v1_5, SHA1>(MESSAGE).unwrap();
    assert!(public_key.verify::<BadPKCS1v1_5, SHA1>(MESSAGE, &signature));

    let forged_signature = forge_signature::<SHA1>(1024 / 8, MESSAGE);
    assert!(public_key.verify::<BadPKCS1v1_5, SHA1>(MESSAGE, &forged_signature));
}
