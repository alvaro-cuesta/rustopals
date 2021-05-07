// Implement unpadded message recovery oracle - https://cryptopals.com/sets/1/challenges/41
mod challenge41_unpadded_message_recovery;

// Bleichenbacher's e=3 RSA Attack - https://cryptopals.com/sets/1/challenges/42
mod challenge42_bleichenbacher_e_3_rsa_attack;

// DSA key recovery from nonce - https://cryptopals.com/sets/1/challenges/43
#[test]
fn challenge43_dsa_key_from_nonce() {
    use num_bigint::BigUint;
    use num_traits::Num;
    use rustopals::digest::SHA1;
    use rustopals::dsa::{DSASignature, CHALLENGE_DSA, DSA};

    const EXPECTED_FINGERPRINT: [u8; 20] = [
        0x09, 0x54, 0xed, 0xd5, 0xe0, 0xaf, 0xe5, 0x54, 0x2a, 0x4a, 0xdf, 0x01, 0x26, 0x11, 0xa9,
        0x19, 0x12, 0xa3, 0xec, 0x16,
    ];

    let dsa: &DSA<_> = &CHALLENGE_DSA;

    let min_k = BigUint::from(0_usize);
    let max_k = BigUint::from(2_usize.pow(16));

    let signature = DSASignature {
        r: BigUint::from_str_radix("548099063082341131477253921760299949438196259240", 10).unwrap(),
        s: BigUint::from_str_radix("857042759984254168557880549501802188789837994940", 10).unwrap(),
    };

    let h_m = BigUint::from_str_radix("d2d0714f014a9784047eaeccf956520045c45265", 16).unwrap();

    for k in num_iter::range_inclusive(min_k, max_k) {
        let cracked_pk = dsa.crack_private_key(&signature, &h_m, &k);
        println!("{:?}", cracked_pk);
        let pk_fingerprint = cracked_pk.fingerprint_after_hex::<SHA1>();

        if pk_fingerprint == EXPECTED_FINGERPRINT {
            return;
        }
    }

    panic!("Key should've been cracked by now")
}
