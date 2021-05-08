use num_bigint::BigUint;
use num_traits::Num;
use rustopals::digest::SHA1;
use rustopals::dsa::{
    DSAPublicKey, DSASignature, CHALLENGE_DSA, CHALLENGE_DSA_P, CHALLENGE_DSA_Q, DSA,
};

// Implement unpadded message recovery oracle - https://cryptopals.com/sets/1/challenges/41
mod challenge41_unpadded_message_recovery;

// Bleichenbacher's e=3 RSA Attack - https://cryptopals.com/sets/1/challenges/42
mod challenge42_bleichenbacher_e_3_rsa_attack;

// DSA key recovery from nonce - https://cryptopals.com/sets/1/challenges/43
#[test]
fn challenge43_dsa_key_from_nonce() {
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
        let cracked_pk = dsa.crack_private_key_guess(&signature, &h_m, &k);
        let pk_fingerprint = cracked_pk.fingerprint_after_hex::<SHA1>();

        if pk_fingerprint == EXPECTED_FINGERPRINT {
            return;
        }
    }

    panic!("Key should've been cracked by now")
}

// DSA nonce recovery from repeated nonce - https://cryptopals.com/sets/1/challenges/44
#[test]
fn challenge44_dsa_key_from_repeated_nonce() {
    use itertools::Itertools;
    use regex::Regex;

    const INPUT_FILE: &str = include_str!("44.txt");

    const EXPECTED_FINGERPRINT: [u8; 20] = [
        0xca, 0x8f, 0x6f, 0x7c, 0x66, 0xfa, 0x36, 0x2d, 0x40, 0x76, 0x0d, 0x13, 0x5b, 0x76, 0x3e,
        0xb8, 0x52, 0x7d, 0x3d, 0x52,
    ];

    let re = Regex::new(
        r"msg: (?P<msg>[^\n]+)\ns: (?P<s>\d+)\nr: (?P<r>\d+)\nm: (?P<m>[a-f0-9]{40})(?:\n|$)",
    )
    .unwrap();

    let duplicates = re
        .captures_iter(INPUT_FILE)
        .map(|x| (x["r"].to_string(), x))
        .into_group_map()
        .into_iter()
        .find(|(_, v)| v.len() > 1)
        .expect("No duplicate `r` found")
        .1;

    let sig_1 = (
        DSASignature {
            r: BigUint::from_str_radix(&duplicates[0]["r"], 10).unwrap(),
            s: BigUint::from_str_radix(&duplicates[0]["s"], 10).unwrap(),
        },
        BigUint::from_str_radix(&duplicates[0]["m"], 16).unwrap(),
    );

    let sig_2 = (
        DSASignature {
            r: BigUint::from_str_radix(&duplicates[1]["r"], 10).unwrap(),
            s: BigUint::from_str_radix(&duplicates[1]["s"], 10).unwrap(),
        },
        BigUint::from_str_radix(&duplicates[1]["m"], 16).unwrap(),
    );

    let dsa: &DSA<_> = &CHALLENGE_DSA;

    let cracked_pk = dsa
        .crack_private_key_repeated_nonce([(&sig_1.0, &sig_1.1), (&sig_2.0, &sig_2.1)])
        .unwrap();
    let pk_fingerprint = cracked_pk.fingerprint_after_hex::<SHA1>();

    assert_eq!(pk_fingerprint, EXPECTED_FINGERPRINT);
}

// DSA parameter tampering - https://cryptopals.com/sets/1/challenges/45
#[test]
fn challenge45_dsa_param_tampering() {
    let dsa = DSA::<SHA1>::new_from_params(
        CHALLENGE_DSA_P.clone(),
        CHALLENGE_DSA_Q.clone(),
        (&CHALLENGE_DSA_P as &BigUint) + BigUint::from(1_usize),
    );

    let y = BigUint::from_str_radix(
        "\
        2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
        13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
        5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
        f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
        f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
        2971c3de5084cce04a2e147821",
        16,
    )
    .unwrap();

    let public_key = DSAPublicKey(y);
    let magic_signature = dsa.gen_magic_signature(&public_key).unwrap();

    assert!(dsa.verify(&public_key, b"Hello, world", &magic_signature));
    assert!(dsa.verify(&public_key, b"Goodbye, world", &magic_signature));
}

// RSA parity oracle - https://cryptopals.com/sets/1/challenges/46
mod challenge46_rsa_parity_oracle;
