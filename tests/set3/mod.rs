/// The CBC padding oracle - http://cryptopals.com/sets/3/challenges/17
mod matasano_17_padding_oracle;

/// Implement CTR, the stream cipher mode - http://cryptopals.com/sets/3/challenges/18
#[test]
fn matasano_18_implement_ctr() {
    use rustopals::block::aes128;
    use rustopals::stream::{ctr, Cipher};

    static BASE64_INPUT: &'static str =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    static KEY: &'static str = "YELLOW SUBMARINE";
    static NONCE: &'static [u8] = &[0, 0, 0, 0, 0, 0, 0, 0];
    static EXPECTED: &'static str = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";

    let input = base64::decode(BASE64_INPUT).unwrap();

    let result = ctr::Cipher::from_nonce(aes128::CIPHER, KEY.as_bytes(), NONCE)
        .process(input)
        .collect::<Vec<_>>();

    assert_eq!(result, EXPECTED.as_bytes())
}

/// Break fixed-nonce CTR mode using substitions - http://cryptopals.com/sets/3/challenges/19
/// Break fixed-nonce CTR statistically - http://cryptopals.com/sets/3/challenges/20
mod matasano_19_20_break_fixed_nonce_ctr;

/// Implement the MT19937 Mersenne Twister RNG - http://cryptopals.com/sets/3/challenges/21
#[test]
fn mt19937() {
    use rand::distributions::Standard;
    use rand::Rng;
    use rustopals::rand::MT19937;

    const SEED: u32 = 1;
    const COUNT: usize = 200;
    const EXPECTED: [u32; COUNT] = [
        1791095845, 4282876139, 3093770124, 4005303368, 491263, 550290313, 1298508491, 4290846341,
        630311759, 1013994432, 396591248, 1703301249, 799981516, 1666063943, 1484172013,
        2876537340, 1704103302, 4018109721, 2314200242, 3634877716, 1800426750, 1345499493,
        2942995346, 2252917204, 878115723, 1904615676, 3771485674, 986026652, 117628829,
        2295290254, 2879636018, 3925436996, 1792310487, 1963679703, 2399554537, 1849836273,
        602957303, 4033523166, 850839392, 3343156310, 3439171725, 3075069929, 4158651785,
        3447817223, 1346146623, 398576445, 2973502998, 2225448249, 3764062721, 3715233664,
        3842306364, 3561158865, 365262088, 3563119320, 167739021, 1172740723, 729416111, 254447594,
        3771593337, 2879896008, 422396446, 2547196999, 1808643459, 2884732358, 4114104213,
        1768615473, 2289927481, 848474627, 2971589572, 1243949848, 1355129329, 610401323,
        2948499020, 3364310042, 3584689972, 1771840848, 78547565, 146764659, 3221845289,
        2680188370, 4247126031, 2837408832, 3213347012, 1282027545, 1204497775, 1916133090,
        3389928919, 954017671, 443352346, 315096729, 1923688040, 2015364118, 3902387977, 413056707,
        1261063143, 3879945342, 1235985687, 513207677, 558468452, 2253996187, 83180453, 359158073,
        2915576403, 3937889446, 908935816, 3910346016, 1140514210, 1283895050, 2111290647,
        2509932175, 229190383, 2430573655, 2465816345, 2636844999, 630194419, 4108289372,
        2531048010, 1120896190, 3005439278, 992203680, 439523032, 2291143831, 1778356919,
        4079953217, 2982425969, 2117674829, 1778886403, 2321861504, 214548472, 3287733501,
        2301657549, 194758406, 2850976308, 601149909, 2211431878, 3403347458, 4057003596,
        127995867, 2519234709, 3792995019, 3880081671, 2322667597, 590449352, 1924060235,
        598187340, 3831694379, 3467719188, 1621712414, 1708008996, 2312516455, 710190855,
        2801602349, 3983619012, 1551604281, 1493642992, 2452463100, 3224713426, 2739486816,
        3118137613, 542518282, 3793770775, 2964406140, 2678651729, 2782062471, 3225273209,
        1520156824, 1498506954, 3278061020, 1159331476, 1531292064, 3847801996, 3233201345,
        1838637662, 3785334332, 4143956457, 50118808, 2849459538, 2139362163, 2670162785,
        316934274, 492830188, 3379930844, 4078025319, 275167074, 1932357898, 1526046390,
        2484164448, 4045158889, 1752934226, 1631242710, 1018023110, 3276716738, 3879985479,
        3313975271, 2463934640, 1294333494, 12327951, 3318889349, 2650617233, 656828586,
    ];

    let rng = MT19937::new(SEED);

    let result = rng.sample_iter(&Standard).take(COUNT).collect::<Vec<u32>>();

    for i in 0..COUNT {
        if result[i] != EXPECTED[i] {
            println!("{}: {} != {}", i, result[i], EXPECTED[i]);
        }
    }

    assert_eq!(result, EXPECTED)
}

/// Crack an MT19937 seed - http://cryptopals.com/sets/3/challenges/22
mod matasano_22_crack_mt19937_seed {
    use rand::Rng;
    use rustopals::rand::MT19937;

    fn get_random() -> (u64, u32) {
        use rand::distributions::uniform::SampleRange;
        use rand::thread_rng;
        use std::time::SystemTime;

        let starting_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut rng = thread_rng();
        let wait_secs = (40u64..1000).sample_single(&mut rng);

        let mut rng = MT19937::new(starting_time as u32);

        (starting_time + wait_secs, rng.gen())
    }

    #[test]
    fn crack() {
        let (now, rand) = get_random();

        let mut i = now as u32;
        while i > 0 {
            let mut rng = MT19937::new(i);

            if rng.gen::<u32>() == rand {
                println!("{}", i);
                return;
            }

            i -= 1;
        }

        unreachable!();
    }
}

/// Clone an MT19937 RNG from its output - http://cryptopals.com/sets/3/challenges/23
#[test]
fn matasano_23_clone_mt19937_state() {
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng, SeedableRng};
    use rustopals::rand::MT19937;

    const TAKE: usize = 10;
    const TAP_LENGTH: usize = 624;

    let rng_original: MT19937 = SeedableRng::from_seed(thread_rng().gen());
    let rng_clone = rng_original.clone();

    let tapped = rng_original
        .sample_iter(&Standard)
        .take(TAP_LENGTH)
        .collect::<Vec<u32>>();

    let rng_from_tap: MT19937 = MT19937::from_tap(&tapped);

    assert!(Iterator::eq(
        rng_clone
            .sample_iter::<u32, &Standard>(&Standard)
            .skip(TAP_LENGTH)
            .take(TAKE),
        rng_from_tap
            .sample_iter::<u32, &Standard>(&Standard)
            .take(TAKE)
    ));
}

// Create the MT19937 stream cipher and break it - http://cryptopals.com/sets/3/challenges/24
