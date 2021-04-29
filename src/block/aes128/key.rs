use std::mem::MaybeUninit;

type ExpandedKey = [[[u8; 4]; 4]; 11];

const RCON: [u8; 16] = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
];

/// Expand a 128 bit key for AES128
pub fn expand(key: &[u8; 16]) -> ExpandedKey {
    let mut expanded = MaybeUninit::<ExpandedKey>::uninit();

    unsafe {
        (*expanded.as_mut_ptr())[0] = [
            [key[0], key[1], key[2], key[3]],
            [key[4], key[5], key[6], key[7]],
            [key[8], key[9], key[10], key[11]],
            [key[12], key[13], key[14], key[15]],
        ];
    }

    for i in 1..11 {
        let previous = unsafe { (*expanded.as_ptr())[i - 1] };

        let mut current = [
            key_core(&previous[3], i),
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
        ];

        for j in 0..4 {
            current[0][j] ^= previous[0][j];
        }

        for j in 1..4 {
            current[j] = current[j - 1];

            for k in 0..4 {
                current[j][k] ^= previous[j][k];
            }
        }

        unsafe {
            (*expanded.as_mut_ptr())[i] = current;
        }
    }

    unsafe { expanded.assume_init() }
}

fn key_core(input: &[u8; 4], iteration: usize) -> [u8; 4] {
    let mut output = *input;

    let temp = output[0];

    // rot_word
    output[0] = output[1];
    output[1] = output[2];
    output[2] = output[3];
    output[3] = temp;

    // sub_word
    for i in 0..4 {
        output[i] = super::S[output[i] as usize];
    }

    // rcon
    output[0] ^= RCON[iteration];

    output
}

#[cfg(test)]
mod test {
    #[test]
    fn expand() {
        const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        const EXPECTED_EXPANDED_KEY: super::ExpandedKey = [
            [
                [0x00, 0x01, 0x02, 0x03],
                [0x04, 0x05, 0x06, 0x07],
                [0x08, 0x09, 0x0A, 0x0B],
                [0x0C, 0x0D, 0x0E, 0x0F],
            ],
            [
                [0xD6, 0xAA, 0x74, 0xFD],
                [0xD2, 0xAF, 0x72, 0xFA],
                [0xDA, 0xA6, 0x78, 0xF1],
                [0xD6, 0xAB, 0x76, 0xFE],
            ],
            [
                [0xB6, 0x92, 0xCF, 0x0B],
                [0x64, 0x3D, 0xBD, 0xF1],
                [0xBE, 0x9B, 0xC5, 0x00],
                [0x68, 0x30, 0xB3, 0xFE],
            ],
            [
                [0xB6, 0xFF, 0x74, 0x4E],
                [0xD2, 0xC2, 0xC9, 0xBF],
                [0x6C, 0x59, 0x0C, 0xBF],
                [0x04, 0x69, 0xBF, 0x41],
            ],
            [
                [0x47, 0xF7, 0xF7, 0xBC],
                [0x95, 0x35, 0x3E, 0x03],
                [0xF9, 0x6C, 0x32, 0xBC],
                [0xFD, 0x05, 0x8D, 0xFD],
            ],
            [
                [0x3C, 0xAA, 0xA3, 0xE8],
                [0xA9, 0x9F, 0x9D, 0xEB],
                [0x50, 0xF3, 0xAF, 0x57],
                [0xAD, 0xF6, 0x22, 0xAA],
            ],
            [
                [0x5E, 0x39, 0x0F, 0x7D],
                [0xF7, 0xA6, 0x92, 0x96],
                [0xA7, 0x55, 0x3D, 0xC1],
                [0x0A, 0xA3, 0x1F, 0x6B],
            ],
            [
                [0x14, 0xF9, 0x70, 0x1A],
                [0xE3, 0x5F, 0xE2, 0x8C],
                [0x44, 0x0A, 0xDF, 0x4D],
                [0x4E, 0xA9, 0xC0, 0x26],
            ],
            [
                [0x47, 0x43, 0x87, 0x35],
                [0xA4, 0x1C, 0x65, 0xB9],
                [0xE0, 0x16, 0xBA, 0xF4],
                [0xAE, 0xBF, 0x7A, 0xD2],
            ],
            [
                [0x54, 0x99, 0x32, 0xD1],
                [0xF0, 0x85, 0x57, 0x68],
                [0x10, 0x93, 0xED, 0x9C],
                [0xBE, 0x2C, 0x97, 0x4E],
            ],
            [
                [0x13, 0x11, 0x1D, 0x7F],
                [0xE3, 0x94, 0x4A, 0x17],
                [0xF3, 0x07, 0xA7, 0x8B],
                [0x4D, 0x2B, 0x30, 0xC5],
            ],
        ];

        assert_eq!(super::expand(&KEY), EXPECTED_EXPANDED_KEY,);
    }
}
