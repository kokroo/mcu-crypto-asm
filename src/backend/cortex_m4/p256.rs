//! High-performance P-256 implementation transplanted from Emil Lenngren's
//! hand-crafted Cortex-M4 assembly suite.
//!
//! Provides:
//! - 31-doubling 2-table precomputed comb for base-point scalar multiplication (~396k cycles)
//! - 63-doubling signed odd recoding for variable-base scalar multiplication (~550k cycles)
//! - Bernstein-Yang constant-time modular inversion (`mod_n_inv`) (~15k cycles)
//! - Fast ECDSA signing (~430k cycles)
//! - Fast ECDSA verification via sliding window and projective coordinate check (~1.2M cycles)

use crate::ecdh::Error as EcdhError;
use crate::ecdsa::Error as EcdsaError;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FGInteger {
    pub flip_sign: i32,
    pub signed_value: [u32; 9],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct XYInteger {
    pub flip_sign: i32,
    pub value: [u32; 8],
}

extern "C" {
    pub fn emill_p256_mul_mont(out: *mut u32, a: *const u32, b: *const u32);
    pub fn emill_p256_sqr_mont(out: *mut u32, a: *const u32);
    pub fn emill_p256_add_mod(out: *mut u32, a: *const u32, b: *const u32);
    pub fn emill_p256_sub_mod(out: *mut u32, a: *const u32, b: *const u32);
    pub fn emill_p256_modinv_p(out: *mut u32, in_: *const u32);

    pub fn P256_to_montgomery(out: *mut u32, in_: *const u32);
    pub fn P256_from_montgomery(out: *mut u32, in_: *const u32);
    pub fn P256_check_range_p(a: *const u32) -> u32;
    pub fn P256_check_range_n(a: *const u32) -> u32;

    pub fn P256_reduce_mod_n_32bytes(res: *mut u32, a: *const u32);
    pub fn P256_add_mod_n(res: *mut u32, a: *const u32, b: *const u32);
    pub fn P256_mul_mod_n(res: *mut u32, a: *const u32, b: *const u32);

    pub fn P256_divsteps2_31(delta: i32, f: u32, g: u32, matrix: *mut u32) -> i32;
    pub fn P256_matrix_mul_fg_9(a: u32, b: u32, fg: *const FGInteger, res: *mut FGInteger);
    pub fn P256_matrix_mul_mod_n(a: u32, b: u32, xy: *const XYInteger, res: *mut XYInteger);

    pub static P256_order: [u32; 9];

    pub fn P256_point_is_on_curve(x_mont: *const u32, y_mont: *const u32) -> u32;
    pub fn P256_decompress_point(y: *mut u32, x: *const u32, y_parity: u32) -> u32;
    pub fn P256_jacobian_to_affine(out_x: *mut u32, out_y: *mut u32, in_j: *const u32);
    pub fn P256_double_j(out: *mut u32, in_: *const u32);
    pub fn P256_add_sub_j(p1: *mut u32, p2: *const u32, is_sub: u32, p2_is_affine: u32);
    pub fn P256_verify_last_step(r: *const u32, j: *const u32) -> u32;
    pub fn P256_select_point(output: *mut u32, table: *const u32, num_coordinates: u32, index: u32);
    pub fn P256_negate_mod_p_if(out: *mut u32, in_: *const u32, should_negate: u32);
    pub fn P256_negate_mod_n_if(out: *mut u32, in_: *const u32, should_negate: u32);
}

pub const ONE_MONTGOMERY: [u32; 8] = [1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0];

/// Table containing 1G, 3G, 5G, ... 15G in affine coordinates in montgomery form
#[repr(C, align(8))]
pub struct AlignedTable<T>(pub T);

pub static P256_BASEPOINT_PRECOMP: AlignedTable<[[[u32; 8]; 2]; 8]> = AlignedTable([
    [
        [
            0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b, 0xa53755c6,
            0x18905f76,
        ],
        [
            0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688, 0x25885d85,
            0x8571ff18,
        ],
    ],
    [
        [
            0x4eebc127, 0xffac3f90, 0x87d81fb, 0xb027f84a, 0x87cbbc98, 0x66ad77dd, 0xb6ff747e,
            0x26936a3f,
        ],
        [
            0xc983a7eb, 0xb04c5c1f, 0x861fe1a, 0x583e47ad, 0x1a2ee98e, 0x78820831, 0xe587cc07,
            0xd5f06a29,
        ],
    ],
    [
        [
            0xc45c61f5, 0xbe1b8aae, 0x94b9537d, 0x90ec649a, 0xd076c20c, 0x941cb5aa, 0x890523c8,
            0xc9079605,
        ],
        [
            0xe7ba4f10, 0xeb309b4a, 0xe5eb882b, 0x73c568ef, 0x7e7a1f68, 0x3540a987, 0x2dd1e916,
            0x73a076bb,
        ],
    ],
    [
        [
            0xa0173b4f, 0x746354e, 0xd23c00f7, 0x2bd20213, 0xc23bb08, 0xf43eaab5, 0xc3123e03,
            0x13ba5119,
        ],
        [
            0x3f5b9d4d, 0x2847d030, 0x5da67bdd, 0x6742f2f2, 0x77c94195, 0xef933bdc, 0x6e240867,
            0xeaedd915,
        ],
    ],
    [
        [
            0x264e20e8, 0x75c96e8f, 0x59a7a841, 0xabe6bfed, 0x44c8eb00, 0x2cc09c04, 0xf0c4e16b,
            0xe05b3080,
        ],
        [
            0xa45f3314, 0x1eb7777a, 0xce5d45e3, 0x56af7bed, 0x88b12f1a, 0x2b6e019a, 0xfd835f9b,
            0x86659cd,
        ],
    ],
    [
        [
            0x6245e404, 0xea7d260a, 0x6e7fdfe0, 0x9de40795, 0x8dac1ab5, 0x1ff3a415, 0x649c9073,
            0x3e7090f1,
        ],
        [
            0x2b944e88, 0x1a768561, 0xe57f61c8, 0x250f939e, 0x1ead643d, 0xc0daa89, 0xe125b88e,
            0x68930023,
        ],
    ],
    [
        [
            0x4b2ed709, 0xccc42563, 0x856fd30d, 0xe356769, 0x559e9811, 0xbcbcd43f, 0x5395b759,
            0x738477ac,
        ],
        [
            0xc00ee17f, 0x35752b90, 0x742ed2e3, 0x68748390, 0xbd1f5bc1, 0x7cd06422, 0xc9e7b797,
            0xfbc08769,
        ],
    ],
    [
        [
            0xbc60055b, 0x72bcd8b7, 0x56e27e4b, 0x3cc23ee, 0xe4819370, 0xee337424, 0xad3da09,
            0xe2aa0e43,
        ],
        [
            0x6383c45d, 0x40b8524f, 0x42a41b25, 0xd7663554, 0x778a4797, 0x64efa6de, 0x7079adf4,
            0x2042170a,
        ],
    ],
]);

/// Two tables, 8 points each in affine coordinates in montgomery form.
/// Table 0: (2^192 +/- 2^128 +/- 2^64 +/- 1)G
/// Table 1: same points multiplied by 2^32
pub static P256_BASEPOINT_PRECOMP2: AlignedTable<[[[[u32; 8]; 2]; 8]; 2]> = AlignedTable([
    [
        [
            [
                0x670844e0, 0x52d8a7c9, 0xef68a29d, 0xe33bdc, 0x4bdb7361, 0xf3d2848, 0x91c5304d,
                0x5222c821,
            ],
            [
                0xdf73fc25, 0xea6d2944, 0x255c81b, 0xa04c0f55, 0xefe488a8, 0x29acdc97, 0x80a560de,
                0xbe2e158f,
            ],
        ],
        [
            [
                0x2b13e673, 0xfc8511ee, 0xd103ed24, 0xffc58dee, 0xea7e99b8, 0x1022523a, 0x4afc8a17,
                0x8f43ea39,
            ],
            [
                0xc5f33d0b, 0x8f4e2dbc, 0xd0aa1681, 0x3bc099fa, 0x79ff9df1, 0xffbb7b41, 0xd58b57c4,
                0x180de09d,
            ],
        ],
        [
            [
                0x8bd1cda5, 0x56430752, 0x8e05eda5, 0x1807577f, 0x956896e9, 0x99c699b, 0xf1f0efb5,
                0x83d6093d,
            ],
            [
                0xed97061c, 0xef5af17e, 0x30d4c3c, 0x35b977b8, 0x49229439, 0x81fa75a2, 0xa0b6d35d,
                0xf5a22070,
            ],
        ],
        [
            [
                0x74f81cf1, 0x814c5365, 0x120065b, 0xe30baff7, 0x15132621, 0x80ae1256, 0x36a80788,
                0x16d2b8cb,
            ],
            [
                0xecc50bca, 0x33d14697, 0x17aedd21, 0x19a9dfb0, 0xedc3f766, 0x523fbcc7, 0xb2cf5afd,
                0x9c4de6dd,
            ],
        ],
        [
            [
                0xcf0d9f6d, 0x5305a9e6, 0x81a9b021, 0x5839172f, 0x75c687cf, 0xcca7a4dd, 0x844be22f,
                0x36d59b3e,
            ],
            [
                0x111a53e9, 0xcace7e62, 0xf063f3a1, 0x91c843d4, 0xda812da, 0xbf77e5f0, 0x437f3176,
                0xe64af9c,
            ],
        ],
        [
            [
                0xcf07517d, 0xdbd568bb, 0xba6830b9, 0x2f1afba2, 0xe6c4c2a6, 0x15b6807c, 0xe4966aef,
                0x91c7eabc,
            ],
            [
                0xd6b2b6e6, 0x716dea1b, 0x19f85b4b, 0x248c43d1, 0x4a315e2a, 0x16dcfd60, 0xc72b3d0b,
                0x15fdd303,
            ],
        ],
        [
            [
                0x42b7dfd5, 0xe40bf9f4, 0x2d934f2a, 0x673689f3, 0x30a6f50b, 0x8314beb4, 0x976ec64e,
                0xd17af2bc,
            ],
            [
                0x1ee7ddf1, 0x39f66c4f, 0x68ea373c, 0x7f68e18b, 0x53d0b186, 0x5166c1f2, 0x7be58f14,
                0x95dda601,
            ],
        ],
        [
            [
                0x42913074, 0xd5ae356, 0x48a542b1, 0x55491b27, 0xb310732a, 0x469ca665, 0x5f1a4cc1,
                0x29591d52,
            ],
            [
                0xb84f983f, 0xe76f5b6b, 0x9f5f84e1, 0xbe7eef41, 0x80baa189, 0x1200d496, 0x18ef332c,
                0x6376551f,
            ],
        ],
    ],
    [
        [
            [
                0x7c4e54f5, 0xb9e5cbc0, 0xe1410e34, 0xc53a1a17, 0xec454425, 0x3e199130, 0x1700902e,
                0xb029c97e,
            ],
            [
                0x786423b6, 0x2de66e11, 0xb41a95be, 0x262dc914, 0x451b683, 0x51766abd, 0x85bb6fb1,
                0x55ad5f34,
            ],
        ],
        [
            [
                0x9066cb79, 0x74f4f1c, 0x30c8b94e, 0x1ab31bd6, 0xd74275b3, 0x6d3f012f, 0x9ddcce40,
                0xa214d0b1,
            ],
            [
                0xd165050a, 0x24aedf74, 0xe0e5dc3e, 0x95f17ece, 0xd9224456, 0x6ada9cda, 0x2dd60eea,
                0x1fadb2d1,
            ],
        ],
        [
            [
                0xe20cfb9b, 0xa3d83091, 0xba76e0cb, 0xae79c975, 0xc8858a6e, 0xa5f2a588, 0x874a3168,
                0xe897a5f4,
            ],
            [
                0x7d48f096, 0xf6c1ef40, 0xc35b132c, 0x1f9c516b, 0x53c479fd, 0xe1040f91, 0x9df06743,
                0x60e881f,
            ],
        ],
        [
            [
                0x52a90e51, 0x9e0ad72, 0x38c50a96, 0xb7e66ea3, 0x7d997770, 0xab32ad05, 0x445671cb,
                0xceaffe2,
            ],
            [
                0x5d37cc99, 0xdfbe753c, 0xe0fea2d5, 0x95d068cc, 0x4dd77cb6, 0x1e37cdda, 0x55530688,
                0x88c5a4bb,
            ],
        ],
        [
            [
                0xc7744f1, 0x3413f033, 0xbc816702, 0x23c05c89, 0x1192b5ac, 0x2322ee9a, 0x373180bb,
                0xc1636a0,
            ],
            [
                0xbdde0207, 0xfe2f3d4, 0xc23578d8, 0xe1a093a, 0xc888ead, 0x6e5f0d1, 0x52a2b660,
                0x9ca285a5,
            ],
        ],
        [
            [
                0xce923964, 0xdae76995, 0xa34c7993, 0xcc96493a, 0xea73d9e7, 0xd19b5144, 0x311e6e34,
                0x4a5c263,
            ],
            [
                0xd9a2a443, 0x7db5b32b, 0x2cfd960c, 0x3754bd33, 0xa430f15, 0xc5bcc98, 0xd9a94574,
                0x5651201f,
            ],
        ],
        [
            [
                0xfc0418fe, 0xebdd8921, 0x34e20036, 0x37015b39, 0xdf03a353, 0xcf4fcd8f, 0xf12cab16,
                0xdc2de6e1,
            ],
            [
                0xd071df14, 0x9c17cc1a, 0x63415530, 0xd7c5e6a3, 0x68f3fb1e, 0xb5301660, 0x18269301,
                0xb5f70bc9,
            ],
        ],
        [
            [
                0x79ec1a0f, 0x2d8daefd, 0xceb39c97, 0x3bbcd6fd, 0x58f61a95, 0xf5575ffc, 0xadf7b420,
                0xdbd986c4,
            ],
            [
                0x15f39eb7, 0x81aa8814, 0xb98d976c, 0x6ee2fcf5, 0xcf2f717d, 0x5465475d, 0x6860bbd0,
                0x8e24d3c4,
            ],
        ],
    ],
]);

#[inline(always)]
fn get_bit(arr: &[u32; 8], i: usize) -> u32 {
    (arr[i / 32] >> (i % 32)) & 1
}

#[inline(always)]
fn abs_int(a: i8) -> u32 {
    let a_u = a as i32 as u32;
    let mask = (a_u >> 31).wrapping_neg();
    let result = ((-a as i32 as u32) & mask) | ((a as i32 as u32) & (!mask & 0xf));
    result
}

/// Constant-time inversion modulo n via 24 iterations of 31 divsteps.
pub fn mod_n_inv(out: &mut [u32; 8], in_: &[u32; 8]) {
    #[derive(Clone, Copy)]
    struct State {
        fg: [FGInteger; 2],
        xy: [XYInteger; 2],
    }

    let mut state: [State; 2] = [
        State {
            fg: [
                FGInteger {
                    flip_sign: 0,
                    signed_value: unsafe { P256_order },
                },
                FGInteger {
                    flip_sign: 0,
                    signed_value: [
                        in_[0], in_[1], in_[2], in_[3], in_[4], in_[5], in_[6], in_[7], 0,
                    ],
                },
            ],
            xy: [
                XYInteger {
                    flip_sign: 0,
                    value: [0; 8],
                },
                XYInteger {
                    flip_sign: 0,
                    value: [1 << 24, 0, 0, 0, 0, 0, 0, 0],
                },
            ],
        },
        State {
            fg: [
                FGInteger {
                    flip_sign: 0,
                    signed_value: [0; 9],
                },
                FGInteger {
                    flip_sign: 0,
                    signed_value: [0; 9],
                },
            ],
            xy: [
                XYInteger {
                    flip_sign: 0,
                    value: [0; 8],
                },
                XYInteger {
                    flip_sign: 0,
                    value: [0; 8],
                },
            ],
        },
    ];

    let mut delta = 1i32;
    for i in 0..24 {
        let cur = i % 2;
        let next = (i + 1) % 2;
        let mut matrix = [0u32; 4];

        let negate_f = state[cur].fg[0].flip_sign as u32;
        let negate_g = state[cur].fg[1].flip_sign as u32;
        let f0 = (state[cur].fg[0].signed_value[0] ^ negate_f).wrapping_sub(negate_f);
        let g0 = (state[cur].fg[1].signed_value[0] ^ negate_g).wrapping_sub(negate_g);

        delta = unsafe { P256_divsteps2_31(delta, f0, g0, matrix.as_mut_ptr()) };

        unsafe {
            P256_matrix_mul_fg_9(
                matrix[0],
                matrix[1],
                state[cur].fg.as_ptr(),
                &mut state[next].fg[0],
            );
            P256_matrix_mul_fg_9(
                matrix[2],
                matrix[3],
                state[cur].fg.as_ptr(),
                &mut state[next].fg[1],
            );
            P256_matrix_mul_mod_n(
                matrix[0],
                matrix[1],
                state[cur].xy.as_ptr(),
                &mut state[next].xy[0],
            );
            P256_matrix_mul_mod_n(
                matrix[2],
                matrix[3],
                state[cur].xy.as_ptr(),
                &mut state[next].xy[1],
            );
        }
    }

    let should_neg = ((state[0].xy[0].flip_sign
        ^ state[0].fg[0].flip_sign
        ^ (state[0].fg[0].signed_value[8] as i32))
        & 1) as u32;
    unsafe {
        P256_negate_mod_n_if(out.as_mut_ptr(), state[0].xy[0].value.as_ptr(), should_neg);
    }
}

/// Constant-time fixed-base scalar multiplication: `scalar * G`.
/// Returns output affine coordinates in Montgomery form.
pub fn scalarmult_fixed_base(
    out_mont_x: &mut [u32; 8],
    out_mont_y: &mut [u32; 8],
    scalar: &[u32; 8],
) {
    let mut scalar2 = [0u32; 8];
    let even = (scalar[0] & 1) ^ 1;
    unsafe {
        P256_negate_mod_n_if(scalar2.as_mut_ptr(), scalar.as_ptr(), even);
    }

    let mut current_point = [[0u32; 8]; 3];
    let mut selected_point = [[0u32; 8]; 2];

    for i in (0..32).rev() {
        {
            let mask = get_bit(&scalar2, i + 32 + 1)
                | (get_bit(&scalar2, i + 64 + 32 + 1) << 1)
                | (get_bit(&scalar2, i + 2 * 64 + 32 + 1) << 2);
            if i == 31 {
                unsafe {
                    P256_select_point(
                        current_point.as_mut_ptr() as *mut u32,
                        P256_BASEPOINT_PRECOMP2.0[1].as_ptr() as *const u32,
                        2,
                        mask,
                    );
                }
                current_point[2] = ONE_MONTGOMERY;
            } else {
                unsafe {
                    P256_double_j(
                        current_point.as_mut_ptr() as *mut u32,
                        current_point.as_ptr() as *const u32,
                    );
                }
                let sign = get_bit(&scalar2, i + 3 * 64 + 32 + 1).wrapping_sub(1);
                let mask = (mask ^ sign) & 7;
                unsafe {
                    P256_select_point(
                        selected_point.as_mut_ptr() as *mut u32,
                        P256_BASEPOINT_PRECOMP2.0[1].as_ptr() as *const u32,
                        2,
                        mask,
                    );
                    P256_negate_mod_p_if(
                        selected_point[1].as_mut_ptr(),
                        selected_point[1].as_ptr(),
                        sign & 1,
                    );
                    P256_add_sub_j(
                        current_point.as_mut_ptr() as *mut u32,
                        selected_point.as_ptr() as *const u32,
                        0,
                        1,
                    );
                }
            }
        }
        {
            let mask = get_bit(&scalar2, i + 1)
                | (get_bit(&scalar2, i + 64 + 1) << 1)
                | (get_bit(&scalar2, i + 2 * 64 + 1) << 2);
            let sign = get_bit(&scalar2, i + 3 * 64 + 1).wrapping_sub(1);
            let mask = (mask ^ sign) & 7;
            unsafe {
                P256_select_point(
                    selected_point.as_mut_ptr() as *mut u32,
                    P256_BASEPOINT_PRECOMP2.0[0].as_ptr() as *const u32,
                    2,
                    mask,
                );
                P256_negate_mod_p_if(
                    selected_point[1].as_mut_ptr(),
                    selected_point[1].as_ptr(),
                    sign & 1,
                );
                P256_add_sub_j(
                    current_point.as_mut_ptr() as *mut u32,
                    selected_point.as_ptr() as *const u32,
                    0,
                    1,
                );
            }
        }
    }

    unsafe {
        P256_jacobian_to_affine(
            out_mont_x.as_mut_ptr(),
            out_mont_y.as_mut_ptr(),
            current_point.as_ptr() as *const u32,
        );
        P256_negate_mod_p_if(out_mont_y.as_mut_ptr(), out_mont_y.as_ptr(), even);
    }
}

/// Batch invert Z coordinates and convert 7 Jacobian points (indices 1..8) to affine coordinates in Montgomery form.
pub fn batch_jacobian_to_affine_7(out_affine: &mut [[[u32; 8]; 2]], in_j: &[[[u32; 8]; 3]]) {
    debug_assert_eq!(out_affine.len(), 7);
    debug_assert_eq!(in_j.len(), 7);
    let mut c = [[0u32; 8]; 7];
    c[0] = in_j[0][2];
    unsafe {
        for i in 1..7 {
            emill_p256_mul_mont(c[i].as_mut_ptr(), c[i - 1].as_ptr(), in_j[i][2].as_ptr());
        }
        let mut inv = [0u32; 8];
        emill_p256_modinv_p(inv.as_mut_ptr(), c[6].as_ptr());

        let mut z_inv = [[0u32; 8]; 7];
        for i in (1..7).rev() {
            emill_p256_mul_mont(z_inv[i].as_mut_ptr(), inv.as_ptr(), c[i - 1].as_ptr());
            let mut next_inv = [0u32; 8];
            emill_p256_mul_mont(next_inv.as_mut_ptr(), inv.as_ptr(), in_j[i][2].as_ptr());
            inv = next_inv;
        }
        z_inv[0] = inv;

        for i in 0..7 {
            let mut z_inv2 = [0u32; 8];
            let mut z_inv3 = [0u32; 8];
            emill_p256_sqr_mont(z_inv2.as_mut_ptr(), z_inv[i].as_ptr());
            emill_p256_mul_mont(z_inv3.as_mut_ptr(), z_inv2.as_ptr(), z_inv[i].as_ptr());
            emill_p256_mul_mont(
                out_affine[i][0].as_mut_ptr(),
                in_j[i][0].as_ptr(),
                z_inv2.as_ptr(),
            );
            emill_p256_mul_mont(
                out_affine[i][1].as_mut_ptr(),
                in_j[i][1].as_ptr(),
                z_inv3.as_ptr(),
            );
        }
    }
}

/// Constant-time variable-base scalar multiplication: `scalar * P`.
/// Inputs and outputs are in Montgomery form.
pub fn scalarmult_variable_base(
    out_mont_x: &mut [u32; 8],
    out_mont_y: &mut [u32; 8],
    in_mont_x: &[u32; 8],
    in_mont_y: &[u32; 8],
    scalar: &[u32; 8],
) {
    let mut scalar2 = [0u32; 8];
    let mut e = [0i8; 64];

    let even = (scalar[0] & 1) ^ 1;
    unsafe {
        P256_negate_mod_n_if(scalar2.as_mut_ptr(), scalar.as_ptr(), even);
    }

    e[0] = (scalar2[0] & 0xf) as i8;
    for i in 1..64 {
        e[i] = ((scalar2[i / 8] >> ((i % 8) * 4)) & 0xf) as i8;
        e[i - 1] = e[i - 1].wrapping_sub((((e[i] as u8 & 1) ^ 1) << 4) as i8);
        e[i] |= 1;
    }

    let mut table = [[[0u32; 8]; 3]; 8];
    table[0][0] = *in_mont_x;
    table[0][1] = *in_mont_y;
    table[0][2] = ONE_MONTGOMERY;

    unsafe {
        P256_double_j(
            table[7].as_mut_ptr() as *mut u32,
            table[0].as_ptr() as *const u32,
        );
        for i in 1..8 {
            table[i] = table[7];
            P256_add_sub_j(
                table[i].as_mut_ptr() as *mut u32,
                table[i - 1].as_ptr() as *const u32,
                0,
                if i == 1 { 1 } else { 0 },
            );
        }
    }

    let mut affine_table = [[[0u32; 8]; 2]; 8];
    affine_table[0][0] = *in_mont_x;
    affine_table[0][1] = *in_mont_y;
    batch_jacobian_to_affine_7(&mut affine_table[1..8], &table[1..8]);

    let mut current_point = [[0u32; 8]; 3];
    unsafe {
        P256_select_point(
            current_point.as_mut_ptr() as *mut u32,
            affine_table.as_ptr() as *const u32,
            2,
            (e[63] as u32) >> 1,
        );
    }
    current_point[2] = ONE_MONTGOMERY;

    for i in (0..63).rev() {
        unsafe {
            for _ in 0..4 {
                P256_double_j(
                    current_point.as_mut_ptr() as *mut u32,
                    current_point.as_ptr() as *const u32,
                );
            }
            let mut selected_point = [[0u32; 8]; 2];
            let abs_val = abs_int(e[i]);
            P256_select_point(
                selected_point.as_mut_ptr() as *mut u32,
                affine_table.as_ptr() as *const u32,
                2,
                abs_val >> 1,
            );
            P256_negate_mod_p_if(
                selected_point[1].as_mut_ptr(),
                selected_point[1].as_ptr(),
                ((e[i] as u8) >> 7) as u32,
            );
            P256_add_sub_j(
                current_point.as_mut_ptr() as *mut u32,
                selected_point.as_ptr() as *const u32,
                0,
                1,
            );
        }
    }

    unsafe {
        P256_jacobian_to_affine(
            out_mont_x.as_mut_ptr(),
            out_mont_y.as_mut_ptr(),
            current_point.as_ptr() as *const u32,
        );
        P256_negate_mod_p_if(out_mont_y.as_mut_ptr(), out_mont_y.as_ptr(), even);
    }
}

/// Convert hash to 256-bit little-endian integer z.
pub fn hash_to_z(z: &mut [u32; 8], hash: &[u8]) {
    *z = [0; 8];
    let len = hash.len().min(32);
    let bytes = unsafe { core::slice::from_raw_parts_mut(z.as_mut_ptr() as *mut u8, 32) };
    for i in 0..len {
        bytes[i] = hash[len - 1 - i];
    }
}

/// Big-endian bytes -> little-endian 32-bit limbs.
#[inline(always)]
pub fn be_to_limbs(bytes: &[u8], out: &mut [u32; 8]) -> Result<(), EcdhError> {
    if bytes.len() != 32 {
        return Err(EcdhError::BadLength);
    }
    for i in 0..8 {
        let off = (7 - i) * 4;
        out[i] = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
    Ok(())
}

/// Little-endian 32-bit limbs -> big-endian bytes.
#[inline(always)]
pub fn limbs_to_be(limbs: &[u32; 8], out: &mut [u8]) {
    for i in 0..8 {
        let off = (7 - i) * 4;
        out[off..off + 4].copy_from_slice(&limbs[i].to_be_bytes());
    }
}

/// SEC1 public key derivation from private scalar.
pub fn derive_public_key(secret: &[u8], out: &mut [u8]) -> Result<(), EcdhError> {
    if out.len() != 65 {
        return Err(EcdhError::BadLength);
    }
    let mut k = [0u32; 8];
    be_to_limbs(secret, &mut k)?;
    if unsafe { P256_check_range_n(k.as_ptr()) } == 0 {
        return Err(EcdhError::BadScalar);
    }

    let mut px_mont = [0u32; 8];
    let mut py_mont = [0u32; 8];
    scalarmult_fixed_base(&mut px_mont, &mut py_mont, &k);

    let mut px = [0u32; 8];
    let mut py = [0u32; 8];
    unsafe {
        P256_from_montgomery(px.as_mut_ptr(), px_mont.as_ptr());
        P256_from_montgomery(py.as_mut_ptr(), py_mont.as_ptr());
    }

    out[0] = 0x04;
    limbs_to_be(&px, &mut out[1..33]);
    limbs_to_be(&py, &mut out[33..65]);
    Ok(())
}

/// SEC1 compressed public key derivation from private scalar.
pub fn derive_public_key_compressed(secret: &[u8], out: &mut [u8]) -> Result<(), EcdhError> {
    if out.len() != 33 {
        return Err(EcdhError::BadLength);
    }
    let mut k = [0u32; 8];
    be_to_limbs(secret, &mut k)?;
    if unsafe { P256_check_range_n(k.as_ptr()) } == 0 {
        return Err(EcdhError::BadScalar);
    }

    let mut px_mont = [0u32; 8];
    let mut py_mont = [0u32; 8];
    scalarmult_fixed_base(&mut px_mont, &mut py_mont, &k);

    let mut px = [0u32; 8];
    let mut py = [0u32; 8];
    unsafe {
        P256_from_montgomery(px.as_mut_ptr(), px_mont.as_ptr());
        P256_from_montgomery(py.as_mut_ptr(), py_mont.as_ptr());
    }

    out[0] = if (py[0] & 1) == 1 { 0x03 } else { 0x02 };
    limbs_to_be(&px, &mut out[1..33]);
    Ok(())
}

/// Decode public key into affine (x, y) limbs in Montgomery form.
pub fn decode_public_key_mont(
    pk: &[u8],
    out_x_mont: &mut [u32; 8],
    out_y_mont: &mut [u32; 8],
) -> Result<(), EcdhError> {
    let mut x = [0u32; 8];
    let mut y = [0u32; 8];

    if pk.len() == 65 && pk[0] == 0x04 {
        be_to_limbs(&pk[1..33], &mut x)?;
        be_to_limbs(&pk[33..65], &mut y)?;
    } else if pk.len() == 33 && (pk[0] == 0x02 || pk[0] == 0x03) {
        be_to_limbs(&pk[1..33], &mut x)?;
        let y_parity = (pk[0] == 0x03) as u32;
        if unsafe { P256_decompress_point(y.as_mut_ptr(), x.as_ptr(), y_parity) } == 0 {
            return Err(EcdhError::BadPoint);
        }
    } else {
        return Err(EcdhError::BadLength);
    }

    if unsafe { P256_check_range_p(x.as_ptr()) == 0 || P256_check_range_p(y.as_ptr()) == 0 } {
        return Err(EcdhError::BadPoint);
    }

    unsafe {
        P256_to_montgomery(out_x_mont.as_mut_ptr(), x.as_ptr());
        P256_to_montgomery(out_y_mont.as_mut_ptr(), y.as_ptr());
        if P256_point_is_on_curve(out_x_mont.as_ptr(), out_y_mont.as_ptr()) == 0 {
            return Err(EcdhError::BadPoint);
        }
    }
    Ok(())
}

/// ECDH shared secret: computes `x` coordinate of `scalar * peer`.
pub fn ecdh_shared_secret(secret: &[u8], peer: &[u8], out: &mut [u8]) -> Result<(), EcdhError> {
    if out.len() != 32 {
        return Err(EcdhError::BadLength);
    }
    let mut k = [0u32; 8];
    be_to_limbs(secret, &mut k)?;
    if unsafe { P256_check_range_n(k.as_ptr()) } == 0 {
        return Err(EcdhError::BadScalar);
    }

    let mut qx_mont = [0u32; 8];
    let mut qy_mont = [0u32; 8];
    decode_public_key_mont(peer, &mut qx_mont, &mut qy_mont)?;

    let mut sx_mont = [0u32; 8];
    let mut sy_mont = [0u32; 8];
    scalarmult_variable_base(&mut sx_mont, &mut sy_mont, &qx_mont, &qy_mont, &k);

    let mut sx = [0u32; 8];
    unsafe {
        P256_from_montgomery(sx.as_mut_ptr(), sx_mont.as_ptr());
    }
    limbs_to_be(&sx, out);
    Ok(())
}

/// Decompress point from x-coordinate limbs and parity bit.
pub fn decompress_point(x_limbs: &[u32; 8], y_is_odd: bool) -> Option<[u32; 8]> {
    let mut y = [0u32; 8];
    if unsafe { P256_check_range_p(x_limbs.as_ptr()) } == 0 {
        return None;
    }
    let ok = unsafe { P256_decompress_point(y.as_mut_ptr(), x_limbs.as_ptr(), y_is_odd as u32) };
    if ok != 0 {
        Some(y)
    } else {
        None
    }
}

/// Fast constant-time ECDSA signing.
pub fn sign(
    sk: &[u8],
    msg_hash: &[u8],
    k_nonce: &[u8],
    out_r: &mut [u8],
    out_s: &mut [u8],
) -> Result<(), EcdsaError> {
    if sk.len() != 32 || k_nonce.len() != 32 || out_r.len() != 32 || out_s.len() != 32 {
        return Err(EcdsaError::BadLength);
    }

    let mut d = [0u32; 8];
    let mut k = [0u32; 8];
    be_to_limbs(sk, &mut d).map_err(|_| EcdsaError::BadLength)?;
    be_to_limbs(k_nonce, &mut k).map_err(|_| EcdsaError::BadLength)?;

    if unsafe { P256_check_range_n(d.as_ptr()) } == 0
        || unsafe { P256_check_range_n(k.as_ptr()) } == 0
    {
        return Err(EcdsaError::BadScalar);
    }

    // Step 1: k * G and k_inv
    let mut rx_mont = [0u32; 8];
    let mut ry_mont = [0u32; 8];
    scalarmult_fixed_base(&mut rx_mont, &mut ry_mont, &k);

    let mut k_inv = [0u32; 8];
    mod_n_inv(&mut k_inv, &k);

    let mut r = [0u32; 8];
    unsafe {
        P256_from_montgomery(r.as_mut_ptr(), rx_mont.as_ptr());
        P256_reduce_mod_n_32bytes(r.as_mut_ptr(), r.as_ptr());
    }

    let mut r_nz = 0u32;
    for &v in r.iter() {
        r_nz |= v;
    }
    if r_nz == 0 {
        return Err(EcdsaError::BadScalar);
    }

    // Step 2: s = k_inv * (z + r * d) mod n
    let mut z = [0u32; 8];
    hash_to_z(&mut z, msg_hash);

    let mut rd = [0u32; 8];
    let mut z_plus_rd = [0u32; 8];
    let mut s = [0u32; 8];
    unsafe {
        P256_mul_mod_n(rd.as_mut_ptr(), r.as_ptr(), d.as_ptr());
        P256_add_mod_n(z_plus_rd.as_mut_ptr(), z.as_ptr(), rd.as_ptr());
        P256_mul_mod_n(s.as_mut_ptr(), k_inv.as_ptr(), z_plus_rd.as_ptr());
    }

    let mut s_nz = 0u32;
    for &v in s.iter() {
        s_nz |= v;
    }
    if s_nz == 0 {
        return Err(EcdsaError::BadScalar);
    }

    limbs_to_be(&r, out_r);
    limbs_to_be(&s, out_s);
    Ok(())
}

/// Sliding window recoding: each r[i] is in {-15, -13, ..., 13, 15} or 0.
pub fn slide_257(r: &mut [i8; 257], a: &[u8; 32]) {
    for i in 0..256 {
        r[i] = ((a[i >> 3] >> (i & 7)) & 1) as i8;
    }
    r[256] = 0;

    let mut i = 0;
    while i < 256 {
        if r[i] != 0 {
            let mut b = 1;
            while b <= 4 && i + b < 256 {
                if r[i + b] != 0 {
                    let term = (r[i + b] as i32) << b;
                    let sum = (r[i] as i32) + term;
                    let diff = (r[i] as i32) - term;
                    if sum <= 15 {
                        r[i] = sum as i8;
                        r[i + b] = 0;
                    } else if diff >= -15 {
                        r[i] = diff as i8;
                        loop {
                            r[i + b] = 0;
                            b += 1;
                            if r[i + b] == 0 {
                                r[i + b] = 1;
                                b -= 1;
                                break;
                            }
                        }
                    } else {
                        break;
                    }
                }
                b += 1;
            }
        }
        i += 1;
    }
}

/// Fast ECDSA verification via sliding window double scalar multiplication
/// and projective coordinate checking (`P256_verify_last_step`).
pub fn verify(
    pk: &[u8],
    msg_hash: &[u8],
    r_bytes: &[u8],
    s_bytes: &[u8],
) -> Result<(), EcdsaError> {
    if r_bytes.len() != 32 || s_bytes.len() != 32 {
        return Err(EcdsaError::BadLength);
    }

    let mut r = [0u32; 8];
    let mut s = [0u32; 8];
    be_to_limbs(r_bytes, &mut r).map_err(|_| EcdsaError::BadLength)?;
    be_to_limbs(s_bytes, &mut s).map_err(|_| EcdsaError::BadLength)?;

    if unsafe { P256_check_range_n(r.as_ptr()) } == 0
        || unsafe { P256_check_range_n(s.as_ptr()) } == 0
    {
        return Err(EcdsaError::BadSignature);
    }

    let mut qx_mont = [0u32; 8];
    let mut qy_mont = [0u32; 8];
    decode_public_key_mont(pk, &mut qx_mont, &mut qy_mont).map_err(|e| match e {
        EcdhError::BadLength => EcdsaError::BadLength,
        _ => EcdsaError::BadPoint,
    })?;

    // Create table of Q, 3Q, 5Q, ... 15Q
    let mut pk_table = [[[0u32; 8]; 3]; 8];
    pk_table[0][0] = qx_mont;
    pk_table[0][1] = qy_mont;
    pk_table[0][2] = ONE_MONTGOMERY;

    unsafe {
        P256_double_j(
            pk_table[7].as_mut_ptr() as *mut u32,
            pk_table[0].as_ptr() as *const u32,
        );
        for i in 1..8 {
            pk_table[i] = pk_table[7];
            P256_add_sub_j(
                pk_table[i].as_mut_ptr() as *mut u32,
                pk_table[i - 1].as_ptr() as *const u32,
                0,
                if i == 1 { 1 } else { 0 },
            );
        }
    }

    let mut z = [0u32; 8];
    hash_to_z(&mut z, msg_hash);

    let mut w = [0u32; 8];
    mod_n_inv(&mut w, &s);

    let mut u1 = [0u32; 8];
    let mut u2 = [0u32; 8];
    unsafe {
        P256_mul_mod_n(u1.as_mut_ptr(), z.as_ptr(), w.as_ptr());
        P256_mul_mod_n(u2.as_mut_ptr(), r.as_ptr(), w.as_ptr());
    }

    let u1_bytes = unsafe { core::slice::from_raw_parts(u1.as_ptr() as *const u8, 32) };
    let u2_bytes = unsafe { core::slice::from_raw_parts(u2.as_ptr() as *const u8, 32) };
    let mut slide_bp = [0i8; 257];
    let mut slide_pk = [0i8; 257];
    slide_257(&mut slide_bp, u1_bytes.try_into().unwrap());
    slide_257(&mut slide_pk, u2_bytes.try_into().unwrap());

    let mut max_i = 256;
    while max_i > 0 && slide_bp[max_i] == 0 && slide_pk[max_i] == 0 {
        max_i -= 1;
    }

    let mut cp = [[0u32; 8]; 3];

    for i in (0..=max_i).rev() {
        unsafe {
            P256_double_j(cp.as_mut_ptr() as *mut u32, cp.as_ptr() as *const u32);
            if slide_bp[i] > 0 {
                let idx = (slide_bp[i] as usize) / 2;
                P256_add_sub_j(
                    cp.as_mut_ptr() as *mut u32,
                    P256_BASEPOINT_PRECOMP.0[idx].as_ptr() as *const u32,
                    0,
                    1,
                );
            } else if slide_bp[i] < 0 {
                let idx = ((-slide_bp[i]) as usize) / 2;
                P256_add_sub_j(
                    cp.as_mut_ptr() as *mut u32,
                    P256_BASEPOINT_PRECOMP.0[idx].as_ptr() as *const u32,
                    1,
                    1,
                );
            }

            if slide_pk[i] > 0 {
                let idx = (slide_pk[i] as usize) / 2;
                P256_add_sub_j(
                    cp.as_mut_ptr() as *mut u32,
                    pk_table[idx].as_ptr() as *const u32,
                    0,
                    if idx == 0 { 1 } else { 0 },
                );
            } else if slide_pk[i] < 0 {
                let idx = ((-slide_pk[i]) as usize) / 2;
                P256_add_sub_j(
                    cp.as_mut_ptr() as *mut u32,
                    pk_table[idx].as_ptr() as *const u32,
                    1,
                    if idx == 0 { 1 } else { 0 },
                );
            }
        }
    }

    let ok = unsafe { P256_verify_last_step(r.as_ptr(), cp.as_ptr() as *const u32) };
    if ok != 0 {
        Ok(())
    } else {
        Err(EcdsaError::BadSignature)
    }
}
