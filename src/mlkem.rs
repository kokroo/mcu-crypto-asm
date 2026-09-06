//! ML-KEM (Kyber, FIPS 203) Polynomial and Number-Theoretic Transform (NTT) Arithmetic.
//!
//! Hand-written ARM Cortex-M DSP SIMD assembly acceleration for Target 1 (ARMv7E-M / ARMv8-M),
//! based on PQM4 (Junhao Huang / Kannwischer / Rijneveld / Schwabe / Stoffelen).
//!
//! Ring: $R_q = \\mathbb{Z}_q[X] / (X^{256} + 1)$, where $q = 3329$ and $n = 256$.

#![allow(clippy::needless_range_loop)]

pub const KYBER_N: usize = 256;
pub const KYBER_Q: i16 = 3329;
pub const KYBER_POLYBYTES: usize = 384;
pub const KYBER_SYMBYTES: usize = 32;

/// Barrett reduction constant: (2^26 + 3329/2) / 3329 = 20159.
pub const BARRETT_CONST: i32 = 20159;

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
use core::arch::global_asm;

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
global_asm!(include_str!("../asm/cortex_m_mlkem.S"), options(raw));

#[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
extern "C" {
    fn ntt_fast(poly: *mut i16, zetas: *const i32);
    fn invntt_fast(poly: *mut i16, zetas_inv: *const i32);
    fn asm_barrett_reduce(poly: *mut i16);
    fn asm_fromplant(poly: *mut i16);
    fn pointwise_add(r: *mut i16, a: *const i16, b: *const i16);
    fn pointwise_sub(r: *mut i16, a: *const i16, b: *const i16);
    fn basemul_asm(r: *mut i16, a: *const i16, b: *const i16, zetas: *const i32);
    fn basemul_asm_acc(r: *mut i16, a: *const i16, b: *const i16, zetas: *const i32);
    #[allow(dead_code)]
    fn basemul_asm_opt_16_32(r_tmp: *mut i32, a: *const i16, b: *const i16, a_prime: *const i16);
    #[allow(dead_code)]
    fn basemul_asm_acc_opt_32_16(r: *mut i16, a: *const i16, b: *const i16, a_prime: *const i16, r_tmp: *const i32);
}

/// Twiddle factors for forward NTT in Plantard domain (128 elements).
pub static ZETAS_ASM: [i32; 128] = [
    0x84f5c5b6_u32 as i32, 0xc666e465_u32 as i32, 0xfcec8b58_u32 as i32, 0xcb2b72d0_u32 as i32, 0x30726d5b_u32 as i32, 0x91e11612_u32 as i32, 0x41360f89_u32 as i32, 0x51aaf2da_u32 as i32,
    0x93922fd5_u32 as i32, 0x0ed77946_u32 as i32, 0x3d4a0dff_u32 as i32, 0xd63e49fb_u32 as i32, 0xfab1a391_u32 as i32, 0x2bc18ea7_u32 as i32, 0x864470e4_u32 as i32, 0x16c32c11_u32 as i32,
    0x16395e0d_u32 as i32, 0x19743224_u32 as i32, 0x014eab2e_u32 as i32, 0xd4522112_u32 as i32, 0x2cd52aae_u32 as i32, 0xcbb540d4_u32 as i32, 0xbc2c9a1c_u32 as i32, 0xfa27d58e_u32 as i32,
    0x87094e0e_u32 as i32, 0x7de29fcd_u32 as i32, 0x379942fb_u32 as i32, 0xaff27732_u32 as i32, 0x54970814_u32 as i32, 0x66f8144e_u32 as i32, 0x5c0c9c92_u32 as i32, 0xb12d72a9_u32 as i32,
    0x6c5a2074_u32 as i32, 0xccb52d24_u32 as i32, 0xfc4f0d9d_u32 as i32, 0x11eaedee_u32 as i32, 0x71811d74_u32 as i32, 0xaf19ea51_u32 as i32, 0x9e078945_u32 as i32, 0x3a22e9a0_u32 as i32,
    0xa5cbdca1_u32 as i32, 0xe7da790b_u32 as i32, 0xea8b7f1e_u32 as i32, 0xea3cc040_u32 as i32, 0x31fc27af_u32 as i32, 0x9807ff63_u32 as i32, 0x82f5ed16_u32 as i32, 0x7ef63bd5_u32 as i32,
    0xd6795921_u32 as i32, 0x8992f4b3_u32 as i32, 0x044e701f_u32 as i32, 0xc13fe765_u32 as i32, 0x3099ccc9_u32 as i32, 0x8e08c440_u32 as i32, 0x4935720b_u32 as i32, 0x7059d1b5_u32 as i32,
    0xcea1560e_u32 as i32, 0xac4184cf_u32 as i32, 0xdc518394_u32 as i32, 0x0289a6a5_u32 as i32, 0x483585bb_u32 as i32, 0xb17c3187_u32 as i32, 0xbb67bcf2_u32 as i32, 0xb7a31ad7_u32 as i32,
    0x6681f601_u32 as i32, 0x658209b1_u32 as i32, 0x934370f8_u32 as i32, 0x385e2025_u32 as i32, 0xb3b7194d_u32 as i32, 0x149bf401_u32 as i32, 0x314afa3c_u32 as i32, 0x6da8cba2_u32 as i32,
    0xb254be68_u32 as i32, 0x6e59f915_u32 as i32, 0x79cf3ed4_u32 as i32, 0xb0b7545c_u32 as i32, 0x9ca52e5f_u32 as i32, 0xf79e2ee9_u32 as i32, 0xa1074e36_u32 as i32, 0x3e0eeb29_u32 as i32,
    0x22c23fd4_u32 as i32, 0x1cd665aa_u32 as i32, 0xc4049d2f_u32 as i32, 0xa0b88f58_u32 as i32, 0x7e801d88_u32 as i32, 0x2924384b_u32 as i32, 0x6e95083b_u32 as i32, 0xdc8c92ba_u32 as i32,
    0x51bea292_u32 as i32, 0x1887f58b_u32 as i32, 0xd53e5dab_u32 as i32, 0x3a369957_u32 as i32, 0xdda02ec2_u32 as i32, 0x75f6ed02_u32 as i32, 0xb8b6b6df_u32 as i32, 0xa169bccb_u32 as i32,
    0x2b2410ec_u32 as i32, 0xbda2a4b9_u32 as i32, 0xc77a806d_u32 as i32, 0xb805896c_u32 as i32, 0xcb8de165_u32 as i32, 0xc93f49e7_u32 as i32, 0xd7a0a4e0_u32 as i32, 0x53f98a58_u32 as i32,
    0x1efd9db9_u32 as i32, 0x4ee63d0f_u32 as i32, 0xdd651f9c_u32 as i32, 0x71e38c09_u32 as i32, 0x31d4c840_u32 as i32, 0x57e58be2_u32 as i32, 0xa555be54_u32 as i32, 0xd565bd19_u32 as i32,
    0x442224c3_u32 as i32, 0x97ccf03d_u32 as i32, 0xbe402274_u32 as i32, 0xef28ae1a_u32 as i32, 0x846bf7b2_u32 as i32, 0x5d33e851_u32 as i32, 0x901c4c98_u32 as i32, 0x4f214c36_u32 as i32,
    0x3f228731_u32 as i32, 0x5e5b3410_u32 as i32, 0x45fa9df4_u32 as i32, 0xa24249ac_u32 as i32, 0xe1b38fba_u32 as i32, 0x440e750b_u32 as i32, 0xa5a47d32_u32 as i32, 0x00000000_u32 as i32,
];

/// Twiddle factors for inverse NTT (256 elements).
pub static ZETAS_INV_CT_ASM: [i32; 256] = [
    0x0013afb8_u32 as i32, 0x0013afb8_u32 as i32, 0x7b0a3a4b_u32 as i32, 0x0013afb8_u32 as i32, 0x031374a9_u32 as i32, 0x7b0a3a4b_u32 as i32, 0x39991b9c_u32 as i32, 0x0013afb8_u32 as i32,
    0xbec9f078_u32 as i32, 0x031374a9_u32 as i32, 0xcf8d92a6_u32 as i32, 0x7b0a3a4b_u32 as i32, 0x6e1ee9ef_u32 as i32, 0x39991b9c_u32 as i32, 0x34d48d31_u32 as i32, 0x0013afb8_u32 as i32,
    0x7b0a3a4b_u32 as i32, 0x0013afb8_u32 as i32, 0x031374a9_u32 as i32, 0x7b0a3a4b_u32 as i32, 0x39991b9c_u32 as i32, 0x912fe8a0_u32 as i32, 0x114d7033_u32 as i32, 0xaf7c58e6_u32 as i32,
    0xb41987e2_u32 as i32, 0x6b6de3db_u32 as i32, 0x23fd3b4b_u32 as i32, 0xc92b9a30_u32 as i32, 0x9f914399_u32 as i32, 0x79bb8f1d_u32 as i32, 0xc0dd78d0_u32 as i32, 0x68330fc4_u32 as i32,
    0xba05620d_u32 as i32, 0x10d751e7_u32 as i32, 0xa1a4cbf1_u32 as i32, 0x41bfdd8d_u32 as i32, 0x62e4b355_u32 as i32, 0x6a6df78b_u32 as i32, 0x73bc053b_u32 as i32, 0xa12eada4_u32 as i32,
    0x1560d12b_u32 as i32, 0x2f4b219b_u32 as i32, 0x5720aeb8_u32 as i32, 0x63bd4037_u32 as i32, 0xbec9f078_u32 as i32, 0x79bb8f1d_u32 as i32, 0xd43e715a_u32 as i32, 0xc0dd78d0_u32 as i32,
    0x229ae065_u32 as i32, 0x68330fc4_u32 as i32, 0x47fa7695_u32 as i32, 0xe7b3199c_u32 as i32, 0x7ebb2cae_u32 as i32, 0x33fc004f_u32 as i32, 0xcd3efb28_u32 as i32, 0x1f600c4e_u32 as i32,
    0x11d73e37_u32 as i32, 0xe701ec29_u32 as i32, 0xc9a1b87c_u32 as i32, 0xc2b5f202_u32 as i32, 0x997e0a00_u32 as i32, 0x53be7b32_u32 as i32, 0x6cbc8f09_u32 as i32, 0xfd76595c_u32 as i32,
    0x9a7df650_u32 as i32, 0x23ae7c6d_u32 as i32, 0x770a890a_u32 as i32, 0xad1a11b0_u32 as i32, 0x99a5696f_u32 as i32, 0x0c12c37b_u32 as i32, 0x01d87932_u32 as i32, 0xe2ee8b31_u32 as i32,
    0x49d2efc7_u32 as i32, 0x7545bf8f_u32 as i32, 0x031374a9_u32 as i32, 0xbec9f078_u32 as i32, 0x6e1ee9ef_u32 as i32, 0x79bb8f1d_u32 as i32, 0x054e5c70_u32 as i32, 0xd43e715a_u32 as i32,
    0x29c1b606_u32 as i32, 0x615af901_u32 as i32, 0x82a72e38_u32 as i32, 0x3636e816_u32 as i32, 0x6a1f38ad_u32 as i32, 0x7894435e_u32 as i32, 0x94e0db03_u32 as i32, 0xd72a8694_u32 as i32,
    0x43223872_u32 as i32, 0x054e5c70_u32 as i32, 0x225fd13f_u32 as i32, 0xd6dbc7b6_u32 as i32, 0x47494922_u32 as i32, 0x23736d47_u32 as i32, 0x8a0912ff_u32 as i32, 0x916af7c6_u32 as i32,
    0xd88ce179_u32 as i32, 0xad5520d7_u32 as i32, 0xd6033ad5_u32 as i32, 0x154d2174_u32 as i32, 0x70813124_u32 as i32, 0x540d3a10_u32 as i32, 0x942fad91_u32 as i32, 0x22111262_u32 as i32,
    0xcf8d92a6_u32 as i32, 0xc2b5f202_u32 as i32, 0xf12886bb_u32 as i32, 0x997e0a00_u32 as i32, 0xfbb18fe2_u32 as i32, 0x53be7b32_u32 as i32, 0x15c33fc1_u32 as i32, 0xee9ee017_u32 as i32,
    0x91b9b6a4_u32 as i32, 0x48d30376_u32 as i32, 0xc5048980_u32 as i32, 0x60f88a6c_u32 as i32, 0xc8b57be3_u32 as i32, 0x26d5a0cd_u32 as i32, 0x5c5b5b70_u32 as i32, 0x6c6dd02c_u32 as i32,
    0x8e7ee28d_u32 as i32, 0x9907ebb3_u32 as i32, 0x61f876bc_u32 as i32, 0x4ed28d58_u32 as i32, 0x50e615b0_u32 as i32, 0xa3f3636f_u32 as i32, 0x3b3685a7_u32 as i32, 0xdb6546fb_u32 as i32,
    0x4084e216_u32 as i32, 0x47d31726_u32 as i32, 0x14c35370_u32 as i32, 0x38fb9de1_u32 as i32, 0x3e850976_u32 as i32, 0xe750ab07_u32 as i32, 0x7b0a3a4b_u32 as i32, 0x031374a9_u32 as i32,
    0x39991b9c_u32 as i32, 0xbec9f078_u32 as i32, 0xcf8d92a6_u32 as i32, 0x6e1ee9ef_u32 as i32, 0x34d48d31_u32 as i32, 0xc73f7147_u32 as i32, 0xfdd8c7f1_u32 as i32, 0x21e9b2f3_u32 as i32,
    0xa9df3d99_u32 as i32, 0x4c83f5da_u32 as i32, 0x8ae19fe1_u32 as i32, 0xf49e69f8_u32 as i32, 0xb340fb01_u32 as i32, 0xd43e715a_u32 as i32, 0x229ae065_u32 as i32, 0x47fa7695_u32 as i32,
    0xce2b37c1_u32 as i32, 0x36c0b61a_u32 as i32, 0x8e1c73f8_u32 as i32, 0x34721e9c_u32 as i32, 0x8430e88c_u32 as i32, 0x1dfdb169_u32 as i32, 0xa7a455d3_u32 as i32, 0xafa3b855_u32 as i32,
    0x31ad68d1_u32 as i32, 0x7194cd2c_u32 as i32, 0xc3186097_u32 as i32, 0xbf400ec4_u32 as i32, 0x6e1ee9ef_u32 as i32, 0x054e5c70_u32 as i32, 0x29c1b606_u32 as i32, 0x225fd13f_u32 as i32,
    0x5ef8b1cb_u32 as i32, 0xd6dbc7b6_u32 as i32, 0x9257345f_u32 as i32, 0xbc7b58fa_u32 as i32, 0xa76946ac_u32 as i32, 0x7345e6ef_u32 as i32, 0x28730ad8_u32 as i32, 0x02ec153a_u32 as i32,
    0x51f9b1b8_u32 as i32, 0x74e350fa_u32 as i32, 0xcf03c4a3_u32 as i32, 0xf12886bb_u32 as i32, 0xfbb18fe2_u32 as i32, 0x15c33fc1_u32 as i32, 0xcf663338_u32 as i32, 0x67f8009e_u32 as i32,
    0x3ec0189c_u32 as i32, 0xce03d852_u32 as i32, 0x1a255f97_u32 as i32, 0x64335e83_u32 as i32, 0x15d6ef78_u32 as i32, 0xa806c468_u32 as i32, 0x69956aaa_u32 as i32, 0x410eb01a_u32 as i32,
    0x7f58aa6a_u32 as i32, 0x2a4b840a_u32 as i32, 0x39991b9c_u32 as i32, 0xcf8d92a6_u32 as i32, 0x34d48d31_u32 as i32, 0xc2b5f202_u32 as i32, 0x6c6dd02c_u32 as i32, 0xf12886bb_u32 as i32,
    0xae550d27_u32 as i32, 0x0189ba55_u32 as i32, 0xe7c6c953_u32 as i32, 0x3d851d26_u32 as i32, 0x370f74f8_u32 as i32, 0x9ccc8dce_u32 as i32, 0x9a6a4699_u32 as i32, 0x7ff62825_u32 as i32,
    0x209b07c5_u32 as i32, 0x29c1b606_u32 as i32, 0x5ef8b1cb_u32 as i32, 0x9257345f_u32 as i32, 0xdd3dc02d_u32 as i32, 0x91a606ec_u32 as i32, 0xc1f114d8_u32 as i32, 0x4dab4199_u32 as i32,
    0x0f263824_u32 as i32, 0xd1660bd8_u32 as i32, 0x5df8c57b_u32 as i32, 0xb7f1d9b5_u32 as i32, 0xaededb2b_u32 as i32, 0xbdca0428_u32 as i32, 0x52d23e99_u32 as i32, 0xa790a61b_u32 as i32,
    0x34d48d31_u32 as i32, 0x6c6dd02c_u32 as i32, 0xae550d27_u32 as i32, 0x8e7ee28d_u32 as i32, 0x43d365e5_u32 as i32, 0x9907ebb3_u32 as i32, 0xe93cd3f0_u32 as i32, 0x886ba8f4_u32 as i32,
    0x1b605b0d_u32 as i32, 0x50d265f9_u32 as i32, 0x470e39fc_u32 as i32, 0xa0dfeec7_u32 as i32, 0x1a390f4e_u32 as i32, 0x22fd4efa_u32 as i32, 0x18ea6420_u32 as i32, 0xae550d27_u32 as i32,
    0x43d365e5_u32 as i32, 0xe93cd3f0_u32 as i32, 0x78f6b1f3_u32 as i32, 0xe68bcddd_u32 as i32, 0x05d82a73_u32 as i32, 0xe9c6a1f4_u32 as i32, 0x2624735a_u32 as i32, 0xa741e73d_u32 as i32,
    0xf5b20600_u32 as i32, 0x224c2188_u32 as i32, 0x63d0efee_u32 as i32, 0x5be53d23_u32 as i32, 0x98a57d1e_u32 as i32, 0x5bd18d6c_u32 as i32, 0x00000000_u32 as i32, 0x00000000_u32 as i32,
];

/// Twiddle factors for base multiplication in NTT domain (64 elements).
pub static ZETAS_BASEMUL: [i32; 64] = [
    0x014eab2e_u32 as i32, 0xd4522112_u32 as i32, 0x2cd52aae_u32 as i32, 0xcbb540d4_u32 as i32, 0x7de29fcd_u32 as i32, 0x379942fb_u32 as i32, 0xaff27732_u32 as i32, 0x54970814_u32 as i32,
    0x6c5a2074_u32 as i32, 0xccb52d24_u32 as i32, 0xfc4f0d9d_u32 as i32, 0x11eaedee_u32 as i32, 0x3a22e9a0_u32 as i32, 0xa5cbdca1_u32 as i32, 0xe7da790b_u32 as i32, 0xea8b7f1e_u32 as i32,
    0x82f5ed16_u32 as i32, 0x7ef63bd5_u32 as i32, 0xd6795921_u32 as i32, 0x8992f4b3_u32 as i32, 0x8e08c440_u32 as i32, 0x4935720b_u32 as i32, 0x7059d1b5_u32 as i32, 0xcea1560e_u32 as i32,
    0x483585bb_u32 as i32, 0xb17c3187_u32 as i32, 0xbb67bcf2_u32 as i32, 0xb7a31ad7_u32 as i32, 0x385e2025_u32 as i32, 0xb3b7194d_u32 as i32, 0x149bf401_u32 as i32, 0x314afa3c_u32 as i32,
    0x79cf3ed4_u32 as i32, 0xb0b7545c_u32 as i32, 0x9ca52e5f_u32 as i32, 0xf79e2ee9_u32 as i32, 0x1cd665aa_u32 as i32, 0xc4049d2f_u32 as i32, 0xa0b88f58_u32 as i32, 0x7e801d88_u32 as i32,
    0x51bea292_u32 as i32, 0x1887f58b_u32 as i32, 0xd53e5dab_u32 as i32, 0x3a369957_u32 as i32, 0xa169bccb_u32 as i32, 0x2b2410ec_u32 as i32, 0xbda2a4b9_u32 as i32, 0xc77a806d_u32 as i32,
    0xd7a0a4e0_u32 as i32, 0x53f98a58_u32 as i32, 0x1efd9db9_u32 as i32, 0x4ee63d0f_u32 as i32, 0x57e58be2_u32 as i32, 0xa555be54_u32 as i32, 0xd565bd19_u32 as i32, 0x442224c3_u32 as i32,
    0x846bf7b2_u32 as i32, 0x5d33e851_u32 as i32, 0x901c4c98_u32 as i32, 0x4f214c36_u32 as i32, 0xa24249ac_u32 as i32, 0xe1b38fba_u32 as i32, 0x440e750b_u32 as i32, 0xa5a47d32_u32 as i32,
];

/// An element of the polynomial quotient ring $R_q = \\mathbb{Z}_q[X] / (X^{256} + 1)$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct Polynomial {
    pub coeffs: [i16; KYBER_N],
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Polynomial {
    /// The zero polynomial with all 256 coefficients equal to 0.
    pub const ZERO: Self = Self {
        coeffs: [0; KYBER_N],
    };

    /// Create a polynomial from an array of 256 coefficients.
    pub const fn from_coeffs(coeffs: [i16; KYBER_N]) -> Self {
        Self { coeffs }
    }

    /// Computes in-place forward Number-Theoretic Transform (NTT) in $R_q$.
    ///
    /// Transforms polynomial from standard coefficient order to bit-reversed NTT domain.
    pub fn ntt(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            ntt_fast(self.coeffs.as_mut_ptr(), ZETAS_ASM.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            self.portable_ntt();
        }
    }

    /// Computes in-place inverse Number-Theoretic Transform (InvNTT) in $R_q$.
    ///
    /// Transforms polynomial from bit-reversed NTT domain back to standard coefficient order.
    pub fn invntt(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            invntt_fast(self.coeffs.as_mut_ptr(), ZETAS_INV_CT_ASM.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            self.portable_invntt();
        }
    }

    /// In-place Barrett reduction: reduces all coefficients modulo 3329 into $[0, 3328]$.
    pub fn reduce(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            asm_barrett_reduce(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for c in self.coeffs.iter_mut() {
                *c = barrett_reduce(*c);
            }
        }
    }

    /// Converts coefficients from Plantard domain to standard domain.
    pub fn from_plant(&mut self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            asm_fromplant(self.coeffs.as_mut_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            // In portable fallback, the coefficients remain in standard form.
        }
    }

    /// Pointwise addition of two polynomials modulo $q$.
    pub fn add(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pointwise_add(r.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..KYBER_N {
                r.coeffs[i] = barrett_reduce(self.coeffs[i] + other.coeffs[i]);
            }
        }
        r
    }

    /// Pointwise subtraction of two polynomials modulo $q$.
    pub fn sub(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            pointwise_sub(r.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            for i in 0..KYBER_N {
                r.coeffs[i] = barrett_reduce(self.coeffs[i] - other.coeffs[i]);
            }
        }
        r
    }

    /// Pointwise base multiplication of two polynomials in the NTT domain: $r = a \circ b \pmod{X^2 - \zeta}$.
    ///
    /// The result polynomial remains in the NTT domain.
    pub fn basemul(&self, other: &Self) -> Self {
        let mut r = Self::ZERO;
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            basemul_asm(r.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr(), ZETAS_BASEMUL.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            r.portable_basemul(self, other);
        }
        r
    }

    /// Pointwise base multiplication with in-place accumulation in the NTT domain: $r += a \circ b \pmod{X^2 - \zeta}$.
    pub fn basemul_acc(&self, other: &Self, acc: &mut Self) {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        unsafe {
            basemul_asm_acc(acc.coeffs.as_mut_ptr(), self.coeffs.as_ptr(), other.coeffs.as_ptr(), ZETAS_BASEMUL.as_ptr());
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            let prod = self.basemul(other);
            for i in 0..KYBER_N {
                acc.coeffs[i] = acc.coeffs[i].wrapping_add(prod.coeffs[i]);
            }
        }
    }

    /// Full ring multiplication $c(X) = a(X) \cdot b(X) \pmod{X^{256} + 1} \pmod{3329}$.
    ///
    /// Accelerated by forward NTT, NTT basemul, inverse NTT, and Barrett reduction on Cortex-M.
    pub fn mul_ring(&self, other: &Self) -> Self {
        #[cfg(all(nistp_asm_cm4, not(feature = "force-portable")))]
        {
            let mut a_ntt = *self;
            let mut b_ntt = *other;
            a_ntt.ntt();
            b_ntt.ntt();
            let mut prod = a_ntt.basemul(&b_ntt);
            prod.invntt();
            prod.reduce();
            prod
        }

        #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
        {
            let mut prod = [0i32; 2 * KYBER_N];
            for i in 0..KYBER_N {
                for j in 0..KYBER_N {
                    prod[i + j] += (self.coeffs[i] as i32) * (other.coeffs[j] as i32);
                }
            }
            let mut out = Self::ZERO;
            for i in 0..KYBER_N {
                let coeff = (prod[i] - prod[i + KYBER_N]) % (KYBER_Q as i32);
                let mut c = coeff as i16;
                if c < 0 {
                    c += KYBER_Q;
                }
                out.coeffs[i] = c;
            }
            out
        }
    }

    /// Deserializes a polynomial from 384 bytes (12 bits per coefficient).
    pub fn from_bytes(bytes: &[u8; KYBER_POLYBYTES]) -> Self {
        let mut r = Self::ZERO;
        for i in 0..(KYBER_N / 2) {
            let b0 = bytes[3 * i] as i16;
            let b1 = bytes[3 * i + 1] as i16;
            let b2 = bytes[3 * i + 2] as i16;

            r.coeffs[2 * i] = b0 | ((b1 & 0x0F) << 8);
            r.coeffs[2 * i + 1] = (b1 >> 4) | (b2 << 4);
        }
        r
    }

    /// Serializes a polynomial to 384 bytes (12 bits per coefficient).
    pub fn to_bytes(&self, out: &mut [u8; KYBER_POLYBYTES]) {
        for i in 0..(KYBER_N / 2) {
            let c0 = (self.coeffs[2 * i] as u16) & 0x0FFF;
            let c1 = (self.coeffs[2 * i + 1] as u16) & 0x0FFF;

            out[3 * i] = (c0 & 0xFF) as u8;
            out[3 * i + 1] = ((c0 >> 8) | ((c1 & 0x0F) << 4)) as u8;
            out[3 * i + 2] = (c1 >> 4) as u8;
        }
    }

    // --- Portable fallback implementations ---

    #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
    fn portable_ntt(&mut self) {
        let mut len = 128;
        let mut k = 0;
        while len >= 2 {
            let mut start = 0;
            while start < KYBER_N {
                let twiddle = ZETAS_ASM[k];
                k += 1;
                for j in start..(start + len) {
                    let a1 = self.coeffs[j + len];
                    let t = plant_mul(a1, twiddle);
                    self.coeffs[j + len] = self.coeffs[j].wrapping_sub(t);
                    self.coeffs[j] = self.coeffs[j].wrapping_add(t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
    fn portable_invntt(&mut self) {
        let mut len = 2;
        let mut k = 0;
        while len <= 128 {
            let mut start = 0;
            while start < KYBER_N {
                let twiddle = ZETAS_INV_CT_ASM[k];
                k += 1;
                for j in start..(start + len) {
                    let a0 = self.coeffs[j];
                    let a1 = self.coeffs[j + len];
                    self.coeffs[j] = a0.wrapping_add(a1);
                    let diff = a0.wrapping_sub(a1);
                    self.coeffs[j + len] = plant_mul(diff, twiddle);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
    }

    #[cfg(any(not(nistp_asm_cm4), feature = "force-portable"))]
    fn portable_basemul(&mut self, a: &Self, b: &Self) {
        for i in 0..64 {
            let zeta = ZETAS_BASEMUL[i];
            // basemul for 4*i .. 4*i + 1
            let a0 = a.coeffs[4 * i] as i32;
            let a1 = a.coeffs[4 * i + 1] as i32;
            let b0 = b.coeffs[4 * i] as i32;
            let b1 = b.coeffs[4 * i + 1];

            let b1_zeta = plant_mul(b1, zeta) as i32;
            let c0 = a0 * b0 + a1 * b1_zeta;
            let c1 = a0 * (b.coeffs[4 * i + 1] as i32) + a1 * b0;

            self.coeffs[4 * i] = plant_red(c0);
            self.coeffs[4 * i + 1] = plant_red(c1);

            // basemul for 4*i + 2 .. 4*i + 3 with -zeta
            let a2 = a.coeffs[4 * i + 2] as i32;
            let a3 = a.coeffs[4 * i + 3] as i32;
            let b2 = b.coeffs[4 * i + 2] as i32;
            let b3 = b.coeffs[4 * i + 3];

            let b3_neg_zeta = plant_mul(b3, -zeta) as i32;
            let c2 = a2 * b2 + a3 * b3_neg_zeta;
            let c3 = a2 * (b.coeffs[4 * i + 3] as i32) + a3 * b2;

            self.coeffs[4 * i + 2] = plant_red(c2);
            self.coeffs[4 * i + 3] = plant_red(c3);
        }
    }
}

/// Plantard reduction helper for portable simulation:
/// computes $(a \cdot (-R^{-1})) \pmod q$ matching ARM DSP plant_red macro.
#[inline]
pub fn plant_red(val: i32) -> i16 {
    let qinv: i32 = 0x6ba8f301_u32 as i32;
    let tmp = val.wrapping_mul(qinv);
    let tmp_high = tmp >> 16;
    let res = tmp_high * (KYBER_Q as i32) + 26632;
    (res >> 16) as i16
}

/// Plantard multiplication helper for portable simulation:
/// computes $(a \cdot \text{twiddle} \cdot R^{-1}) \pmod q$ matching ARM DSP instructions.
#[inline]
pub fn plant_mul(a: i16, twiddle: i32) -> i16 {
    let prod = (twiddle as i64) * (a as i64);
    let tmp = (prod >> 16) as i32;
    let tmp_b = (tmp as i16) as i32;
    let res = (tmp_b * (KYBER_Q as i32) + 26632) >> 16;
    res as i16
}

/// Barrett reduction: computes $a \\pmod{3329}$ in constant time into $[0, 3328]$.
#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    let prod = (a as i32) * BARRETT_CONST;
    let quot = (prod >> 26) as i16;
    let mut rem = a - quot * KYBER_Q;
    if rem < 0 {
        rem += KYBER_Q;
    }
    if rem >= KYBER_Q {
        rem -= KYBER_Q;
    }
    rem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook_mul(a: &[i16; KYBER_N], b: &[i16; KYBER_N]) -> [i16; KYBER_N] {
        let mut prod = [0i32; 2 * KYBER_N];
        for i in 0..KYBER_N {
            for j in 0..KYBER_N {
                prod[i + j] += (a[i] as i32) * (b[j] as i32);
            }
        }
        let mut out = [0i16; KYBER_N];
        for i in 0..KYBER_N {
            let coeff = (prod[i] - prod[i + KYBER_N]) % (KYBER_Q as i32);
            let mut c = coeff as i16;
            if c < 0 {
                c += KYBER_Q;
            }
            out[i] = c;
        }
        out
    }

    #[test]
    fn test_zero_poly() {
        let mut p = Polynomial::ZERO;
        p.ntt();
        assert_eq!(p.coeffs, [0; KYBER_N]);
        p.invntt();
        assert_eq!(p.coeffs, [0; KYBER_N]);
    }

    #[test]
    fn test_add_sub_reduce() {
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..KYBER_N {
            a.coeffs[i] = (i * 17) as i16;
            b.coeffs[i] = (i * 31 + 5) as i16;
        }
        let sum = a.add(&b);
        let diff = a.sub(&b);
        for i in 0..KYBER_N {
            let exp_sum = barrett_reduce(a.coeffs[i] + b.coeffs[i]);
            let exp_diff = barrett_reduce(a.coeffs[i] - b.coeffs[i]);
            assert_eq!(barrett_reduce(sum.coeffs[i]), exp_sum);
            assert_eq!(barrett_reduce(diff.coeffs[i]), exp_diff);
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut p = Polynomial::ZERO;
        for i in 0..KYBER_N {
            p.coeffs[i] = ((i * 73 + 19) % (KYBER_Q as usize)) as i16;
        }
        let mut bytes = [0u8; KYBER_POLYBYTES];
        p.to_bytes(&mut bytes);
        let recovered = Polynomial::from_bytes(&bytes);
        assert_eq!(p.coeffs, recovered.coeffs);
    }

    #[test]
    fn test_mul_ring_matches_schoolbook() {
        let mut a = Polynomial::ZERO;
        let mut b = Polynomial::ZERO;
        for i in 0..KYBER_N {
            a.coeffs[i] = ((i * 13 + 7) % (KYBER_Q as usize)) as i16;
            b.coeffs[i] = ((i * 29 + 11) % (KYBER_Q as usize)) as i16;
        }
        let expected = schoolbook_mul(&a.coeffs, &b.coeffs);
        let prod = a.mul_ring(&b);
        for i in 0..KYBER_N {
            let got = (prod.coeffs[i] % KYBER_Q + KYBER_Q) % KYBER_Q;
            assert_eq!(got, expected[i], "Ring multiplication mismatch at index {}", i);
        }
    }
}
