//! X25519 Diffie-Hellman key exchange (RFC 7748).

pub const BASEPOINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Compute scalar * point on Curve25519.
///
/// On ARMv7E-M / ARMv8-M (Cortex-M4/M7/M33), this uses hand-written `UMAAL`
/// assembly executing in ~548k cycles.
/// On other targets, it uses a constant-time portable Montgomery ladder.
pub fn scalarmult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    #[cfg(nistp_asm_cm4)]
    {
        let mut result = [0u8; 32];
        unsafe {
            super::cortex_m::curve25519_scalarmult(
                result.as_mut_ptr(),
                scalar.as_ptr(),
                point.as_ptr(),
            );
        }
        result
    }
    #[cfg(not(nistp_asm_cm4))]
    {
        super::portable::scalarmult(scalar, point)
    }
}

/// Compute public key from a private key.
#[inline]
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    scalarmult(secret_key, &BASEPOINT)
}
