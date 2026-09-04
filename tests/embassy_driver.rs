//! Contract tests for the `embassy-crypto-driver` `P256Ops` backend.
//!
//! Run with: `cargo test --features embassy-driver`
//!
//! Compares AFFINE canonical forms (projective `z` limbs may legitimately
//! differ between code paths); uses `projective_is_identity` for infinity.

#![cfg(feature = "embassy-driver")]

use drv::{P256AffinePoint, P256Ops, P256Scalar};
use mcu_crypto_asm::embassy::{drv, P256OpsDriver};

type Ops = P256OpsDriver;

fn canon(v: u8) -> P256Scalar {
    P256Scalar([v; 32])
}

fn one() -> P256Scalar {
    let mut b = [0u8; 32];
    b[31] = 1;
    P256Scalar(b)
}

fn to_aff(p: &<Ops as P256Ops>::ProjectivePoint) -> P256AffinePoint {
    Ops::point_to_canonical(p)
}

#[test]
fn generator_and_identity_contracts() {
    let g = Ops::projective_generator();
    assert!(!Ops::projective_is_identity(&g));

    // canonical round-trip is exact for the generator (z == R for both)
    let ga = Ops::point_to_canonical(&g);
    assert_eq!(Ops::point_from_canonical(&ga), g);

    // identity: to_canonical -> (0,0); from_canonical((0,0)) -> identity
    let id = Ops::projective_identity();
    assert!(Ops::projective_is_identity(&id));
    assert_eq!(
        to_aff(&id),
        P256AffinePoint {
            x: [0u8; 32],
            y: [0u8; 32]
        }
    );
    assert!(Ops::projective_is_identity(&Ops::point_from_canonical(
        &P256AffinePoint {
            x: [0u8; 32],
            y: [0u8; 32]
        }
    )));

    // off-curve / out-of-range encodings decode to the identity
    let bad = P256AffinePoint {
        x: [0xff; 32],
        y: [0xff; 32],
    };
    assert!(Ops::projective_is_identity(&Ops::point_from_canonical(
        &bad
    )));
}

#[test]
fn scalar_arithmetic_and_inverse() {
    let zero = Ops::scalar_from_canonical(&canon(0));
    let one_s = Ops::scalar_from_canonical(&one());
    assert!(Ops::scalar_is_zero(&zero));
    assert!(!Ops::scalar_is_zero(&one_s));

    // inv(0) == 0 (defined fallback)
    assert!(Ops::scalar_is_zero(&Ops::scalar_inv(&zero)));
    assert!(Ops::scalar_is_zero(&Ops::scalar_inv_vartime(&zero)));

    // a * a^-1 == 1 for several scalars (CT and vartime inverses agree)
    for v in [0x01u8, 0x42, 0x7f, 0x80, 0xff] {
        let a = Ops::scalar_reduce_bytes(&[v; 32]);
        if Ops::scalar_is_zero(&a) {
            continue;
        }
        let prod = Ops::scalar_mul(&a, &Ops::scalar_inv(&a));
        assert_eq!(Ops::scalar_to_canonical(&prod), one());
        let prod_vt = Ops::scalar_mul(&a, &Ops::scalar_inv_vartime(&a));
        assert_eq!(Ops::scalar_to_canonical(&prod_vt), one());
        // neg: a + (-a) == 0
        assert!(Ops::scalar_is_zero(&Ops::scalar_add(
            &a,
            &Ops::scalar_neg(&a)
        )));
    }

    // reduce: n -> 0, (n as bytes via reduce of 2^256-ish) and small values
    let reduced = Ops::scalar_reduce_bytes(&[0xff; 32]);
    assert!(!Ops::scalar_is_zero(&reduced)); // 2^256-1 mod n != 0

    // out-of-range canonical scalar maps to zero (unspecified-but-defined fallback)
    assert!(Ops::scalar_is_zero(&Ops::scalar_from_canonical(
        &P256Scalar([0xff; 32])
    )));
}

#[test]
fn point_arithmetic_matches_canonical_affine() {
    let g = Ops::projective_generator();
    let ga = to_aff(&g);

    // double == add-self; affine comparison
    let dbl = Ops::projective_double(&g);
    let add_self = Ops::projective_add(&g, &g);
    assert_eq!(to_aff(&dbl), to_aff(&add_self));

    // sub: g - g == identity; g + g - g == g
    assert!(Ops::projective_is_identity(&Ops::projective_sub(&g, &g)));
    let back = Ops::projective_sub(&add_self, &g);
    assert_eq!(to_aff(&back), ga);

    // sub == add(neg) at the affine level
    let k = Ops::scalar_reduce_bytes(&[0x42; 32]);
    let p = Ops::scalar_mul_base(&k);
    let q = Ops::projective_generator();
    let sub1 = to_aff(&Ops::projective_sub(&p, &q));
    let neg_q = Ops::projective_sub(&Ops::projective_identity(), &q);
    let add1 = to_aff(&Ops::projective_add(&p, &neg_q));
    assert_eq!(sub1, add1);
}

#[test]
fn scalar_mul_matches_between_paths() {
    let g = Ops::projective_generator();
    let zero = Ops::scalar_from_canonical(&canon(0));
    let one_s = Ops::scalar_from_canonical(&one());

    // k == 0 yields the identity (both paths)
    assert!(Ops::projective_is_identity(&Ops::scalar_mul_base(&zero)));
    assert!(Ops::projective_is_identity(&Ops::scalar_mul_projective(
        &zero, &g
    )));

    // k == 1 yields G (affine comparison: comb/ladder projective
    // representations are not normalized to z == R)
    assert_eq!(to_aff(&Ops::scalar_mul_base(&one_s)), to_aff(&g));
    assert_eq!(to_aff(&Ops::scalar_mul_projective(&one_s, &g)), to_aff(&g));

    // mul_base == mul_projective(., G) on affine coordinates
    for v in [0x11u8, 0x99, 0xab] {
        let k = Ops::scalar_reduce_bytes(&[v; 32]);
        let a = to_aff(&Ops::scalar_mul_base(&k));
        let b = to_aff(&Ops::scalar_mul_projective(&k, &g));
        assert_eq!(a, b);
    }
}

#[test]
fn lincomb_is_joint_multiplication() {
    let g = Ops::projective_generator();
    let k1 = Ops::scalar_reduce_bytes(&[0x21; 32]);
    let k2 = Ops::scalar_reduce_bytes(&[0x43; 32]);
    let sum = Ops::scalar_add(&k1, &k2);

    let joint = Ops::projective_lincomb(&k1, &g, &k2, &g);
    let direct = Ops::scalar_mul_base(&sum);
    assert_eq!(to_aff(&joint), to_aff(&direct));

    // zero coefficients contribute nothing
    let zero = Ops::scalar_from_canonical(&canon(0));
    assert_eq!(
        to_aff(&Ops::projective_lincomb(&zero, &g, &k2, &g)),
        to_aff(&Ops::scalar_mul_base(&k2))
    );
    assert!(Ops::projective_is_identity(&Ops::projective_lincomb(
        &zero, &g, &zero, &g
    )));
}

#[test]
fn ecdh_crosscheck_with_native_path() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[..].copy_from_slice(&[0x3a; 32]);
    b[..].copy_from_slice(&[0x17; 32]);

    // peer public key (SEC1 uncompressed) via the native path
    let mut peer = [0u8; 65];
    mcu_crypto_asm::p256::derive_public_key(&b, &mut peer).unwrap();
    assert_eq!(peer[0], 0x04);

    // same ECDH via the driver ops: x-coordinate must match shared_secret()
    let peer_point = Ops::point_from_canonical(&P256AffinePoint {
        x: peer[1..33].try_into().unwrap(),
        y: peer[33..65].try_into().unwrap(),
    });
    assert!(!Ops::projective_is_identity(&peer_point));

    let a_scalar = Ops::scalar_from_canonical(&P256Scalar(a));
    let shared = Ops::scalar_mul_projective(&a_scalar, &peer_point);
    let aff = to_aff(&shared);

    let mut expect = [0u8; 32];
    mcu_crypto_asm::p256::ecdh::shared_secret(&a, &peer, &mut expect).unwrap();
    assert_eq!(aff.x, expect);
}
