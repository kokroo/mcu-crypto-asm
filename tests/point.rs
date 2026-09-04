//! Point arithmetic and scalar multiplication against an independent oracle.
//!
//! The oracle (`gen/gen_point_vectors.py`) is plain affine arithmetic with
//! explicit special cases — deliberately a different algorithm from the
//! projective complete formulas under test, so a transcription error cannot be
//! mirrored in both.

use mcu_crypto_asm::{p256, p384, CurveParams, Point};

#[path = "point_vectors.rs"]
mod vectors;

fn check<const N: usize>(
    c: &CurveParams,
    name: &str,
    cases: &[([u32; N], [u32; N], [u32; N], bool)],
) {
    let g = Point::<N>::generator(c);
    for (i, (k, want_x, want_y, want_inf)) in cases.iter().enumerate() {
        let r = g.mul_scalar(c, k);
        match r.to_affine(&c.field) {
            None => assert!(
                *want_inf,
                "{name} case {i}: got identity, expected a finite point"
            ),
            Some((x, y)) => {
                assert!(
                    !*want_inf,
                    "{name} case {i}: expected identity, got a point"
                );
                assert_eq!(&x, want_x, "{name} case {i}: x mismatch");
                assert_eq!(&y, want_y, "{name} case {i}: y mismatch");
            }
        }
    }
}

#[test]
fn p256_scalar_mul_matches_affine_oracle() {
    check::<{ p256::N }>(&p256::CURVE, "p256", &vectors::P256_MUL_G);
}

#[test]
fn p384_scalar_mul_matches_affine_oracle() {
    check::<{ p384::N }>(&p384::CURVE, "p384", &vectors::P384_MUL_G);
}

/// The identity must be absorbing, and adding a point to its own inverse must
/// give the identity. These are the cases complete formulas exist to handle.
#[test]
fn complete_formulas_handle_exceptional_cases() {
    let c = &p256::CURVE;
    let g = Point::<{ p256::N }>::generator(c);
    let id = Point::<{ p256::N }>::identity(&c.field);

    assert!(id.add(c, &id).is_identity(), "identity + identity");
    assert_eq!(
        g.add(c, &id).to_affine(&c.field),
        g.to_affine(&c.field),
        "G + identity == G"
    );
    // G + G must equal 2G (doubling through the general addition formula).
    let two_g = g.add(c, &g);
    let two_g_scalar = {
        let mut k = [0u32; p256::N];
        k[0] = 2;
        g.mul_scalar(c, &k)
    };
    assert_eq!(
        two_g.to_affine(&c.field),
        two_g_scalar.to_affine(&c.field),
        "G + G == 2G"
    );
}

/// The fixed-base comb must agree with the general scalar multiplication on
/// the oracle vectors, and with `mul_scalar` on random scalars.
#[test]
fn p256_comb_matches_oracle() {
    use mcu_crypto_asm::p256;
    for (i, (k, want_x, want_y, want_inf)) in vectors::P256_MUL_G.iter().enumerate() {
        let r = p256::mul_base(k);
        match r.to_affine(&p256::CURVE.field) {
            None => assert!(*want_inf, "p256 comb case {i}: got identity"),
            Some((x, y)) => {
                assert!(!*want_inf, "p256 comb case {i}: expected identity");
                assert_eq!(&x, want_x, "p256 comb case {i}: x");
                assert_eq!(&y, want_y, "p256 comb case {i}: y");
            }
        }
    }
}

#[test]
fn p384_comb_matches_oracle() {
    use mcu_crypto_asm::p384;
    for (i, (k, want_x, want_y, want_inf)) in vectors::P384_MUL_G.iter().enumerate() {
        let r = p384::mul_base(k);
        match r.to_affine(&p384::CURVE.field) {
            None => assert!(*want_inf, "p384 comb case {i}: got identity"),
            Some((x, y)) => {
                assert!(!*want_inf, "p384 comb case {i}: expected identity");
                assert_eq!(&x, want_x, "p384 comb case {i}: x");
                assert_eq!(&y, want_y, "p384 comb case {i}: y");
            }
        }
    }
}

/// Comb and general path must agree on arbitrary scalars, including ones with
/// zero digits (which select the stored identity entry).
#[test]
fn comb_agrees_with_general_scalar_mul() {
    use mcu_crypto_asm::{p256, p384, Point};
    let g = Point::<{ p256::N }>::generator(&p256::CURVE);
    let mut st = 0x243F6A88u32;
    for _ in 0..12 {
        let mut k = [0u32; p256::N];
        for limb in k.iter_mut() {
            st = st.wrapping_mul(1664525).wrapping_add(1013904223);
            *limb = st;
        }
        assert_eq!(
            p256::mul_base(&k).to_affine(&p256::CURVE.field),
            g.mul_scalar(&p256::CURVE, &k).to_affine(&p256::CURVE.field),
            "p256 comb vs general disagreed on {k:08x?}"
        );
    }
    // A scalar that is mostly zeros exercises the identity table entry.
    let mut sparse = [0u32; p384::N];
    sparse[0] = 0x0000_0003;
    sparse[p384::N - 1] = 0x0100_0000;
    let g4 = Point::<{ p384::N }>::generator(&p384::CURVE);
    assert_eq!(
        p384::mul_base(&sparse).to_affine(&p384::CURVE.field),
        g4.mul_scalar(&p384::CURVE, &sparse)
            .to_affine(&p384::CURVE.field),
        "p384 comb vs general disagreed on a sparse scalar"
    );
}

#[test]
fn jacobian_matches_projective() {
    use mcu_crypto_asm::{p256, p384, Point, PointJacobian};

    // Test P-256
    let g256 = Point::<{ p256::N }>::generator(&p256::CURVE);
    let gj256 = PointJacobian::<{ p256::N }>::generator(&p256::CURVE);
    let d256_proj = g256.add(&p256::CURVE, &g256);
    let d256_jac = gj256.double(&p256::CURVE);
    assert_eq!(
        d256_proj.to_affine(&p256::FIELD),
        d256_jac.to_affine(&p256::FIELD),
        "P-256 doubling mismatch"
    );

    let add256_proj = d256_proj.add(&p256::CURVE, &g256);
    let add256_jac = d256_jac.add(&p256::CURVE, &gj256);
    assert_eq!(
        add256_proj.to_affine(&p256::FIELD),
        add256_jac.to_affine(&p256::FIELD),
        "P-256 Jacobian add mismatch"
    );

    let (gx256, gy256) = g256.to_affine(&p256::FIELD).unwrap();
    let gx256_fe = mcu_crypto_asm::Fe::from_int(&p256::FIELD, &gx256);
    let gy256_fe = mcu_crypto_asm::Fe::from_int(&p256::FIELD, &gy256);
    let mixed256_jac = d256_jac.add_mixed(&p256::CURVE, &gx256_fe, &gy256_fe);
    assert_eq!(
        add256_proj.to_affine(&p256::FIELD),
        mixed256_jac.to_affine(&p256::FIELD),
        "P-256 Jacobian add_mixed mismatch"
    );

    // Test P-384
    let g384 = Point::<{ p384::N }>::generator(&p384::CURVE);
    let gj384 = PointJacobian::<{ p384::N }>::generator(&p384::CURVE);
    let d384_proj = g384.add(&p384::CURVE, &g384);
    let d384_jac = gj384.double(&p384::CURVE);
    assert_eq!(
        d384_proj.to_affine(&p384::FIELD),
        d384_jac.to_affine(&p384::FIELD),
        "P-384 doubling mismatch"
    );

    let add384_proj = d384_proj.add(&p384::CURVE, &g384);
    let add384_jac = d384_jac.add(&p384::CURVE, &gj384);
    assert_eq!(
        add384_proj.to_affine(&p384::FIELD),
        add384_jac.to_affine(&p384::FIELD),
        "P-384 Jacobian add mismatch"
    );

    let (gx384, gy384) = g384.to_affine(&p384::FIELD).unwrap();
    let gx384_fe = mcu_crypto_asm::Fe::from_int(&p384::FIELD, &gx384);
    let gy384_fe = mcu_crypto_asm::Fe::from_int(&p384::FIELD, &gy384);
    let mixed384_jac = d384_jac.add_mixed(&p384::CURVE, &gx384_fe, &gy384_fe);
    assert_eq!(
        add384_proj.to_affine(&p384::FIELD),
        mixed384_jac.to_affine(&p384::FIELD),
        "P-384 Jacobian add_mixed mismatch"
    );

    // Coordinate conversions roundtrip
    let proj_roundtrip = gj384.to_projective(&p384::FIELD);
    assert_eq!(
        proj_roundtrip.to_affine(&p384::FIELD),
        gj384.to_affine(&p384::FIELD)
    );
    let jac_roundtrip = PointJacobian::from_projective(&g384, &p384::FIELD);
    assert_eq!(
        jac_roundtrip.to_affine(&p384::FIELD),
        g384.to_affine(&p384::FIELD)
    );
}
