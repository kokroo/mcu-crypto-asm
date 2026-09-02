//! Point arithmetic and scalar multiplication against an independent oracle.
//!
//! The oracle (`gen/gen_point_vectors.py`) is plain affine arithmetic with
//! explicit special cases — deliberately a different algorithm from the
//! projective complete formulas under test, so a transcription error cannot be
//! mirrored in both.

use nistp_mcu::{p256, p384, CurveParams, Point};

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
                assert!(!*want_inf, "{name} case {i}: expected identity, got a point");
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
